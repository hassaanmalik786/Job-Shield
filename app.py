
import os, re, io, json, sqlite3, socket, ipaddress, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from flask import Flask, request, jsonify, render_template, send_file
import requests
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "jobshield.sqlite3")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_500_000
app.config["JSON_SORT_KEYS"] = False

USER_AGENT = "JobShieldAcademicScanner/1.0 (safe public-page analysis)"
MAX_PAGE_BYTES = 1_000_000
MAX_REDIRECTS = 4
TIMEOUT = (4, 8)

# Each rule adds a transparent number of points. The score is a heuristic,
# not a probability and not proof that a job is fraudulent.
RULES = [
    ("registration_fee", "Registration / application fee request", 25,
     [r"\bregistration fee\b", r"\bapplication fee\b", r"\bjob fee\b", r"\bpay\s+(?:a\s+)?registration\b", r"\bfee\s+for\s+(?:the\s+)?job\b"]),
    ("advance_payment", "Advance payment / security deposit request", 30,
     [r"\badvance payment\b", r"\bsecurity deposit\b", r"\brefundable deposit\b", r"\bpay\s+before\s+(?:joining|interview|selection)\b", r"\bdeposit\s+(?:an amount|money|rs\.?|inr|pkr)\b"]),
    ("processing_fee", "Processing / document / verification fee", 20,
     [r"\bprocessing fee\b", r"\bdocument(?:ation)? fee\b", r"\bverification fee\b", r"\btraining fee\b", r"\bmedical fee\b"]),
    ("pay_to_interview", "Payment required for interview or selection", 25,
     [r"\bpay\s+(?:to|for)\s+(?:attend|schedule|confirm)\s+(?:the\s+)?interview\b", r"\binterview fee\b", r"\bselection fee\b"]),
    ("guaranteed_selection", "Guaranteed job / selection claim", 12,
     [r"\b100%\s+guaranteed\b", r"\bguaranteed\s+(?:job|selection|placement)\b", r"\bno interview required\b"]),
    ("urgency", "High-pressure or urgent action language", 8,
     [r"\bapply immediately\b", r"\blimited seats\b", r"\burgent hiring\b", r"\bpay today\b", r"\blast chance\b", r"\bwithin 24 hours\b"]),
    ("unrealistic_salary", "Unusually high salary or easy-money claim", 12,
     [r"\bearn\s+(?:rs\.?|pkr|inr|\$)\s?[\d,]{5,}\s*(?:per day|daily)\b", r"\bno experience\s+needed.{0,40}\bhigh salary\b", r"\beasy money\b", r"\bwork\s+1?\s*[-–]?\s*2\s+hours.{0,40}\b(?:daily|per day)\b"]),
    ("personal_data", "Sensitive personal information requested unusually early", 10,
     [r"\bsend\s+(?:your\s+)?(?:cnic|national id|passport)\b", r"\bshare\s+(?:your\s+)?bank details\b", r"\bsend\s+(?:your\s+)?otp\b", r"\bprovide\s+(?:your\s+)?card details\b"]),
    ("whatsapp_only", "WhatsApp / messaging-only contact signal", 5,
     [r"\bwhatsapp only\b", r"\bcontact (?:only )?on whatsapp\b", r"\bwhatsapp(?:\s+number)?\s*[:\-]"]),
]

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            submitted_url TEXT,
            input_excerpt TEXT,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            findings_json TEXT NOT NULL,
            summary TEXT NOT NULL
        )""")
        con.commit()

def clean_text(value, limit=50000):
    if not isinstance(value, str):
        return ""
    return value[:limit].strip()

def is_public_host(hostname):
    """Reject local/private/reserved destinations before any outbound request."""
    if not hostname:
        return False, "Missing hostname"
    host = hostname.rstrip(".").lower()
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
        return False, "Local hostnames are not allowed"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if not ip.is_global:
            return False, "Private or non-public IP addresses are not allowed"
        return True, ""
    except ValueError:
        pass
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = {item[4][0] for item in answers}
        if not ips:
            return False, "Hostname did not resolve"
        for raw_ip in ips:
            ip = ipaddress.ip_address(raw_ip.split("%")[0])
            if not ip.is_global:
                return False, "Hostname resolves to a private or non-public IP"
        return True, ""
    except Exception:
        return False, "Could not safely resolve hostname"

def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return None, "Enter a job URL or paste advertisement text"
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are supported"
        if not parsed.hostname or parsed.username or parsed.password:
            return None, "Invalid URL or URLs containing credentials are not allowed"
        if parsed.port and not (1 <= parsed.port <= 65535):
            return None, "Invalid port"
        return parsed.geturl(), ""
    except Exception:
        return None, "Invalid URL format"

def fetch_public_page(start_url):
    """Fetch a small public HTML page with redirects validated at every hop."""
    current = start_url
    session = requests.Session()
    session.trust_env = False
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    for hop in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        ok, reason = is_public_host(parsed.hostname)
        if not ok:
            raise ValueError("URL blocked by safety checks: " + reason)
        try:
            response = session.get(
                current, headers=headers, timeout=TIMEOUT, allow_redirects=False,
                stream=True, verify=True
            )
        except requests.RequestException as exc:
            raise ValueError("Could not retrieve the page safely: " + str(exc)[:180])
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ValueError("The website returned an invalid redirect")
            if hop >= MAX_REDIRECTS:
                raise ValueError("Too many redirects")
            current = urljoin(current, location)
            parsed_next = urlparse(current)
            if parsed_next.scheme not in ("http", "https"):
                raise ValueError("Redirect to an unsupported URL scheme was blocked")
            continue
        content_type = response.headers.get("Content-Type", "").lower()
        if response.status_code >= 400:
            response.close()
            raise ValueError("Website returned HTTP status " + str(response.status_code))
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            response.close()
            raise ValueError("The URL did not return an HTML page")
        chunks, total = [], 0
        try:
            for chunk in response.iter_content(16384):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_PAGE_BYTES:
                    raise ValueError("Page is larger than the 1 MB scan limit")
                chunks.append(chunk)
        finally:
            response.close()
        raw = b"".join(chunks)
        encoding = response.encoding or "utf-8"
        html = raw.decode(encoding, errors="replace")
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        text = soup.get_text(" ", strip=True)
        return {
            "final_url": current,
            "status_code": response.status_code,
            "title": title[:300],
            "text": text[:50000],
            "content_type": content_type,
            "https": urlparse(current).scheme == "https",
        }
    raise ValueError("Could not complete safe page retrieval")

def domain_observations(url):
    if not url:
        return {"domain": "Not supplied", "https": None, "notes": ["No URL was provided."]}
    p = urlparse(url)
    host = p.hostname or ""
    https = p.scheme == "https"
    notes = []
    if not https:
        notes.append("The submitted URL uses HTTP rather than HTTPS.")
    else:
        notes.append("The submitted URL uses HTTPS. This encrypts the connection but does not prove the employer is genuine.")
    if host.startswith("xn--") or ".xn--" in host:
        notes.append("The domain contains internationalized/punycode characters; inspect carefully for lookalike spelling.")
    if re.search(r"\d{4,}", host):
        notes.append("The domain contains a long numeric sequence; this is a weak signal and not proof of fraud.")
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "shorturl.at", "is.gd", "cutt.ly", "rb.gy")
    if any(host == s or host.endswith("." + s) for s in shorteners):
        notes.append("The URL uses a link-shortening service, so the final destination should be verified.")
    return {"domain": host or "Unknown", "https": https, "notes": notes}

def analyze_text(text, submitted_url=None, page_info=None):
    text_l = (text or "").lower()
    findings = []
    points = 0
    for key, label, weight, patterns in RULES:
        matches = []
        for pattern in patterns:
            m = re.search(pattern, text_l, re.I)
            if m:
                matches.append(m.group(0))
        if matches:
            # one contribution per rule, with the exact evidence retained
            points += weight
            findings.append({
                "key": key, "title": label, "severity": "High" if weight >= 20 else ("Medium" if weight >= 10 else "Low"),
                "points": weight, "evidence": list(dict.fromkeys(matches))[:3],
                "explanation": label + " was found in the supplied content."
            })

    # Company identity checks are explicitly "unverified", not a fraud accusation.
    company_signals = []
    if not re.search(r"\b(company|limited|ltd|inc\.?|llc|private limited|pvt\.?)\b", text_l):
        company_signals.append("No clear company legal name/type was found in the supplied text.")
    if not re.search(r"\b(?:company|employer|office|address)\b.{0,80}\b(?:street|road|avenue|city|building|park|suite|floor)\b", text_l):
        company_signals.append("No clear business address was identified in the supplied text.")
    if company_signals:
        findings.append({
            "key": "company_unverified", "title": "Company details could not be verified from submitted content",
            "severity": "Low", "points": 5, "evidence": company_signals,
            "explanation": "Missing details are treated as unverified information, not proof of a fake company."
        })
        points += 5

    domain = domain_observations(submitted_url)
    if submitted_url and domain["https"] is False:
        findings.append({
            "key": "no_https", "title": "Website does not use HTTPS", "severity": "Low",
            "points": 5, "evidence": ["URL scheme is HTTP"],
            "explanation": "The connection is not protected by HTTPS. This is a security weakness, but does not alone prove a scam."
        })
        points += 5

    score = min(100, points)
    if score <= 30:
        level, color = "Low Risk", "success"
        summary = "Few configured warning signs were detected. This is not a guarantee that the job or employer is genuine."
    elif score <= 60:
        level, color = "Medium Risk", "warning"
        summary = "Some warning signs were detected. Verify the employer and recruitment process independently before proceeding."
    else:
        level, color = "High Risk", "danger"
        summary = "Multiple or higher-impact warning signs were detected. Do not pay money or share sensitive information until independently verified."

    if not findings:
        findings.append({
            "key": "no_rule_match", "title": "No configured warning phrase was detected",
            "severity": "Info", "points": 0,
            "evidence": ["No match in the current rule set"],
            "explanation": "Scams can use wording not covered by this prototype. A clean scan does not establish legitimacy."
        })

    recommendations = []
    keys = {f["key"] for f in findings}
    if keys.intersection({"registration_fee", "advance_payment", "processing_fee", "pay_to_interview"}):
        recommendations.append("Do not pay registration, processing, interview or security-deposit fees without independently confirming the employer and applicable local rules.")
    if "personal_data" in keys:
        recommendations.append("Do not send CNIC, passport, bank, card or OTP details before verifying the employer through official channels.")
    if "urgency" in keys or "guaranteed_selection" in keys:
        recommendations.append("Treat pressure tactics and guaranteed-selection claims cautiously; contact the employer using contact details found independently.")
    recommendations.append("Search for the company’s official website and independently obtained phone number or email; do not rely only on details in the advertisement.")
    recommendations.append("Compare the vacancy with the employer’s official careers page and reputable recruitment sources.")
    recommendations.append("Remember: HTTPS, a polished website or a low risk score does not prove that a job is genuine.")

    return {
        "score": score, "level": level, "color": color, "summary": summary,
        "findings": findings, "recommendations": recommendations,
        "domain": domain, "page_info": page_info or {},
        "scanned_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "text_length": len(text or "")
    }

def save_scan(url, text, result):
    excerpt = (text or "")[:500]
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute(
            "INSERT INTO scans(created_at,submitted_url,input_excerpt,score,level,findings_json,summary) VALUES(?,?,?,?,?,?,?)",
            (result["scanned_at"], url or "", excerpt, result["score"], result["level"],
             json.dumps(result["findings"]), result["summary"])
        )
        con.commit()
        return cur.lastrowid

def make_pdf(result, url, text):
    buff = io.BytesIO()
    doc = SimpleDocTemplate(buff, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm,
                            topMargin=17*mm, bottomMargin=17*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Title2", parent=styles["Title"], textColor=colors.HexColor("#12233F"),
                              fontSize=22, leading=26, alignment=0, spaceAfter=8))
    styles.add(ParagraphStyle(name="Body2", parent=styles["BodyText"], fontSize=9, leading=13,
                              textColor=colors.HexColor("#253247"), spaceAfter=6))
    styles.add(ParagraphStyle(name="Head2", parent=styles["Heading2"], textColor=colors.HexColor("#2463EB"),
                              fontSize=12, leading=15, spaceBefore=10, spaceAfter=5))
    styles.add(ParagraphStyle(name="Small2", parent=styles["BodyText"], fontSize=8, leading=11,
                              textColor=colors.HexColor("#58677E")))
    story = [
        Paragraph("JOBSHIELD", styles["Title2"]),
        Paragraph("Fake Job Advertisement Security Analysis Report", styles["Heading2"]),
        Paragraph("Generated: " + result["scanned_at"], styles["Small2"]),
        Spacer(1, 8),
    ]
    score_color = {"Low Risk": "#23845B", "Medium Risk": "#B7791F", "High Risk": "#C2414B"}.get(result["level"], "#2463EB")
    data = [
        [Paragraph("<b>RISK SCORE</b>", styles["Body2"]), Paragraph("<b>RISK LEVEL</b>", styles["Body2"])],
        [Paragraph(f'<font color="{score_color}" size="25"><b>{result["score"]}/100</b></font>', styles["Body2"]),
         Paragraph(f'<font color="{score_color}" size="17"><b>{result["level"]}</b></font>', styles["Body2"])]
    ]
    t = Table(data, colWidths=[75*mm, 85*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#F1F5FB")),
                           ("BOX",(0,0),(-1,-1),0.6,colors.HexColor("#D7E0ED")),
                           ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                           ("LEFTPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),8),
                           ("BOTTOMPADDING",(0,0),(-1,-1),8)]))
    story += [t, Spacer(1, 9), Paragraph("Assessment Summary", styles["Head2"]),
              Paragraph(result["summary"], styles["Body2"]),
              Paragraph("Submitted URL", styles["Head2"]),
              Paragraph((url or "Not provided").replace("&","&amp;").replace("<","&lt;"), styles["Body2"]),
              Paragraph("Domain and Website Observations", styles["Head2"]),
              Paragraph("Domain: " + result["domain"]["domain"], styles["Body2"])]
    for note in result["domain"]["notes"]:
        story.append(Paragraph("• " + note.replace("&","&amp;"), styles["Body2"]))
    if result["page_info"]:
        story.append(Paragraph("Fetched page title: " + (result["page_info"].get("title") or "Not available").replace("&","&amp;"), styles["Body2"]))
    story.append(Paragraph("Detected Findings", styles["Head2"]))
    for f in result["findings"]:
        story.append(Paragraph(f'<b>{f["title"]}</b> — {f["severity"]} severity; +{f["points"]} points', styles["Body2"]))
        for ev in f["evidence"]:
            story.append(Paragraph("• Evidence: " + ev.replace("&","&amp;").replace("<","&lt;"), styles["Small2"]))
        story.append(Paragraph(f["explanation"].replace("&","&amp;"), styles["Small2"]))
        story.append(Spacer(1, 3))
    story.append(Paragraph("Recommendations", styles["Head2"]))
    for rec in result["recommendations"]:
        story.append(Paragraph("• " + rec, styles["Body2"]))
    story += [
        Spacer(1, 8),
        Paragraph("Important limitations", styles["Head2"]),
        Paragraph("This prototype uses transparent heuristic rules and available public information. The score is not a probability of fraud and is not proof that an advertisement or company is fraudulent. A low score does not guarantee safety. HTTPS only indicates encrypted transport. External pages may block access or provide incomplete information. Verify employers independently before paying money or sharing sensitive information.", styles["Small2"]),
        Spacer(1, 8),
        Paragraph("JobShield | Academic Cybersecurity Project", styles["Small2"])
    ]
    doc.build(story)
    buff.seek(0)
    return buff

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    raw_url = clean_text(data.get("url"), 2000)
    pasted = clean_text(data.get("text"), 50000)
    if not raw_url and not pasted:
        return jsonify({"error": "Enter a job URL, paste advertisement text, or provide both."}), 400

    normalized_url, url_error = (None, "")
    page_info = {}
    combined_text = pasted

    if raw_url:
        normalized_url, url_error = normalize_url(raw_url)
        if url_error:
            return jsonify({"error": url_error}), 400
        try:
            page_info = fetch_public_page(normalized_url)
            page_text = page_info.get("text", "")
            combined_text = (pasted + "\n\n" + page_text).strip() if pasted else page_text
        except ValueError as exc:
            # Text-only analysis remains possible if the user supplied text.
            if not pasted:
                return jsonify({"error": str(exc), "text_fallback": True}), 422
            page_info = {"fetch_error": str(exc), "title": "", "final_url": normalized_url}
    if not combined_text:
        return jsonify({"error": "No readable advertisement text was found. Paste the job description manually and scan again."}), 422

    result = analyze_text(combined_text, normalized_url, page_info)
    scan_id = save_scan(normalized_url, combined_text, result)
    result["scan_id"] = scan_id
    result["submitted_url"] = normalized_url or ""
    result["input_excerpt"] = combined_text[:350]
    result["page_fetch_error"] = page_info.get("fetch_error", "")
    return jsonify(result)

@app.route("/api/history")
def history():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT id,created_at,submitted_url,score,level,summary FROM scans ORDER BY id DESC LIMIT 20").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/report/<int:scan_id>")
def report(scan_id):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Report not found"}), 404
    result = {
        "scanned_at": row["created_at"], "score": row["score"], "level": row["level"],
        "findings": json.loads(row["findings_json"]), "summary": row["summary"],
        "domain": domain_observations(row["submitted_url"]), "page_info": {}
    }
    pdf = make_pdf(result, row["submitted_url"], row["input_excerpt"])
    return send_file(pdf, mimetype="application/pdf", as_attachment=True,
                     download_name=f"JobShield_Report_{scan_id}.pdf")

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "JobShield", "version": "1.0"})

init_db()

if __name__ == "__main__":
    # Local development only. For public deployment, use a production WSGI server
    # and HTTPS reverse proxy; do not expose Flask's debug server.
    app.run(host="127.0.0.1", port=5000, debug=False)
