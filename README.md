# JobShield — Fake Job Advertisement Detector

A runnable academic cybersecurity prototype that accepts a job-posting URL, pasted advertisement text, or both. It performs transparent rule-based analysis and generates a downloadable PDF report.

## Features
- URL input and manual advertisement-text input (both can be used together)
- Registration-fee, advance-payment, processing-fee and interview-fee phrase detection
- Suspicious urgency, guaranteed-selection, unrealistic-offer and early-sensitive-data indicators
- Basic domain and HTTPS observations
- Explainable 0–100 heuristic risk score
- Evidence and recommendations for each scan
- SQLite scan history
- Downloadable PDF report
- Responsive interface

## Requirements
- Python 3.10 or newer
- Internet connection for optional public webpage retrieval

## Run on Windows
1. Extract `JobShield.zip`.
2. Open the `JobShield` folder.
3. Open Command Prompt / PowerShell in this folder.
4. Create a virtual environment:

   ```bash
   py -m venv venv
   venv\Scripts\activate
   ```

5. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

6. Start the application:

   ```bash
   python app.py
   ```

7. Open this address in your browser:

   `http://127.0.0.1:5000`

## Run on macOS / Linux
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Test it
You can paste this clearly fictional sample text into the analyzer:

> ABC Example Company is hiring a Junior Office Assistant. Applicants must pay a refundable registration fee before the interview. Selection is guaranteed. Contact our recruitment team for details.

This should trigger payment and other warning indicators. Do not use real people's private information in test data.

## Important technical and safety notes
- The score is a heuristic based on explicit rules. It is not a probability, a verified fraud verdict, or proof that a company is fake.
- A low score does not prove a job is genuine. A high score means warning signs were detected and should be investigated.
- HTTPS indicates encrypted transport only; it does not prove employer legitimacy.
- Public websites may block automated access, require JavaScript, login or CAPTCHA, or return incomplete content. In that case, paste the job text manually.
- The URL fetcher allows only HTTP/HTTPS, validates public DNS/IP destinations, checks redirects, uses TLS verification, and limits redirects, timeouts and page size. No URL fetcher can guarantee protection from every network-level attack; review and harden before public deployment.
- This development server binds to localhost only. Do not expose Flask's development server to the public internet. For deployment, use a production WSGI server, HTTPS reverse proxy, strict outbound network controls, rate limiting, monitoring and a security review.
- Scan history is stored locally in `jobshield.sqlite3`. Delete that file to clear local history.
- Do not enter passwords, OTPs, bank details, CNIC/passport scans or other sensitive personal data.

## Project structure
```text
JobShield/
├── app.py
├── requirements.txt
├── jobshield.sqlite3       # created automatically after first run
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
└── reports/
```

## Academic project note
The current version uses transparent regular-expression rules, not machine learning or a commercial threat-intelligence feed. Future work may add verified reputation APIs, multilingual detection, labeled datasets and evaluated ML models.
