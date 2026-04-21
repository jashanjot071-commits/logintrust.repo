# Login Trust — Advanced Phishing Detection Platform

Login Trust is a web-based cybersecurity platform that detects phishing login pages in real time using a multi-layer heuristic scanning engine.

## Features
- Real-time URL scanning
- 24+ phishing detection checks
- Risk score (0–10)
- Verdict: Safe / Suspicious / Malicious
- Detailed threat analysis
- Secure authentication (bcrypt)
- Responsive user interface
- Trusted domain whitelist

## Tech Stack
Backend:
- Python (Flask)
- Bash (Scanning Engine)

Frontend:
- HTML, CSS, JavaScript

Database:
- Supabase (PostgreSQL)

## How It Works
1. User logs in
2. Enters a URL
3. Backend validates input
4. Bash script performs checks
5. Score is calculated
6. Verdict is generated
7. Results displayed with reasons

## Detection Techniques
- HTTPS validation
- Domain analysis
- URL redirection tracking
- JavaScript obfuscation detection
- Fake login form detection
- OTP phishing detection
- Suspicious domain patterns

## Risk Score
| Score | Verdict |
|------|--------|
| 0–2  | Safe |
| 3–4  | Suspicious |
| 5–10 | Malicious |

## Project Structure
LoginTrust/
│── app.py
│── scan.sh
│── requirements.txt
│── templates/
│── static/
│── .gitignore
│── README.md

## Setup
git clone https://github.com/your-username/logintrust.git
cd logintrust

python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python app.py

## API
POST /scan-api

Request:
{
  "url": "https://example.com"
}

Response:
{
  "score": 7,
  "verdict": "malicious",
  "reasons": ["Suspicious domain", "No HTTPS"]
}

## Security
- bcrypt password hashing
- Input validation
- Command injection protection
- Session-based authentication

## Authors
- Jashanjot Singh  
- Prabhjot Singh
- Jaspreet Kaur

## License
Academic project
