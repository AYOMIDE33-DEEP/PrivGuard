 # PrivGuard

PrivGuard is a Flask-based cybersecurity and privacy platform that transforms Gmail into a monitored security environment for individual users.

The platform combines email threat intelligence, phishing detection, encryption systems, forensic analysis, password auditing, IP reputation checks, and AI-assisted threat explanations into a unified web application.

---

## Features

### Gmail Scanner
- Gmail OAuth 2.0 integration
- Email risk scoring (LOW / MEDIUM / HIGH)
- SPF/DKIM/DMARC validation
- Phishing link detection
- Attachment inspection
- Spoofing and anomaly analysis

### AES-256-GCM Crypto Tool
- File encryption and decryption
- AES-256-GCM encryption
- Scrypt key derivation
- Custom `.pgc1` encrypted binary format
- Async progress tracking

### Password Strength Analyser
- Real-time password scoring
- Entropy calculation
- Pattern detection
- Crack-time estimation

### Phishing URL Checker
- URL heuristic analysis
- WHOIS domain age checks
- Google Safe Browsing integration
- VirusTotal scanning

### Email Header Analyser
- Email forensic analysis
- SPF/DKIM/DMARC verification
- Origin IP extraction
- Header anomaly detection

### IP Reputation Tool
- AbuseIPDB integration
- VirusTotal reputation checks
- IPInfo intelligence
- Normalised risk verdicts

### Quick File Scanner
- SHA-256 and MD5 hashing
- Shannon entropy analysis
- MIME mismatch detection
- EICAR signature detection

### Email Centre
- SMTP email sending
- CC/BCC support
- HTML email rendering
- Attachment support
- Draft saving
- Sent logs
- Phishing content warnings

### AI Email Explainer
- GPT-powered email explanation
- Human-readable threat interpretation
- Rule-based fallback system

### Admin Dashboard
- SOC-style monitoring dashboard
- KPI cards and analytics
- Threat reports
- Chart.js visualisations
- Auto-refresh functionality

### Authentication System
- User registration and login
- bcrypt password hashing
- Google reCAPTCHA v2
- Account lockout protection
- Password reset functionality
- Role-based access control

---

## Technologies Used

- Python
- Flask
- SQLite
- HTML/CSS
- JavaScript
- Jinja2
- Chart.js
- Cryptography
- OAuth 2.0
- VirusTotal API
- Google Safe Browsing API
- AbuseIPDB API

---

## Project Purpose

PrivGuard was developed as a cybersecurity-focused platform aimed at giving individual users enterprise-style email threat visibility, privacy protection, and secure communication tools through a web-based interface.

---

## Screenshots
###  PrivGuard Login Page
<img width="470" height="225" alt="image" src="https://github.com/user-attachments/assets/9f357e4b-1bab-463a-af35-1ddfd0ca92de" />
### PrivGuard OAuth Result 
<img width="469" height="183" alt="image" src="https://github.com/user-attachments/assets/a369f9e2-88b3-440c-b29c-ca08ea598175" />
### PrivGuard Admin Login Section
<img width="467" height="224" alt="image" src="https://github.com/user-attachments/assets/4e168f3d-8b2b-4600-995c-eb8743a430ff" />
### PrivGuard Email Inbox Card
<img width="451" height="196" alt="image" src="https://github.com/user-attachments/assets/3ef33e5a-252d-4759-bbe9-049ecfd2b748" />
### PrivGuard Email Scanner Card
<img width="446" height="219" alt="image" src="https://github.com/user-attachments/assets/2b16e5eb-04e1-4513-be56-35387056394d" />
###  PrivGuard Threat Report Card
<img width="453" height="217" alt="image" src="https://github.com/user-attachments/assets/f925eec3-c074-4262-b6b9-6d31e70fb075" />
###  PrivGuard Setting Section
<img width="441" height="191" alt="image" src="https://github.com/user-attachments/assets/4757110a-1d32-4711-a6b0-4ac67304a5a4" />
### PrivGuard Help Section 
<img width="432" height="176" alt="image" src="https://github.com/user-attachments/assets/c38db057-7a2e-4454-a411-55f0e488da9f" />
### PrivGuard SOC Dashboard Interface
<img width="417" height="251" alt="image" src="https://github.com/user-attachments/assets/9f6028d2-b100-4b55-94f1-424cc9fc72dc" />
###  Admin Dashboard Interface
<img width="439" height="212" alt="image" src="https://github.com/user-attachments/assets/f04151e8-e1d8-4098-b8cb-831e0723276d" />
###  Email Centre Interface
<img width="414" height="200" alt="image" src="https://github.com/user-attachments/assets/52c34872-0def-4345-820b-a567067ea12d" />
###  Quick File Scanner
<img width="381" height="275" alt="image" src="https://github.com/user-attachments/assets/bc39cd91-7e3a-4d9f-9019-894a76458bdd" />
###  IP Reputation Tool
<img width="397" height="234" alt="image" src="https://github.com/user-attachments/assets/1f4e7160-d49c-4ffd-ba09-ad4535c99955" />
###  Email Header Analyser
<img width="389" height="262" alt="image" src="https://github.com/user-attachments/assets/b4a2f369-9919-41dc-bee1-94d491027082" />
###  Phishing URL Checker
<img width="399" height="244" alt="image" src="https://github.com/user-attachments/assets/7408aacc-8ec4-447a-affc-03ba1a4e1f2c" />
###  Password Analyser Module
<img width="410" height="273" alt="image" src="https://github.com/user-attachments/assets/c3ed45f3-dd1d-4262-a608-929f174782cd" />
###  Crypto Tool Interface
<img width="437" height="268" alt="image" src="https://github.com/user-attachments/assets/5f47b016-54e8-4bc8-9e62-402988ea3d3a" />
### Gmail Scanner Interface
<img width="396" height="243" alt="image" src="https://github.com/user-attachments/assets/39561deb-d18d-4cbc-a5fe-203e61329035" />
### Main Dashboard and Navigation
<img width="437" height="221" alt="image" src="https://github.com/user-attachments/assets/aeaacbbf-06b5-4c90-afa8-1124b93ee4d7" />
### Authentication Pages
<img width="422" height="247" alt="image" src="https://github.com/user-attachments/assets/5912a0e9-c965-4bf5-8b71-de8010290685" />





---

## Author

Afolarin Ayomide
