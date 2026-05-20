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
### Authentication Pages
<img width="422" height="247" alt="image" src="https://github.com/user-attachments/assets/4a0cd8dc-2ffe-4dbc-b493-71ea74c971d0" />
### Main Dashboard and Navigation
<img width="437" height="221" alt="image" src="https://github.com/user-attachments/assets/a22eeaf3-5df1-4854-a0ec-c25e22e43aa3" />
### Gmail Scanner Interface
<img width="396" height="243" alt="image" src="https://github.com/user-attachments/assets/6eac6085-9d9e-43dc-936e-3426137e391d" />
### Crypto Tool Interface
<img width="437" height="268" alt="image" src="https://github.com/user-attachments/assets/72204418-bbd4-4ecf-8e32-e39f0c4c53a2" />
###  Password Analyser Module
<img width="410" height="273" alt="image" src="https://github.com/user-attachments/assets/9350188a-e6fe-4056-9746-7df18ac31cc1" />
### Phishing URL Checker
<img width="399" height="244" alt="image" src="https://github.com/user-attachments/assets/1b74fb0a-f065-4a80-98df-e8c4be7e5ed2" />
### Email Header Analyser
<img width="389" height="262" alt="image" src="https://github.com/user-attachments/assets/44c7f27a-06ea-4c46-8d2f-5bdd2d5ac7b6" />
### IP Reputation Tool
<img width="397" height="234" alt="image" src="https://github.com/user-attachments/assets/9d8bd3cf-e40b-4741-a2e0-d0a7fcbae737" />
### Quick File Scanner
<img width="381" height="275" alt="image" src="https://github.com/user-attachments/assets/b2e22d5c-2fb6-4603-b7f1-3abbda8cef9d" />
### Email Centre Interface
<img width="414" height="200" alt="image" src="https://github.com/user-attachments/assets/4f77d28f-55ed-4b7a-94b7-cc1c9228d73b" />
### Admin Dashboard Interface
<img width="439" height="212" alt="image" src="https://github.com/user-attachments/assets/894e3c00-4492-4d16-9dd4-5e43e82055d7" />
### PrivGuard Login Page
<img width="470" height="225" alt="image" src="https://github.com/user-attachments/assets/50a01c34-a3d3-4720-8f98-2b85087578a6" />
### PrivGuard OAuth Result 
<img width="469" height="183" alt="image" src="https://github.com/user-attachments/assets/05a1ad9b-96bc-459b-bf0a-25b8f9c39aa6" />
### PrivGuard Admin Login Section
<img width="467" height="224" alt="image" src="https://github.com/user-attachments/assets/3c4357c6-65aa-4c5e-a345-f5fd3aca8df7" />
### PrivGuard Email Inbox Card
<img width="451" height="196" alt="image" src="https://github.com/user-attachments/assets/4f833d26-d1a8-408c-989c-919b5fb73c03" />
###  PrivGuard Email Scanner Card
<img width="446" height="219" alt="image" src="https://github.com/user-attachments/assets/90f7114d-2fde-44dc-9eb1-3d40150f79de" />
###  PrivGuard Threat Report Card
<img width="453" height="217" alt="image" src="https://github.com/user-attachments/assets/cdeec664-59f7-41b4-b2ed-5c2e93eab1f0" />
### PrivGuard Setting Section
<img width="441" height="191" alt="image" src="https://github.com/user-attachments/assets/e166c2a2-1ecf-44c3-b8e3-51efca7cb43a" />
### PrivGuard Help Section 
<img width="432" height="176" alt="image" src="https://github.com/user-attachments/assets/258dff43-cf9f-4b60-b13a-73bd965c1148" />
### PrivGuard SOC Dashboard Interface
<img width="417" height="251" alt="image" src="https://github.com/user-attachments/assets/e00e2cc6-2eec-4883-9f74-5cfc91245971" />




## Author

Afolarin Ayomide

## Copyright

© 2026 Afolarin Ayomide. All rights reserved.
