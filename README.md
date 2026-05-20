# PrivGuard Web (Built from your PrivGuard groundwork)

This project converts your existing PrivGuard desktop groundwork (scan + analyze + crypto modules) into a **web app**:
- **Backend**: FastAPI + Gmail OAuth (web server flow) + SQLite (dev)
- **Frontend**: React (Vite) + Tailwind

## 0) Security note
Do **not** commit or deploy any `credentials.json` or `token.json` from the desktop project.
For the web app, tokens are stored **per user** in the database and encrypted.

---

## 1) Backend setup (FastAPI)

### 1.1 Create a Google OAuth client (Web application)
In Google Cloud Console:
- Enable Gmail API
- Create OAuth client: **Web application**
- Authorized redirect URI:
  - `http://localhost:8000/api/gmail/oauth/callback` (dev)
- Download the client secret JSON and save it to:
  - `backend/credentials/google_client_secret.json`

### 1.2 Configure env
Copy:
- `backend/.env.example` -> `backend/.env`

Generate a Fernet key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set in `.env`:
- `JWT_SECRET` (long random)
- `TOKEN_ENC_KEY` (Fernet key)

### 1.3 Install + run
```bash
cd backend
python -m venv .venv
# activate venv
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend health:
- `GET http://localhost:8000/api/health`

---

## 2) Frontend setup (React)

Copy:
- `frontend/.env.example` -> `frontend/.env` (optional)

Run:
```bash
cd frontend
npm install
npm run dev
```

Open:
- `http://localhost:5173`

---

## 3) How the Gmail linking works
1. Sign up / login (JWT stored in browser localStorage)
2. Click **Connect Gmail**
3. Google consent screen opens
4. Google redirects back to backend callback; backend stores encrypted token in DB
5. Back to dashboard
6. Click **Scan Now** to analyze recent emails on demand

---

## 4) Next upgrades (recommended)
- Replace SQLite with PostgreSQL for production
- Add per-user scan scheduling (optional)
- Add attachment download + scanning (requires more Gmail scopes + careful handling)
- Add role-based access, admin reporting, audit logs


## Copyright

© 2026 Afolarin Ayomide. All rights reserved.
