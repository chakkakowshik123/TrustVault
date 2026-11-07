# TrustVault — Deployment Guide

## 1. Local Development

```bash
# Clone / enter project
cd trustvault

# Create virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env — set a strong SECRET_KEY:
# python -c "import secrets; print(secrets.token_hex(32))"

# Run the application
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 — first registered user becomes **Admin**.

---

## 2. Run Tests

```bash
# From the trustvault/ directory (venv active)
pytest tests/ -v --tb=short --cov=app --cov-report=term-missing
```

Expected: **all tests pass**, coverage ≥ 80 %.

---

## 3. Docker (Local Container)

```bash
# Build and start
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

Data is persisted in Docker volume `trustvault_data`.

---

## 4. GitHub — Push

```bash
cd trustvault
git init
git add .
git commit -m "feat: initial TrustVault implementation"
git remote add origin https://github.com/<YOUR-USERNAME>/trustvault.git
git push -u origin main
```

> **Important**: `.gitignore` already excludes `.env`, `uploads/`, `*.db`.
> Never commit secrets or uploaded files.

---

## 5. Google Cloud Run (Production)

### Prerequisites
- Google Cloud account with billing enabled
- `gcloud` CLI installed and authenticated

### Deploy

```bash
# Set your project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com

# Deploy directly from source (Cloud Build builds the Docker image)
gcloud run deploy trustvault \
  --source . \
  --region asia-southeast1 \
  --platform managed \
  --allow-unauthenticated \
  --port 8000 \
  --memory 512Mi \
  --cpu 1 \
  --set-env-vars "SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')" \
  --set-env-vars "DATABASE_URL=sqlite:////tmp/trustvault.db" \
  --set-env-vars "UPLOAD_DIR=/tmp/uploads" \
  --set-env-vars "MAX_FILE_SIZE_MB=50"
```

> ⚠️ **Cloud Run caveat**: The container filesystem is ephemeral. For production,
> use **Cloud SQL** (PostgreSQL) for the database and **Google Cloud Storage** for file uploads.
> The SQLite + local uploads setup works for demos and hackathon submissions.

### Production-grade GCS upload (optional upgrade)
Replace the `open()` calls in `documents.py` with `google-cloud-storage` client calls.
Set `BUCKET_NAME` as an env var and store/retrieve files via signed URLs.

---

## 6. Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | JWT signing key — **must be set in production** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Session length |
| `DATABASE_URL` | `sqlite:///./trustvault.db` | SQLAlchemy connection string |
| `UPLOAD_DIR` | `uploads` | Private directory for uploaded files |
| `MAX_FILE_SIZE_MB` | `50` | Maximum upload size |

---

## 7. Security Checklist

- [x] Passwords hashed with bcrypt (never stored plaintext)
- [x] JWT stored in `HttpOnly` cookie (not accessible by JS)
- [x] `uploads/` directory is NOT under `/static` (never served directly)
- [x] Every access event recorded in `audit_logs` table
- [x] Soft delete (documents recoverable by admin)
- [x] Admin role restricted endpoints (`/audit`, `/audit/export`)
- [x] Permission levels: `view` → `download` → `manage`
- [ ] Set `secure=True` on cookie when behind HTTPS (update `auth.py`)
- [ ] Rotate `SECRET_KEY` periodically in production
- [ ] Enable Cloud Armor / rate limiting in front of Cloud Run
