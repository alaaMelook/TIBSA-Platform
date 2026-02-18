# TIBSA — Threat Intelligence-Based Security Application

A full-stack cybersecurity platform built with **Next.js** (frontend) and **FastAPI** (backend), using **Supabase** for authentication and database.

## 🏗️ Architecture

| Layer | Technology | Deployment |
|-------|-----------|------------|
| Frontend | Next.js 16 (TypeScript) | Vercel |
| Backend | FastAPI (Python) | Railway |
| Database & Auth | Supabase |  |

## 📁 Project Structure

```
TIBSA/
├── frontend/          # Next.js app
│   └── src/
│       ├── app/       # Pages (App Router)
│       ├── components/# UI, Layout, Shared
│       ├── lib/       # Supabase client, API wrapper
│       ├── contexts/  # AuthContext (role-based)
│       ├── hooks/     # Custom hooks
│       └── types/     # TypeScript definitions
│
├── backend/           # FastAPI app
│   ├── app/
│   │   ├── routers/   # API endpoints
│   │   ├── models/    # Pydantic schemas
│   │   ├── services/  # Business logic
│   │   ├── repositories/ # Data access
│   │   └── middleware/ # Rate limiter, etc.
│   ├── tests/         # pytest
│   ├── Dockerfile     # For Railway
│   └── requirements.txt
│
├── database/          # SQL schemas (split by module)
│   ├── 01_users.sql   # Users & auth
│   ├── 02_scans.sql   # Scanning engine
│   └── 03_threats.sql # Threat intelligence
│
└── README.md
```

## 🚀 Getting Started

### Frontend
```bash
cd frontend
npm install
cp .env.local.example .env.local  # Add your Supabase keys
npm run dev                        # → http://localhost:3000
```

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate              # Windows
pip install -r requirements.txt
cp .env.example .env               # Add your Supabase keys
uvicorn app.main:app --reload      # → http://localhost:8000/docs
```

## 👤 Roles

- **User** — Default role for all new accounts
- **Admin** — Assigned manually by existing admin via User Management page

## 📦 Database Setup

SQL schemas are in the `database/` folder, split by module. Run them **in order** in the Supabase SQL Editor:

1. `01_users.sql` — User profiles & roles
2. `02_scans.sql` — Scan engine tables
3. `03_threats.sql` — Threat intelligence feeds & indicators

> **Note:** The schema is modular and evolving — new modules can be added as separate files (e.g., `04_reports.sql`).

## 🌐 Deployment

| Service | Platform | Config |
|---------|----------|--------|
| Frontend | Vercel | Root Directory: `frontend`, Framework: Next.js |
| Backend | Railway | Root Directory: `backend`, Builder: Dockerfile |

### Environment Variables

**Frontend (Vercel):**
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `NEXT_PUBLIC_API_URL` — Railway backend URL

**Backend (Railway):**
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `CORS_ORIGINS` — Vercel frontend URL
