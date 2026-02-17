# TIBSA — Threat Intelligence-Based Security Application

A full-stack cybersecurity platform built with **Next.js** (frontend) and **FastAPI** (backend), using **Supabase** for authentication and database.

## 🏗️ Architecture

| Layer | Technology | Deployment |
|-------|-----------|------------|
| Frontend | Next.js 14+ (TypeScript) | Vercel |
| Backend | FastAPI (Python) | Render |
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
│   ├── Dockerfile     # For Render
│   └── requirements.txt
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

## 📦 Supabase Tables Needed

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY REFERENCES auth.users(id),
  email TEXT NOT NULL,
  full_name TEXT NOT NULL,
  role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Scans table
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  scan_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  threat_level TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ
);

-- Scan Reports
CREATE TABLE scan_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id),
  summary TEXT,
  details JSONB DEFAULT '{}',
  indicators JSONB DEFAULT '[]',
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Threat Feeds
CREATE TABLE threat_feeds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  source_url TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_updated TIMESTAMPTZ DEFAULT now()
);

-- Threat Indicators (IOCs)
CREATE TABLE threat_indicators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  threat_level TEXT DEFAULT 'safe',
  source TEXT,
  last_seen TIMESTAMPTZ DEFAULT now()
);
```
