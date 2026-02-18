---
description: How to run TIBSA locally and deploy to Vercel + Render
---

# Run Locally & Deploy

## Step 1: Set Environment Variables

### Frontend (`frontend/.env.local`)
```env
NEXT_PUBLIC_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key-here
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### Backend (`backend/.env`)
```env
SUPABASE_URL=https://YOUR-PROJECT.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here
CORS_ORIGINS=http://localhost:3000
```

> Get keys from: Supabase Dashboard → Project Settings → API

---

## Step 2: Run Backend (FastAPI)

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload  # → http://localhost:8000/docs
```

## Step 3: Run Frontend (Next.js)

```bash
cd frontend
npm run dev                    # → http://localhost:3000
```

---

## Step 4: Deploy Backend to Render (Free)

1. Push code to GitHub
2. Go to [render.com](https://render.com) → New → **Web Service**
3. Connect your GitHub repo
4. Settings:
   - **Name**: `tibsa-api`
   - **Root Directory**: `backend`
   - **Runtime**: `Docker`
   - **Instance Type**: `Free`
5. Environment Variables (add in Render dashboard):
   - `SUPABASE_URL` = your Supabase URL
   - `SUPABASE_SERVICE_ROLE_KEY` = your service role key
   - `CORS_ORIGINS` = `https://your-frontend.vercel.app`
6. Click **Create Web Service** → wait for deploy

> Your backend URL will be: `https://tibsa-api.onrender.com`

---

## Step 5: Deploy Frontend to Vercel (Free)

1. Go to [vercel.com](https://vercel.com) → **Add New Project**
2. Import your GitHub repo
3. Settings:
   - **Framework Preset**: Next.js (auto-detected)
   - **Root Directory**: `frontend`
4. Environment Variables:
   - `NEXT_PUBLIC_SUPABASE_URL` = your Supabase URL
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY` = your anon key
   - `NEXT_PUBLIC_API_URL` = `https://tibsa-api.onrender.com`
5. Click **Deploy**

> Your frontend URL will be: `https://tibsa.vercel.app`

---

## Step 6: Update CORS After Deploy

Go back to Render → Environment Variables → update `CORS_ORIGINS`:
```
CORS_ORIGINS=https://your-frontend.vercel.app,http://localhost:3000
```

---

## Step 7: Create First Admin

Since all new accounts get `role = "user"`:
1. Register normally on the site
2. Go to Supabase Dashboard → Table Editor → `users`
3. Find your row → change `role` from `user` to `admin`
4. Now you can manage other users from `/admin/users`
