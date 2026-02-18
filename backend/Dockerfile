FROM python:3.11-slim

WORKDIR /app

# Install dependencies (paths relative to repo root)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend app code
COPY backend/app ./app

# Expose port
EXPOSE 8000

# Run with uvicorn
CMD ["/bin/sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
