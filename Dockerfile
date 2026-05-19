FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY backend/ backend/
COPY agents/ agents/
COPY dashboard/ dashboard/
COPY server.py .

# Create __init__.py files so Python treats dirs as packages
RUN touch backend/__init__.py agents/__init__.py

EXPOSE 5000

ENV PYTHONUNBUFFERED=1
ENV DEMO_MODE=true

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120"]
