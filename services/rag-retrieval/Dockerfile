FROM python:3.11-slim

WORKDIR /app

# CPU-only torch to avoid 2GB GPU build
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

EXPOSE 5005
CMD ["gunicorn", "--bind", "0.0.0.0:5005", "--workers", "1", "--timeout", "120", "rag_service:app"]
