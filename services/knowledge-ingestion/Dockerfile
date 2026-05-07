FROM python:3.11-slim

WORKDIR /app

# System deps: tesseract for OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
      tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only torch first (avoids pulling 2GB GPU build)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

EXPOSE 5004
# Single worker to avoid loading the 90MB model N times
CMD ["gunicorn", "--bind", "0.0.0.0:5004", "--workers", "1", "--timeout", "600", "app:app"]
