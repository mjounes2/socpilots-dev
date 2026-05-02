FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap \
      net-tools \
      iputils-ping \
      dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5003

CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "2", "--timeout", "300", "app:app"]
