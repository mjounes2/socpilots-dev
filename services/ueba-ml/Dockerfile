FROM python:3.11-slim

WORKDIR /app

# System deps — gcc for numpy/scikit-learn wheels, libstdc++ for sklearn
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1 \
    FLASK_APP=src.app \
    PORT=5006

EXPOSE 5006

CMD ["python", "-m", "src.app"]
