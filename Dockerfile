FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crawler.py .
COPY worker.py .
COPY controller.py .

RUN useradd -m -u 1000 crawler
USER crawler

CMD ["python", "worker.py"]