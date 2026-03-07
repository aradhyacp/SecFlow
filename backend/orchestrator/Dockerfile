FROM python:3.11-slim

# libmagic1: needed by python-magic
# file: needed for fallback mime detection
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 file curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

ENV FLASK_APP=app
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:create_app()"]
