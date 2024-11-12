# Dockerfile for Flask Application
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
