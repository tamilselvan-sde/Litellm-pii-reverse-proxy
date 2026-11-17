FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py pii_baseline.json ./
EXPOSE 8080
# NOTE: HEALTHCHECK is not embedded here on purpose — podman builds OCI
# images where Dockerfile HEALTHCHECK is silently ignored. The healthcheck
# lives at service level in docker-compose.yml instead.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
