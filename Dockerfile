# One image, shared by all services (auth + both tenants + the init step).
# The service a container becomes is decided by its compose `command`.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    KEYS_DIR=/app/keys \
    DATA_DIR=/app/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default; overridden per service in docker-compose.yml.
CMD ["uvicorn", "auth_service.asgi:app", "--host", "0.0.0.0", "--port", "8000"]
