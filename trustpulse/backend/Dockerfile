# TRUSTPULSE backend image.
#
# The build context MUST be the `trustpulse/` repository root (not `backend/`),
# because the backend depends on the `ml/` package one level up:
#
#   docker build -f backend/Dockerfile .
#
# docker-compose already sets `context: .` / `dockerfile: backend/Dockerfile`.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps for numpy/pandas/scikit-learn wheels when no manylinux wheel matches.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1) Python deps first so the layer caches across code changes.
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# 2) The ML package. Installed explicitly — NOT via requirements.txt, because pip
#    resolves relative paths against the working directory, not the file location.
COPY ml ml
RUN pip install --no-cache-dir ./ml

# 3) Application code and the shared configuration bundle.
COPY backend backend
COPY shared shared

# The trust model JSON is read from disk; make the path deterministic.
ENV SHARED_DIR=/app/shared \
    PYTHONPATH=/app/backend

EXPOSE 8000

# Non-root runtime user.
RUN useradd --create-home --uid 10001 trustpulse \
    && chown -R trustpulse:trustpulse /app
USER trustpulse

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/platform/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
