# ===========================
# Stage 1 - Builder
# ===========================
FROM python:3.13-slim AS builder

# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1

# Install uv
COPY --from=ghcr.io/astral-sh/uv:0.7.4 /uv /uvx /usr/local/bin/

WORKDIR /app

# Copy dependency files first (Docker cache)
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-cache

# Copy only runtime and migration sources. Key material is mounted at runtime.
COPY alembic.ini main.py dependencies.py rate_limit.py redis_client.py utils.py ./
COPY alembic ./alembic
COPY database ./database
COPY model ./model
COPY router ./router
COPY service ./service

# ===========================
# Stage 2 - Runtime
# ===========================
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Create non-root user
RUN addgroup --system app && \
    adduser --system --ingroup app app

# Copy virtual environment
COPY --from=builder /app/.venv /app/.venv

# Copy application
COPY --from=builder /app /app

# Give ownership to non-root user
RUN chown -R app:app /app

USER app

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
