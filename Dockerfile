FROM python:3.12-slim

# uv — fast Python package manager (no pip needed)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (better layer caching)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source
COPY . .

EXPOSE 8000

# Default: run the demo SOC pipeline and render incident reports
CMD ["uv", "run", "python", "manage.py", "scan_logs", "--out", "reports"]
