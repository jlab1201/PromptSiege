FROM python:3.12-slim

WORKDIR /app

# System deps for Playwright's Chromium are installed via `playwright install --with-deps`.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

COPY ui/ ui/
COPY run.py .
COPY prompts.json .
COPY scripts/ scripts/
COPY start.sh .

EXPOSE 8000

# NOTE: 0.0.0.0 makes the server reachable from any interface the container's
# network is attached to. start.sh binds 127.0.0.1 for local-only use, but the
# CMD below intentionally overrides that for container deployment. The operator
# is responsible for controlling exposure (don't publish this port publicly
# without auth/reverse-proxy in front of it — this tool has no built-in auth).
CMD ["uvicorn", "ui.server:app", "--host", "0.0.0.0", "--port", "8000"]
