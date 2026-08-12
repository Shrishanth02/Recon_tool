# RECON-X API image (Phase 0)
#
# This image runs the FastAPI backend only. The single system-level scanner
# tool the API image needs is nmap, installed from apt below.
#
# NOTE: subfinder / httpx / nuclei / ffuf are NOT installed here. Those are
# Phase-2 worker-image tools and belong in the (commented) worker service /
# its own image, not in the API image.

FROM python:3.11-slim

# Don't buffer stdout/stderr (so logs stream straight to docker), don't write
# .pyc files, and keep pip from caching wheels into the image layer.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System dependencies:
#   nmap             - port/service scanner used by the API image
#   ca-certificates  - TLS roots for outbound HTTPS (whois / builtwith / etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first so this layer is cached across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source.
COPY . .

EXPOSE 8002

# Run the ASGI app. Bind to 0.0.0.0 so the port is reachable from outside the
# container; use the same port (8002) the rest of the stack expects.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
