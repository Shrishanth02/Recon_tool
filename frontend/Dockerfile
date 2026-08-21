# RECON-X frontend image (Phase 0) — multi-stage build.
#
# Stage 1 builds the Vite/React SPA into static assets (dist/).
# Stage 2 serves those assets with nginx.

# --- Stage 1: build ---------------------------------------------------------- #
FROM node:20 AS build

WORKDIR /app

# Install dependencies from the lockfile for reproducible builds.
COPY package.json package-lock.json ./
RUN npm ci

# Backend base URL the SPA calls. Vite inlines VITE_* vars at BUILD time, so it
# must be present here (not just at runtime). Provided via compose build args.
ARG VITE_API_BASE=http://localhost:8002
ENV VITE_API_BASE=${VITE_API_BASE}

# Build the production bundle into /app/dist.
COPY . .
RUN npm run build

# --- Stage 2: serve ---------------------------------------------------------- #
# Non-root nginx (runs as uid 101, listens on 8080 — no root master process and
# no privileged port). This is the same maintained nginx, purpose-built to run
# unprivileged, so a container escape does not start from root.
FROM nginxinc/nginx-unprivileged:alpine

# SPA-aware nginx config (try_files fallback to /index.html); it listens on 8080.
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Ship only the built static assets, readable by the unprivileged nginx user.
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html

EXPOSE 8080

# The base image already sets USER 101 and the non-root entrypoint/CMD.
