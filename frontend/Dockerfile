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
FROM nginx:alpine

# SPA-aware nginx config (try_files fallback to /index.html).
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Ship only the built static assets.
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
