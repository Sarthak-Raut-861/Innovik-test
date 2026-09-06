# TRUSTPULSE frontend image — build the SPA, serve it with nginx.
#
# Build context is the `trustpulse/` root so the shared contracts can be copied:
#   docker build -f frontend/Dockerfile .

FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund

COPY frontend/ ./
# Optional: bake the demo integration key in. Leave unset for a real deployment
# where the browser must never hold a credential.
ARG VITE_TRUSTPULSE_API_KEY=""
ARG VITE_TRUSTPULSE_TENANT="trustdev-demo"
ENV VITE_TRUSTPULSE_API_KEY=${VITE_TRUSTPULSE_API_KEY} \
    VITE_TRUSTPULSE_TENANT=${VITE_TRUSTPULSE_TENANT}

RUN npm run build


FROM nginx:1.27-alpine AS runtime

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -q --spider http://127.0.0.1/ || exit 1
