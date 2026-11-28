FROM node:22-alpine AS builder
WORKDIR /app

ARG NPM_REGISTRY=https://registry.npmmirror.com
ENV NPM_CONFIG_REGISTRY=${NPM_REGISTRY} \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_MAXSOCKETS=8 \
    NPM_CONFIG_FETCH_RETRIES=5 \
    NPM_CONFIG_FETCH_RETRY_MINTIMEOUT=20000 \
    NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT=120000

COPY package.json package-lock.json* ./
RUN set -eux; \
    CLEAN_REGISTRY="${NPM_REGISTRY%/}"; \
    if [ -f package-lock.json ] && [ "$CLEAN_REGISTRY" != "https://registry.npmmirror.com" ]; then \
      sed -i "s|https://registry.npmmirror.com|${CLEAN_REGISTRY}|g" package-lock.json; \
    fi; \
    npm ci --no-audit --no-fund --loglevel=warn || \
    (npm cache clean --force && npm install --no-audit --no-fund --loglevel=warn)

COPY . .
RUN npm run build

FROM nginx:alpine
ENV BACKEND_UPSTREAM=http://backend:8080
ENV NGINX_ENVSUBST_FILTER=BACKEND_UPSTREAM
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
EXPOSE 80
