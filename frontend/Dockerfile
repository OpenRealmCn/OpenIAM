FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
RUN printf 'server {\n  listen 80;\n  location / {\n    root /usr/share/nginx/html;\n    try_files $uri $uri/ /index.html;\n  }\n  location /api/ {\n    proxy_pass http://backend:8080;\n  }\n  location /oauth2/ {\n    proxy_pass http://backend:8080;\n  }\n  location /.well-known/ {\n    proxy_pass http://backend:8080;\n  }\n}\n' > /etc/nginx/conf.d/default.conf
EXPOSE 80
