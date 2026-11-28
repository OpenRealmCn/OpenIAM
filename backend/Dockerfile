FROM golang:1.26-alpine AS builder
WORKDIR /app
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /openiam ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /openiam /app/openiam
# data/ 用于持久化自动生成的 JWT 签名私钥，需挂载卷，否则重建容器会使已签发令牌全部失效
RUN adduser -D -H -u 10001 app && mkdir -p /app/data && chown app:app /app/data && chmod 700 /app/data
USER app
VOLUME ["/app/data"]
EXPOSE 8080
ENTRYPOINT ["/app/openiam"]
