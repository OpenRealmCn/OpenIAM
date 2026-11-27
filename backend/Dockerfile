FROM golang:1.26-alpine AS builder
WORKDIR /app
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /openiam ./cmd/server

FROM alpine:3.20
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /openiam /app/openiam
RUN adduser -D -H -u 10001 app
USER app
EXPOSE 8080
ENTRYPOINT ["/app/openiam"]
