# Local Setup

## Requirements

- Go 1.24+
- Node.js 22+
- npm 10+
- Docker with Compose for MySQL and Redis

## Start Dependencies

```bash
docker compose up -d mysql redis
```

## Start Backend

```bash
cd backend
go run ./cmd/server
```

## Start Frontend

```bash
npm install
npm run dev
```

The frontend runs at `http://localhost:3000` and the backend at `http://localhost:8080` by default.
