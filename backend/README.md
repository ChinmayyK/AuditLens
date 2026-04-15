# ShieldSentinel

Integrated backend services and frontend application for ShieldSentinel.

## Layout

- `api/`: FastAPI app, workers, migrations, and backend packages.
- `frontend/`: React + TypeScript + Vite app.
- `compose/`: Docker Compose stack for the API, workers, gateway, frontend, Postgres, Redis, and scanner services.
- `gateway/`: Nginx gateway that serves the frontend and proxies API/websocket traffic.

## Run The Integrated Stack

```sh
docker compose -f compose/docker-compose.yml up gateway api web
```

Open `http://localhost:99`. The gateway proxies `/api/v1/*` to the FastAPI service on `9997` and `/ws/*` to the websocket endpoint.
