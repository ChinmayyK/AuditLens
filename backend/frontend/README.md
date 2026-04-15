# ShieldSentinel Frontend

React + TypeScript + Vite application for the ShieldSentinel API in this repository.

## Integrated Development

From the repository root:

```sh
docker compose -f compose/docker-compose.yml up gateway api web
```

The gateway serves the app at `http://localhost:99`, proxies API requests to `api:9997`, and forwards websocket traffic under `/ws`.

## Local Frontend Only

```sh
npm install
npm run dev
```

When run outside Docker, Vite starts on `http://localhost:9998` and proxies `/api` plus `/ws` to `http://localhost:9997` by default.

Copy `.env.example` to `.env` only when you want the browser to call a specific gateway or API host directly. For the integrated Docker stack, the defaults are usually enough.

## Scripts

- `npm run dev`: start Vite on port `9998`.
- `npm run build`: type-check and build the production bundle.
- `npm run lint`: run ESLint.
- `npm run preview`: preview a production build locally.
