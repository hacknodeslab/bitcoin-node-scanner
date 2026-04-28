## Why

The Next.js dashboard at `frontend/` is built in CI (`.github/workflows/ci.yml` `frontend` job) but is never published anywhere — `.github/workflows/deploy.yml` only `git pull`s the repo and restarts the Python `bitcoin-scanner` systemd service on EC2. After the dashboard cutover (commit `8e3d271` removed the legacy static UI), there is no UI being served in production. The backend on `:8000` redirects `GET /` to `FRONTEND_ORIGIN`, but nothing is listening on the configured origin, so the product is effectively headless in prod.

## What Changes

- Add a CI job that produces a deployable Next.js artifact on every push to `main` (build once, deploy the same artifact — do not rebuild on the server).
- Extend `deploy.yml` to deploy the frontend to the same EC2 host alongside the backend:
  - Install Node 20 + pnpm on the host (one-time bootstrap, idempotent).
  - Sync the built `frontend/.next` output and runtime files (`package.json`, `pnpm-lock.yaml`, `public/`, `next.config.ts`) to `/home/ubuntu/bitcoin-node-scanner/frontend/`.
  - Run `pnpm install --prod --frozen-lockfile` on the host.
  - Manage `next start -p 3000` with a new `bitcoin-scanner-frontend.service` systemd unit (restarted by deploy, started on boot).
- Add an nginx reverse proxy config so the public origin serves the dashboard on `/` and proxies `/api/*` to the FastAPI backend on `:8000` (single origin removes the cross-origin `FRONTEND_ORIGIN` workaround for prod).
- Update environment configuration: set `FRONTEND_ORIGIN` on the backend to the public origin; set `NEXT_PUBLIC_API_BASE_URL` (or equivalent) on the frontend build so it calls the same origin.
- Document required GitHub secrets and one-time host bootstrap steps in `docs/`.
- **Non-goal**: migrating to Vercel, Docker, or multi-host infra. This change keeps the existing single-EC2 + systemd + SSH pattern.

## Capabilities

### New Capabilities
- `frontend-deployment`: CI builds and deploys the Next.js dashboard to the production host so it is reachable on the public origin, lifecycle-managed by systemd, and reverse-proxied alongside the FastAPI backend.

### Modified Capabilities
<!-- None. `web-dashboard` describes UX, not deployment infra; no requirement changes there. -->

## Impact

- **CI/CD**: `.github/workflows/ci.yml` (existing `frontend` job stays as gate), `.github/workflows/deploy.yml` (new frontend deploy steps or a new parallel job).
- **Production host** (`98.94.124.224`): new systemd unit `bitcoin-scanner-frontend.service`, nginx site config, Node 20 + pnpm installed.
- **GitHub secrets**: existing `EC2_SSH_KEY` reused; no new secrets unless we add a separate deploy key.
- **Backend**: `FRONTEND_ORIGIN` value updated; no code changes in `src/`.
- **Frontend**: `next.config.ts` may need `output: 'standalone'` for slimmer deploys; `NEXT_PUBLIC_*` env wired at build time.
- **Risk**: first-time host bootstrap (Node + nginx + systemd unit) is manual; document it so the deploy job stays declarative for subsequent runs.
