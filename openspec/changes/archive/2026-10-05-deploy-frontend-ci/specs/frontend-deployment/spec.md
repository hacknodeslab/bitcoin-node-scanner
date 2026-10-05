## ADDED Requirements

### Requirement: CI builds a deployable frontend artifact on every push to main

The CI pipeline SHALL produce a versioned, ready-to-run Next.js artifact (standalone server bundle, static assets, and `public/`) on every push to `main`. The artifact MUST be built with production environment variables set (`NEXT_PUBLIC_API_BASE_URL` resolved to the same-origin value used in production) and MUST NOT require `pnpm install` or `pnpm build` to be run on the production host.

#### Scenario: Successful build on push to main

- **WHEN** a commit lands on `main` and the GitHub Actions workflow runs
- **THEN** the workflow runs `pnpm install --frozen-lockfile` and `pnpm build` in `frontend/`
- **AND** the build uses `output: 'standalone'` so `frontend/.next/standalone/` and `frontend/.next/static/` are produced
- **AND** the artifact is available to the deploy step (uploaded as a workflow artifact or staged for the SSH/rsync step) without re-building

#### Scenario: Build fails the workflow

- **WHEN** `pnpm lint`, `pnpm typecheck`, or `pnpm build` exits non-zero
- **THEN** the workflow fails before any deploy step runs
- **AND** no frontend deploy is attempted

### Requirement: Deploy publishes the frontend artifact to the production host

The deploy workflow SHALL transfer the CI-built frontend artifact to the production EC2 host and start it under a dedicated systemd unit `bitcoin-scanner-frontend.service`. The deploy MUST NOT run `pnpm build` on the host, MUST be idempotent, and MUST restart the service so the new artifact is live before the workflow reports success.

#### Scenario: Successful deploy after a green build

- **WHEN** the CI build job succeeds on `main`
- **THEN** the deploy job copies `.next/standalone/`, `.next/static/`, and `public/` to `/home/ubuntu/bitcoin-node-scanner/frontend/` on the EC2 host
- **AND** runs `sudo systemctl restart bitcoin-scanner-frontend`
- **AND** the workflow only marks success after `systemctl is-active bitcoin-scanner-frontend` reports `active`

#### Scenario: Deploy is rerun without state changes

- **WHEN** the same commit is deployed twice (e.g., a re-run of the workflow)
- **THEN** the second run produces the same end state on the host (same files, service running on same revision)
- **AND** does not require manual cleanup

#### Scenario: Frontend deploy failure does not corrupt backend

- **WHEN** the frontend deploy step fails (e.g., file copy or service restart error)
- **THEN** the backend `bitcoin-scanner.service` continues running its previous revision
- **AND** the workflow exits non-zero so the failure is visible

### Requirement: Frontend service is lifecycle-managed by systemd

The Next.js server SHALL run as a non-root systemd unit on the production host, started automatically at boot, restarted on crash, and integrated with `journalctl` for logs. The service MUST run as the `ubuntu` user, MUST listen on `127.0.0.1:3000` (loopback only — public access goes via nginx), and MUST set `NODE_ENV=production`.

#### Scenario: Service auto-starts on host reboot

- **WHEN** the EC2 host reboots
- **THEN** `bitcoin-scanner-frontend.service` starts automatically
- **AND** the dashboard is reachable via the nginx origin without manual intervention

#### Scenario: Service auto-restarts after crash

- **WHEN** the Next.js process exits non-zero
- **THEN** systemd restarts it within 10 seconds
- **AND** the restart is recorded in `journalctl -u bitcoin-scanner-frontend`

### Requirement: nginx serves UI and API from a single origin

An nginx reverse proxy SHALL serve the production origin so that paths under `/api/` are proxied to the FastAPI backend on `127.0.0.1:8000` and all other paths are proxied to the Next.js server on `127.0.0.1:3000`. Browsers MUST see a single origin for both the dashboard and its API calls so that no CORS preflight is required in production.

#### Scenario: Dashboard request

- **WHEN** a browser requests `GET /` from the public origin
- **THEN** nginx proxies the request to `127.0.0.1:3000`
- **AND** the Next.js dashboard HTML is returned with status 200

#### Scenario: API request

- **WHEN** a browser requests `GET /api/v1/stats` from the public origin
- **THEN** nginx proxies the request to `127.0.0.1:8000`
- **AND** no CORS preflight (`OPTIONS`) is issued because the origin matches

#### Scenario: Backend root redirect

- **WHEN** an upstream client requests `GET /` directly against the backend port
- **THEN** the backend continues to 302-redirect to `FRONTEND_ORIGIN` as before
- **AND** in production `FRONTEND_ORIGIN` is set to the public origin so the redirect resolves to the same host

### Requirement: Deployment is documented and bootstrap is reproducible

The repository SHALL document the one-time host bootstrap (Node, nginx, systemd unit, sudoers rule) and the runtime deploy flow in `docs/`, and SHALL include a bootstrap shell script in `scripts/` that is safe to re-run on a fresh host. Required GitHub secrets MUST be listed.

#### Scenario: New operator bootstraps a fresh host

- **WHEN** an operator follows `docs/deploy-frontend.md` on a new Ubuntu host with `EC2_SSH_KEY` access
- **THEN** running `scripts/bootstrap-frontend-host.sh` (or the documented manual steps) installs Node 20, nginx, the systemd unit, and the nginx site config
- **AND** the next push to `main` succeeds in deploying without further manual steps

#### Scenario: Required secrets are listed

- **WHEN** an operator reads `docs/deploy-frontend.md`
- **THEN** the doc lists every GitHub secret the deploy workflow consumes (currently `EC2_SSH_KEY`)
- **AND** lists every host-side environment variable the frontend and backend services depend on
