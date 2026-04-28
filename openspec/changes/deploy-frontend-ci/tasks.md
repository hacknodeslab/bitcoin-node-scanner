## 1. Frontend build configuration

- [x] 1.1 Set `output: 'standalone'` in `frontend/next.config.ts` and verify `pnpm build` produces `.next/standalone/` and `.next/static/` locally.
- [x] 1.2 Decide and document the production same-origin convention: build with `NEXT_PUBLIC_API_BASE_URL="/api/v1"` (relative → same-origin via nginx). Audited `frontend/lib/`: only the dev default in `config.ts` references `localhost:8000`; `client.ts buildUrl` updated to handle relative bases via `window.location.origin`.
- [x] 1.3 Added `pnpm build:prod` script in `frontend/package.json` (`NEXT_PUBLIC_API_BASE_URL=/api/v1 next build`). `frontend/.env.example` documents dev vs prod values.

## 2. CI: build the deploy artifact

- [x] 2.1 Packaging step lives in `deploy.yml` (`Assemble frontend-dist (standalone layout)` step), not `ci.yml`, since strategy (b) was chosen — the deploy job builds and packages in one place. The step writes the standalone layout (`server.js`, `node_modules/`, `.next/static/`, `public/`) under `frontend/frontend-dist/`.
- [x] 2.2 Strategy (b) chosen: build inside the deploy job. No artifact upload/download round-trip; CI's `frontend` job stays as the lint/typecheck/build gate, and the deploy job rebuilds with prod env vars (`NEXT_PUBLIC_API_BASE_URL=/api/v1`, `NEXT_PUBLIC_WEB_API_KEY` from secrets).

## 3. Production host: one-time bootstrap

- [x] 3.1 `scripts/bootstrap-frontend-host.sh` — idempotent bash script: installs Node 20 (NodeSource) + nginx, creates `$FRONTEND_RUNTIME_DIR` (default `/home/ubuntu/bitcoin-scanner-frontend/`, **outside** the git checkout to avoid `git pull` collisions), installs the systemd unit + nginx site + sudoers drop-in, validates with `nginx -t` and `visudo -cf`. Re-run is a no-op when nothing changed.
- [x] 3.2 `scripts/systemd/bitcoin-scanner-frontend.service`: `WorkingDirectory=/home/ubuntu/bitcoin-scanner-frontend`, `ExecStart=/usr/bin/node server.js`, `User=ubuntu`, prod env, `Restart=on-failure`, `MemoryMax=512M`, hardening flags (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=/home/ubuntu/bitcoin-scanner-frontend`).
- [x] 3.3 `scripts/nginx/bitcoin-scanner.conf`: upstreams for `:8000` and `:3000`; `/api/` proxies to backend (with `proxy_buffering off` for streaming routes), `/_next/static/` cached 1y immutable, `/` proxies to Next.js. Sets `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`. HTTP-only; TLS deferred.
- [x] 3.4 `scripts/sudoers.d/bitcoin-scanner-frontend`: NOPASSWD for `systemctl restart|is-active|status bitcoin-scanner-frontend(.service)?`. Installed by the bootstrap script with `visudo -cf` validation.
- [ ] 3.5 **HOST-SIDE (you do this):** copy the bootstrapped repo to the EC2 (or just `git pull` the new commit), run `bash scripts/bootstrap-frontend-host.sh`, then `systemctl enable --now bitcoin-scanner-frontend`. Verify `nginx -t && systemctl reload nginx` is clean. Smoke test: `curl -fsS http://127.0.0.1:3000/` returns Next.js HTML (will only work AFTER the first deploy populates the runtime dir; before that, expect a 5xx — that's fine).

## 4. CD: extend deploy.yml to ship the frontend

- [x] 4.1 New `frontend` job in `.github/workflows/deploy.yml`: checkout → Node 20 + pnpm → `pnpm install --frozen-lockfile` → `pnpm build` with `NEXT_PUBLIC_API_BASE_URL=/api/v1` and `NEXT_PUBLIC_WEB_API_KEY` from `secrets.WEB_API_KEY` → assemble `frontend-dist/` (server.js + node_modules + .next/static + public).
- [x] 4.2 `appleboy/scp-action@v0.1.7` uploads `frontend-dist/` to `$FRONTEND_STAGING_DIR` (`/home/ubuntu/bitcoin-scanner-frontend-staging/`). The follow-up SSH step `rsync -a --delete`s staging → `$FRONTEND_RUNTIME_DIR` so an interrupted upload never leaves a half-broken runtime dir. Files stay `ubuntu:ubuntu`.
- [x] 4.3 SSH activation step runs `sudo systemctl restart bitcoin-scanner-frontend` then `sudo systemctl is-active bitcoin-scanner-frontend`. `set -euo pipefail` + the `is-active` check fail the job non-zero if the service didn't come back.
- [x] 4.4 `frontend` job declares `needs: backend`, so backend deploys first. If frontend fails, backend is on the new revision and the previous frontend keeps serving (acceptable per design).
- [ ] 4.5 **Deferred** — running both jobs unconditionally on every push is fine for now (tiny repo, fast deploys). Revisit if deploy time grows. Would need `paths-filter` or `dorny/paths-filter` action to gate jobs cleanly.

## 5. Backend / environment configuration

- [ ] 5.1 **HOST-SIDE (you do this):** on the EC2, set `FRONTEND_ORIGIN=http://98.94.124.224` (or your domain) in the backend's env (the `.env` it reads on launch, or a systemd drop-in `/etc/systemd/system/bitcoin-scanner.service.d/override.conf`). `sudo systemctl daemon-reload && sudo systemctl restart bitcoin-scanner`. Verify with `curl -I http://98.94.124.224/api/v1/csrf-token` returns 200 (or expected auth status — not a CORS error) and that `curl -I http://98.94.124.224:8000/` (direct to backend) shows `Location: http://98.94.124.224` in the redirect.
- [x] 5.2 Audit done — `src/web/main.py:43–54` reads `FRONTEND_ORIGIN` (default `http://localhost:3000`), splits on commas, sets `CORSMiddleware.allow_origins`. In dev (cross-origin) the preflight fires and is allowed; in prod (single origin via nginx) browsers don't issue a preflight at all, so CORS is effectively a no-op for browser traffic. **No backend code change required.**
- [ ] 5.3 **HOST-SIDE (you do this):** after first deploy, open the dashboard at `http://98.94.124.224/`, hit the network tab on a mutating request (e.g. start a scan), confirm the `csrftoken` cookie round-trips and the `X-CSRF-Token` header is accepted. If cookies don't stick: check `proxy_cookie_path /` in `scripts/nginx/bitcoin-scanner.conf` (already implicit via default settings, but adjust if needed) and that the backend isn't setting `Domain=localhost` or `SameSite=None; Secure` (the latter requires HTTPS).

## 6. Documentation

- [x] 6.1 `docs/deploy-frontend.md` written: architecture diagram, prerequisites, one-time bootstrap, GitHub secrets table (`EC2_SSH_KEY`, `WEB_API_KEY`), per-push deploy flow, smoke tests, troubleshooting matrix (502 from nginx, OOM, CSRF cookie issues, etc.), rollback playbook (revert vs. backup-tree), TLS/HTTPS deferred path with certbot.
- [x] 6.2 `README.md` "Web Interface" section reframed: dev = cross-origin, prod = single-origin via nginx; added link to `docs/deploy-frontend.md` from the Documentation section.
- [x] 6.3 `CLAUDE.md` "Layer Overview" annotated with dev vs. prod topology and link to `docs/deploy-frontend.md`.

## 7. Validation

- [ ] 7.1 **HOST-SIDE (you do this):** after first successful deploy: `curl -fsS http://98.94.124.224/ | head -c 200` returns Next.js HTML; `curl -fsS http://98.94.124.224/api/v1/csrf-token` returns JSON. Open the dashboard in a browser, verify nodes/stats populate, click around routes (no 404 on static assets).
- [ ] 7.2 **HOST-SIDE (you do this):** failure tests. (a) push a commit that breaks `pnpm build` → confirm CI's `frontend` job fails and deploy never starts. (b) push a commit that breaks `next start` at runtime → confirm the `is-active` check fails the deploy job. Note: in case (b) the frontend IS down (we restarted into a broken revision); recovery is `git revert` + push or restore the runtime dir from the manual backup described in `docs/deploy-frontend.md`.
- [ ] 7.3 **HOST-SIDE (you do this):** reboot test — `sudo reboot`, then verify `systemctl is-active bitcoin-scanner` and `systemctl is-active bitcoin-scanner-frontend` both return `active`.
- [ ] 7.4 **HOST-SIDE (you do this):** re-run validation — re-trigger the same successful Actions run via the GitHub UI, confirm no drift (`ls -la /home/ubuntu/bitcoin-scanner-frontend/` shows updated mtimes but the same files; no leftover `frontend-staging-*` dirs).
