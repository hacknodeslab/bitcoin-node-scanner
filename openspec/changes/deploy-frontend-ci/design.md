## Context

The repo has two toolchains: a Python FastAPI backend at `src/web/` (port 8000) and a Next.js 16 dashboard at `frontend/` (port 3000, pnpm). Production today runs only the backend on a single Ubuntu EC2 host (`98.94.124.224`), deployed by `appleboy/ssh-action` from `.github/workflows/deploy.yml` on every push to `main`. The deploy script `git pull`s, `pip install`s, and restarts a `bitcoin-scanner` systemd unit.

The frontend job in `.github/workflows/ci.yml` already runs `pnpm install/lint/typecheck/build`, so build correctness is enforced — but the resulting `.next` is discarded. The cutover commit `8e3d271` removed the legacy backend-served HTML, so production is currently UI-less. `GET /` on the backend 302-redirects to `FRONTEND_ORIGIN`, which today points to nothing reachable.

Stakeholders: solo operator (this user). Constraints: keep ops simple, single host, no new paid services, reuse the existing `EC2_SSH_KEY` secret.

## Goals / Non-Goals

**Goals:**
- Frontend reachable at the public origin after every push to `main`, with no manual steps.
- Same-origin serving of UI (`/`) and API (`/api/*`) so cross-origin/CSRF/cookie complexity disappears in prod.
- Build artifact is produced once in CI and copied to the host — host does not run `pnpm build` (slow, memory-hungry on small EC2).
- Frontend lifecycle managed by systemd, like the backend.
- Rollback is `git checkout <prev-sha> && systemctl restart` on the host (acceptable for solo ops).

**Non-Goals:**
- Migrating to Vercel, Cloudflare Pages, S3+CloudFront, or Docker.
- Multi-host or zero-downtime blue/green deploys.
- HTTPS/TLS automation (assume an existing nginx + certbot setup or document as a one-time manual step).
- Container orchestration, autoscaling, CDN.

## Decisions

### D1. Deploy on the same EC2 host as the backend
**Choice:** Run `next start` on the host as a second systemd service, behind nginx, on the same box as FastAPI.
**Why:** Matches the existing operational model (single host, SSH deploy, systemd). No new infra accounts, secrets, or billing surfaces.
**Alternatives considered:**
- *Vercel*: zero-ops, native Next.js, free tier — but adds a third deploy surface, splits prod across vendors, and the API still lives on EC2 so cross-origin issues remain.
- *Static export (`next export`)* to S3+CloudFront: cheap and fast, but the dashboard uses dynamic data fetching patterns that benefit from `next start`'s server runtime, and we'd need to invalidate CloudFront on deploy.
- *Docker on the same host*: adds a runtime layer for no real benefit at this scale.

### D2. Build in CI, ship the artifact via SCP/rsync
**Choice:** Use `next.config.ts` `output: 'standalone'`. CI uploads `.next/standalone/`, `.next/static/`, and `public/` as a deploy artifact (or `rsync`s directly over SSH). The host does not run `pnpm install` or `pnpm build`.
**Why:** EC2 small instances can OOM during `next build`; CI runners have 7GB. Standalone output bundles only the prod node_modules needed for runtime (~50MB vs ~500MB), and the host doesn't need pnpm at all.
**Alternatives considered:**
- *Build on the host (`git pull && pnpm build`)*: simpler script, but slow (~2–3 min) and risks OOM. Also requires installing pnpm on the host.
- *GitHub Actions artifact + separate deploy job*: cleaner job graph but adds an artifact upload/download round-trip. Acceptable; pick whichever is simpler in YAML.

### D3. Single origin via nginx reverse proxy
**Choice:** nginx serves the public origin. `/api/*` → `http://127.0.0.1:8000`, everything else → `http://127.0.0.1:3000`.
**Why:** Eliminates cross-origin CSRF/cookie pain in prod. The backend already ships CORS+CSRF for dev (`localhost:3000` → `localhost:8000`), but in prod we don't need it. `FRONTEND_ORIGIN` becomes the same public origin, so the redirect from `/` works trivially.
**Alternatives:**
- *Two subdomains (`app.example.com` + `api.example.com`)*: keeps cross-origin in prod, requires CORS allowlist maintenance. Rejected — single origin is strictly simpler.

### D4. Two systemd units, deployed independently but in lockstep
**Choice:** New unit `bitcoin-scanner-frontend.service` runs `node .next/standalone/server.js` (or `pnpm start`) as user `ubuntu`. Existing `bitcoin-scanner.service` keeps the backend. Deploy job restarts both.
**Why:** Independent unit means the frontend can crash/restart without affecting the API and vice versa. Standard systemd patterns.

### D5. Reuse existing `EC2_SSH_KEY` secret
**Choice:** No new GitHub secrets. The frontend deploy step uses the same `appleboy/ssh-action` block.
**Why:** One credential to rotate.

### D6. Environment variables wired at build time
**Choice:** `NEXT_PUBLIC_API_BASE_URL` is set to `""` (empty / same-origin) in the CI build step, since nginx co-locates UI and API. Backend's `FRONTEND_ORIGIN` is set to the public origin in `/etc/systemd/system/bitcoin-scanner.service.d/override.conf` (or `.env`) on the host.
**Why:** `NEXT_PUBLIC_*` vars are inlined at build time, so they must be set in CI before `pnpm build`, not on the host.

## Risks / Trade-offs

- **[Risk] First-run host bootstrap is manual** (install Node 20, nginx, write systemd unit + nginx site, sudoers rule for `systemctl restart bitcoin-scanner-frontend`). → **Mitigation:** Document in `docs/deploy-frontend.md`; provide a one-shot bootstrap script in `scripts/bootstrap-frontend-host.sh` so it's repeatable if the host is ever rebuilt.
- **[Risk] No HTTPS strategy in this change.** → **Mitigation:** Out of scope; document as a prerequisite. If the host already has nginx+certbot, the new site config plugs into it; if not, this change ships HTTP-only and a follow-up adds TLS.
- **[Risk] Frontend and backend deploy can drift** (e.g., backend deploys, frontend fails). → **Mitigation:** Deploy backend first, then frontend, in the same job; if frontend deploy fails, backend is still live and the redirect just lands on a stale UI. Acceptable for solo ops; revisit if it bites.
- **[Risk] `next start` memory footprint** on a small EC2. → **Mitigation:** standalone output keeps RAM under ~150MB idle. Add `MemoryMax=512M` to the unit if needed.
- **[Trade-off] Same-origin nginx setup ties the frontend to running on the same host as the backend.** Acceptable today; if we ever split, we add CORS back and switch `NEXT_PUBLIC_API_BASE_URL` to an absolute URL — both straightforward.
- **[Risk] Rebuild on every main push even if only backend changed (and vice versa).** → **Mitigation:** Use `paths-filter` action or two jobs gated by `paths:` in the workflow trigger to skip unaffected halves. Optimization, not a blocker.

## Migration Plan

1. **One-time host bootstrap (manual, documented):**
   - `apt install -y nginx`, install Node 20 via NodeSource.
   - Create `/etc/systemd/system/bitcoin-scanner-frontend.service` (template in `scripts/`).
   - Create `/etc/nginx/sites-available/bitcoin-scanner` with the reverse-proxy config; `ln -s` to `sites-enabled`; remove default site; `systemctl reload nginx`.
   - Add `ubuntu` to a sudoers rule allowing `systemctl restart bitcoin-scanner-frontend` without a password.
2. **Update `deploy.yml`** to add the frontend build + ship + restart steps.
3. **Update `next.config.ts`** with `output: 'standalone'`.
4. **First deploy:** push to `main`, watch the Actions log, verify `curl http://<host>/` returns the dashboard HTML and `curl http://<host>/api/v1/csrf-token` works.
5. **Rollback:** if a deploy is bad, on the host run `git checkout <prev-good-sha> -- frontend/` (or restore the previous `.next` dir if kept) and `systemctl restart bitcoin-scanner-frontend`. For a hard rollback, `git revert` the offending commit on `main` — re-deploy is automatic.

## Open Questions

- What is the public DNS / origin for prod? (Affects `FRONTEND_ORIGIN`, nginx `server_name`, TLS.) — **Assumption for now:** the EC2 IP `98.94.124.224` over HTTP, until a domain is wired up.
- Is there an existing nginx on the host, or is this its first install? — **Assumption:** first install, scripted in bootstrap.
- Do we want CI to fail the deploy if the build artifact is larger than some budget? — **Defer.** Add later if bundle size becomes a real concern.
