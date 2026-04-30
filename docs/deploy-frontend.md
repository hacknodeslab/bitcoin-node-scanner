# Frontend deployment

Production runs both the FastAPI backend and the Next.js dashboard on a single Ubuntu EC2 host (`98.94.124.224`), behind nginx, lifecycle-managed by systemd. Pushing to `main` triggers `.github/workflows/deploy.yml`, which deploys the backend first and then the frontend.

```
                            EC2 host (98.94.124.224)
                  ┌──────────────────────────────────────────┐
   public :80 ──► │  nginx                                   │
                  │   ├─ /api/  ──► 127.0.0.1:8000  (FastAPI) │
                  │   └─ /      ──► 127.0.0.1:3000  (Next.js) │
                  │                                           │
                  │  bitcoin-scanner.service          (systemd)│
                  │  bitcoin-scanner-frontend.service (systemd)│
                  └──────────────────────────────────────────┘
```

## Prerequisites

- An Ubuntu host reachable over SSH as `ubuntu`.
- The repo cloned at `/home/ubuntu/bitcoin-node-scanner/` with the existing backend `bitcoin-scanner.service` already installed (current state).
- `sudo` available without password for the `ubuntu` user (existing setup).

## One-time host bootstrap

Run on the EC2, after `git pull`ing this change onto the host:

```bash
ssh ubuntu@98.94.124.224
cd /home/ubuntu/bitcoin-node-scanner
git pull origin main
bash scripts/bootstrap-frontend-host.sh
```

The script is idempotent. It:

1. Installs Node 20 via NodeSource (skipped if already present).
2. Installs nginx (skipped if already present).
3. Creates `/home/ubuntu/bitcoin-scanner-frontend/` (the runtime root, **outside** the git checkout so `git pull` never collides with the deployed `server.js`).
4. Installs `/etc/systemd/system/bitcoin-scanner-frontend.service` from `scripts/systemd/`.
5. Installs `/etc/nginx/sites-available/bitcoin-scanner` from `scripts/nginx/`, symlinks it into `sites-enabled`, removes the default site, validates with `nginx -t`, and reloads nginx.
6. Installs `/etc/sudoers.d/bitcoin-scanner-frontend` (NOPASSWD for `systemctl restart|is-active|status bitcoin-scanner-frontend`), validated with `visudo -cf`.
7. Enables `bitcoin-scanner-frontend.service` (so it auto-starts on boot).

After bootstrap, the systemd unit is enabled but won't start cleanly until the first deploy populates `/home/ubuntu/bitcoin-scanner-frontend/` with `server.js` and friends.

### Set `FRONTEND_ORIGIN` on the backend

The backend's `GET /` 302-redirects to `FRONTEND_ORIGIN` and uses it as the CORS allow-list. In prod (single origin via nginx), set it to the public origin:

```bash
sudo systemctl edit bitcoin-scanner
# Add:
[Service]
Environment=FRONTEND_ORIGIN=http://98.94.124.224

sudo systemctl daemon-reload
sudo systemctl restart bitcoin-scanner
```

(Or set `FRONTEND_ORIGIN=…` in whatever `.env` the backend reads at launch — match your existing pattern.)

## GitHub repository secrets

Set these in **GitHub → Settings → Secrets and variables → Actions**:

| Secret          | Source                                                                                              |
| --------------- | --------------------------------------------------------------------------------------------------- |
| `EC2_SSH_KEY`   | The private SSH key for `ubuntu@98.94.124.224`. Already set (used by the existing backend deploy). |
| `WEB_API_KEY`   | **Same value** as the backend's `WEB_API_KEY` env var on the EC2. Inlined into the JS bundle as `NEXT_PUBLIC_WEB_API_KEY` at build time, so changing it requires a redeploy. |

> Any `NEXT_PUBLIC_*` value is shipped to browsers (visible in DevTools). This is the existing single-key model; per-user auth is out of scope.

## Deploy flow (every push to `main`)

1. **`backend` job** — SSHes to the EC2, `git pull`, `pip install`, `systemctl restart bitcoin-scanner`. (Unchanged.)
2. **`frontend` job** (`needs: backend`) — runs in the GitHub runner:
   - `pnpm install --frozen-lockfile` + `pnpm build` with `NEXT_PUBLIC_API_BASE_URL=/api/v1` and `NEXT_PUBLIC_WEB_API_KEY=${{ secrets.WEB_API_KEY }}`.
   - Assembles `frontend-dist/` in the standalone layout (`server.js` + `node_modules/` + `.next/static/` + `public/`).
   - `scp` to `/home/ubuntu/bitcoin-scanner-frontend-staging/` on the EC2.
   - SSH: `rsync -a --delete` staging → `/home/ubuntu/bitcoin-scanner-frontend/`, then `sudo systemctl restart bitcoin-scanner-frontend` and `systemctl is-active bitcoin-scanner-frontend`. The job fails if the service didn't come back up.

If the frontend job fails after the backend succeeded, the backend is on the new revision and the previous frontend keeps serving (until the next push). Acceptable for solo ops.

## Smoke tests

After the first successful deploy:

```bash
# Frontend reachable directly
curl -fsS http://127.0.0.1:3000/ | head -c 200      # on the host
curl -fsS http://98.94.124.224/   | head -c 200      # via nginx, from anywhere

# Backend reachable via nginx
curl -fsS http://98.94.124.224/api/v1/csrf-token

# Service health
sudo systemctl status bitcoin-scanner-frontend --no-pager
sudo systemctl status bitcoin-scanner --no-pager
sudo systemctl status nginx --no-pager
```

## Troubleshooting

| Symptom                                 | Where to look                                                      |
| --------------------------------------- | ------------------------------------------------------------------ |
| Service not starting                    | `journalctl -u bitcoin-scanner-frontend -n 200 --no-pager`         |
| 502 from nginx on `/`                   | service is down → `systemctl status bitcoin-scanner-frontend`      |
| 502 from nginx on `/api/`               | backend is down → `systemctl status bitcoin-scanner`               |
| nginx config rejected                   | `sudo nginx -t` for the exact line/error                           |
| `git pull` clobbered something          | shouldn't — runtime dir is `/home/ubuntu/bitcoin-scanner-frontend/`, outside the repo |
| `next start` OOM                        | Bump `MemoryMax=` in the systemd unit, or move to a bigger instance |
| CSRF cookie not round-tripping          | Inspect Set-Cookie attrs in the network tab; nginx default proxy settings preserve cookies on the same path. Cookies with `SameSite=None; Secure` won't work over HTTP — wait for TLS. |

## Rollback

```bash
ssh ubuntu@98.94.124.224

# Option A: roll back the backend by checking out a previous commit and restarting.
cd /home/ubuntu/bitcoin-node-scanner
git log --oneline -10
git checkout <prev-good-sha>
sudo systemctl restart bitcoin-scanner
# Re-deploy the frontend by re-running the GitHub Actions workflow at the same SHA,
# or `git revert` the bad commit on main and let the next push redeploy.

# Option B (frontend only, in a pinch): keep the old `bitcoin-scanner-frontend/`
# tree around as a backup before the next deploy:
sudo cp -a /home/ubuntu/bitcoin-scanner-frontend /home/ubuntu/bitcoin-scanner-frontend.bak
# After a bad deploy:
sudo rsync -a --delete /home/ubuntu/bitcoin-scanner-frontend.bak/ /home/ubuntu/bitcoin-scanner-frontend/
sudo systemctl restart bitcoin-scanner-frontend
```

For a "real" rollback discipline, `git revert <bad-sha>` on `main` is the cleanest option — the next push redeploys both halves automatically.

## TLS / HTTPS

Out of scope for this change. To add later:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d <your-domain>
```

certbot will edit the nginx site config in place. After that, set `FRONTEND_ORIGIN=https://<your-domain>` and redeploy.
