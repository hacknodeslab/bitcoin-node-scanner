# Deploying to frodo (HackNodes Proxmox)

Runbook for hosting the scanner on **frodo**, the HackNodes Proxmox VE host
on the lab LAN (`192.168.1.247`, Debian 13, web panel `:8006`), instead of
the AWS EC2 described in [deploy-frontend.md](deploy-frontend.md). The
application layout inside the container is the same as on EC2 — nginx on
`:80` fronting FastAPI `:8000` and Next.js `:3000`, both managed by systemd —
so everything in that document about services, smoke tests and
troubleshooting still applies. What changes is *how the host is provisioned*
(an unprivileged LXC) and *how code gets there*: GitHub Actions cannot reach
a container on a home LAN, so deploys run on the host with
`scripts/deploy.sh`.

> Not to be confused with **Gondor**, the Librería de Satoshi Proxmox in SFO.
> HackNodes projects live on frodo.

```
                 frodo (Proxmox VE, root@192.168.1.247)
   ┌──────────────────────────────────────────────────────────────────────┐
   │  CT 113 "pesquisa"  —  unprivileged LXC, Debian 13, 192.168.1.164 static │
   │  ┌────────────────────────────────────────────────────────────────┐  │
   │  │ nginx :80                                                      │  │
   │  │   ├─ /api/  ──► 127.0.0.1:8000  bitcoin-scanner.service        │  │
   │  │   └─ /      ──► 127.0.0.1:3000  bitcoin-scanner-frontend.service│  │
   │  │ cloudflared (optional) ──► https://audit.hacknodes.xyz         │  │
   │  └────────────────────────────────────────────────────────────────┘  │
   └──────────────────────────────────────────────────────────────────────┘
```

## Current state (2026-09-18)

| Item | Value |
| ---- | ----- |
| Container | `113` `pesquisa`, 2 vCPU, 4 GB RAM, 512 MB swap, 32 GB on `local-lvm`, `onboot: 1`, tag `bitcoin-node-scanner` |
| Features | `unprivileged: 1`, `nesting=1,keyctl=1` (same as CT 112) |
| Network | `eth0` on `vmbr0`, **static** `192.168.1.164/24`, gw `192.168.1.1`, DNS `192.168.1.1 1.1.1.1` (set via `pct set`, 2026-09-18) |
| Users | `root` (SSH keys from frodo's `authorized_keys`), `deploy` (same keys, `NOPASSWD: ALL`) |
| Repo | `/home/deploy/bitcoin-node-scanner` (git checkout) |
| Frontend artifact | `/home/deploy/bitcoin-scanner-frontend/` |
| Data | SQLite `bitcoin_scanner.db` = EC2 snapshot of 2026-09-18 (8,307 nodes, 100 CVEs; last scan data 2026-06-30). Pre-import copy in `~/bitcoin-node-scanner/backups/`. `QUERIES`/`QUERIES_OPTIMIZED` copied from the EC2 `.env` |
| URL | `https://audit.hacknodes.xyz` via Cloudflare Tunnel `frodo-pesquisa` (tunnel id `b9bf1acf-f3a1-49ac-8ba2-9cdf92e3d92b`, connector in the CT); `http://192.168.1.164/` on the LAN |

The container was created with DHCP and switched to a static address afterwards:

```bash
# on frodo — keep the hwaddr, or Proxmox generates a new MAC
MAC=$(pct config 113 | sed -n 's/^net0:.*hwaddr=\([^,]*\).*/\1/p')
pct set 113 --net0 "name=eth0,bridge=vmbr0,hwaddr=$MAC,ip=192.168.1.164/24,gw=192.168.1.1,type=veth" --nameserver "192.168.1.1 1.1.1.1"
pct reboot 113     # hot-apply fails with "Address already assigned" while the DHCP lease is live; a reboot regenerates /etc/network/interfaces
```

`192.168.1.164` may sit inside the router's DHCP pool; if the router does not
probe before leasing, also reserve it for MAC `BC:24:11:3C:F1:8F` on
`192.168.1.1` to rule out a future collision.

## 0. Sizing

| Resource | Value | Why |
| -------- | ----- | --- |
| vCPU     | 2     | uvicorn + node; scans are I/O-bound on Shodan |
| RAM      | 4 GB  | `next build` runs on the host and peaks ~1.5 GB; units cap at 2 G + 512 M |
| Disk     | 32 GB | repo + venv + node_modules ≈ 2 GB, SQLite DB is tens of MB, GeoIP DBs ≈ 100 MB |

frodo's `local` (dir) storage sits at ~94 % — put rootfs on `local-lvm`, and
don't download big images into `/var/lib/vz`. The Debian 13 LXC template is
already cached there (`local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst`).

## 1. Create the container (already done for CT 113)

On frodo (`ssh root@192.168.1.247`):

```bash
pct create 113 local:vztmpl/debian-13-standard_13.6-1_amd64.tar.zst \
  --hostname pesquisa --cores 2 --memory 4096 --swap 512 \
  --rootfs local-lvm:32 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp,type=veth \
  --unprivileged 1 --features nesting=1,keyctl=1 --onboot 1 --ostype debian \
  --ssh-public-keys /root/.ssh/authorized_keys --tags bitcoin-node-scanner \
  --start 1
pct exec 113 -- hostname -I

# deploy user with passwordless sudo + SSH, and a sane locale
pct exec 113 -- bash -c '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq sudo openssh-server curl rsync git
  adduser --disabled-password --gecos "" deploy
  echo "deploy ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/deploy && chmod 0440 /etc/sudoers.d/deploy && visudo -cf /etc/sudoers.d/deploy
  install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
  install -m 600 -o deploy -g deploy /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
  echo LANG=C.UTF-8 > /etc/default/locale
  systemctl enable --now ssh'
```

## 2. Bootstrap the host

Inside the container, as `deploy`:

```bash
git clone https://github.com/hacknodeslab/bitcoin-node-scanner.git ~/bitcoin-node-scanner
cd ~/bitcoin-node-scanner
bash scripts/bootstrap-host.sh
```

`bootstrap-host.sh` is idempotent and does, for the *current* user
(`deploy`, home `/home/deploy`):

1. `apt install` git, python3 + venv, rsync, curl, nginx.
2. Node 22 (NodeSource) + `pnpm@10` (global npm install).
3. Renders and installs `scripts/systemd/bitcoin-scanner.service` and
   `bitcoin-scanner-frontend.service` with the user and paths of this host,
   enables both.
4. Installs the nginx site from `scripts/nginx/bitcoin-scanner.conf`,
   disables the default site, `nginx -t`, reload.
5. Installs `/etc/sudoers.d/bitcoin-scanner{,-frontend}` (NOPASSWD for
   `systemctl restart|is-active|status` on both units, `daemon-reload`,
   `nginx -t`, `reload nginx`), validated with `visudo -cf`.
6. Creates `~/bitcoin-scanner-frontend/` (runtime root for the built
   dashboard, outside the git checkout).

Overrides: `DEPLOY_USER`, `REPO_DIR`, `FRONTEND_RUNTIME_DIR`, `NODE_MAJOR`
(see the script header). On the EC2 host (`ubuntu`, `/home/ubuntu`) the
rendered files are byte-identical to the repo copies, so the same script
keeps working there; `bootstrap-frontend-host.sh` is now a thin wrapper.

The systemd hardening (`ProtectSystem=strict`, `PrivateTmp`, `MemoryMax`)
works as-is inside the unprivileged LXC; both units come up clean.

## 3. Configure `.env`

```bash
cp env.example .env && chmod 600 .env && $EDITOR .env
```

What CT 113 runs with (values redacted):

```dotenv
WEB_API_KEY=<64 hex chars, openssl rand -hex 32>   # also inlined into the dashboard bundle at build time
WEB_HOST=127.0.0.1
WEB_PORT=8000
ENABLE_API_DOCS=0
FRONTEND_ORIGIN=http://192.168.1.164,http://pesquisa.lan  # add https://audit.hacknodes.xyz at cutover
DATABASE_URL=sqlite:///./bitcoin_scanner.db
OUTPUT_DIR=./output
LOG_LEVEL=INFO
GEOIP_DB_DIR=./geoip_dbs
MAX_RESULTS_NORMAL=500
MAX_RESULTS_CRITICAL=1000
MAX_QUERY_CREDITS_PER_SCAN=50
SHODAN_API_KEY=<key>
MAXMIND_LICENSE_KEY=<key>
NVD_API_KEY=<key>
```

`FRONTEND_ORIGIN` is both the CORS allow-list and the target of the
`GET /` redirect. With nginx serving UI and API on one origin, browsers never
preflight, so a wrong value here only breaks the redirect — but keep it
accurate (comma-separate several origins). The unit loads `.env` through
`EnvironmentFile=`, so values with spaces or `#` must be quoted.

## 4. Deploy

```bash
cd ~/bitcoin-node-scanner
bash scripts/deploy.sh            # or --no-pull to deploy the tree as-is
```

`deploy.sh` does, in order: `git pull --ff-only origin main` → venv +
`pip install -r requirements.txt` → `alembic upgrade head` → restart backend →
`pnpm install --frozen-lockfile` + `pnpm build` with
`NEXT_PUBLIC_API_BASE_URL=/api/v1` and `NEXT_PUBLIC_WEB_API_KEY=$WEB_API_KEY`
→ assemble the standalone artifact → `rsync --delete` into
`~/bitcoin-scanner-frontend/` → restart frontend → curl smoke tests against
`:8000`, `:3000` and `:80`. Flags: `--no-pull`, `--backend-only`,
`--frontend-only`, `BRANCH=…`. First run on CT 113 took ~2 min, most of it
`pnpm install`.

From the LAN:

```bash
curl -fsS http://192.168.1.164/api/v1/csrf-token
curl -fsS http://192.168.1.164/ | grep -o '<title>[^<]*</title>'    # bns / scanner
```

Routine deploy from any LAN machine with the key:
`ssh deploy@192.168.1.164 'cd ~/bitcoin-node-scanner && bash scripts/deploy.sh'`.

## 5. Bring over the live data (from EC2)

Done on 2026-09-18 (8,307 nodes). Repeat only if scans are run on the EC2
before the DNS switch. The EC2 keeps serving while you do this; SQLite's
online backup is consistent under load. The SSH key is `~/hacknodes.pem`
(`$PEM_HNL`).

```bash
# On a machine with SSH to both
ssh -i ~/hacknodes.pem ubuntu@98.94.124.224 'cd ~/bitcoin-node-scanner && python3 -c "import sqlite3; s=sqlite3.connect(\"bitcoin_scanner.db\"); d=sqlite3.connect(\"/tmp/bns.db\"); s.backup(d)"'   # sqlite3 CLI is not installed there
scp -i ~/hacknodes.pem ubuntu@98.94.124.224:/tmp/bns.db ./bns-$(date +%F).db

ssh deploy@192.168.1.164 'sudo systemctl stop bitcoin-scanner && cp ~/bitcoin-node-scanner/bitcoin_scanner.db ~/bitcoin-node-scanner/bitcoin_scanner.db.pre-cutover'
scp ./bns-*.db deploy@192.168.1.164:~/bitcoin-node-scanner/bitcoin_scanner.db
ssh deploy@192.168.1.164 'cd ~/bitcoin-node-scanner && venv/bin/alembic upgrade head && sudo systemctl start bitcoin-scanner && sudo systemctl is-active bitcoin-scanner'
```

If you want existing API clients (or the dashboard's inlined key) to keep
working unchanged, copy the EC2's `WEB_API_KEY` into the container's `.env`
and run `bash scripts/deploy.sh --no-pull` (the frontend must be rebuilt for
a key change).

## 6. Public exposure — Cloudflare Tunnel (decided 2026-09-18)

Today `audit.hacknodes.xyz` is a CNAME to a CloudFront distribution whose
origin is the EC2 (`nginx` on `:80`, TLS at the edge). DNS for `hacknodes.xyz`
is at Namecheap. frodo sits behind the home router and **no inbound ports
will be opened**, so the container dials out to Cloudflare and the public
hostname is served through that tunnel. TLS terminates at Cloudflare.

### 6a. Cloudflare account side (one-time, in the dashboard)

1. **Add the zone** `hacknodes.xyz` to Cloudflare (Free plan). Cloudflare
   imports the existing records; check them against Namecheap before
   switching — in particular keep `pesquisa.hacknodes.xyz` (another product,
   CloudFront) and any MX/TXT records, and set records that point at other
   CDNs/hosts to **DNS only** (grey cloud) so nothing gets double-proxied.
   The Free plan needs the whole zone: subdomain-only or CNAME setups are
   paid tiers.

   Full record list at Namecheap on 2026-09-18 (Cloudflare's scan only found
   the MX/SPF; everything else must be added by hand, all **DNS only**):

   | Name | Type | Value | On Cloudflare |
   | ---- | ---- | ----- | ------------- |
   | `pesquisa` | CNAME | `d1nqm31up9h70w.cloudfront.net` | keep (another product) |
   | `_cd6e2a54e2ec06ff2256cc97090cad23.pesquisa` | CNAME | `_e1c13f07aab3b33a400315f518976cb3.jkddzztszm.acm-validations.aws` | keep — ACM cert renewal for pesquisa's CloudFront |
   | `origin` | A | `100.50.100.201` | keep (the pesquisa machine) |
   | `observer` | A | `3.219.165.64` | keep (AWS) |
   | `nostr` | A | `129.212.140.106` | keep |
   | `audit` | CNAME | `d1vsfl24f8b7ew.cloudfront.net` | add temporarily so audit keeps resolving after the NS switch; delete right before creating the tunnel's public hostname |
   | `_d5b066b5b48143afe538ec5c967be0f0.audit` | CNAME | `_ec35f466ac0fda8a8a52f84e6b47af89.jkddzztszm.acm-validations.aws` | temporary too; drop with the CloudFront distribution |
   | `@` | MX ×5 + TXT SPF | Namecheap email forwarding | imported; see below |
   | `@`, `www` | — | none | nothing to import |

   **Email gotcha:** the MX/SPF records are Namecheap's free *email
   forwarding*, which only works while the domain uses Namecheap DNS.
   Moving the nameservers breaks forwarding for `*@hacknodes.xyz`. If any
   address there matters, enable **Cloudflare Email Routing** (free) after the
   switch: Email → Email Routing → add the destination mailbox and the
   forwarding addresses; Cloudflare then replaces the MX/SPF records itself.
2. **Change the nameservers at Namecheap** to the two Cloudflare gives you.
   Propagation is usually minutes to a few hours; the old records keep
   answering meanwhile.
3. **Zero Trust → Networks → Tunnels → Create a tunnel** (Cloudflared
   connector), name it `audit-frodo`. Copy the **token** from the install
   command it shows (`cloudflared service install <TOKEN>`).
4. In the tunnel's **Public Hostname** tab add
   `audit.hacknodes.xyz` → service `HTTP` `localhost:80`. Cloudflare creates
   the proxied CNAME record for you (delete the old CloudFront CNAME for
   `audit` first if the import brought it over).
5. Optional but cheap: **SSL/TLS → Edge Certificates → Always Use HTTPS** on,
   and **SSL/TLS mode = Flexible** is NOT needed — tunnels ignore it.

### 6b. Container side

Done on CT 113 (2026-09-18): `cloudflared` 2026.9.1 from `pkg.cloudflare.com`,
connector installed as `cloudflared.service` (token in `/etc/cloudflared/token`,
root-only), four connections to the Madrid PoPs, `FRONTEND_ORIGIN` includes
`https://audit.hacknodes.xyz`. Gotcha from the first attempt: running the
`service install` command on the Proxmox host instead of inside the CT
registers a connector on frodo, where nothing listens on :80 — the token was
moved into the CT and the frodo service uninstalled. For reference:

```bash
ssh deploy@192.168.1.164
sudo cloudflared service install <TOKEN>      # writes /etc/systemd/system/cloudflared.service, enables + starts it
sudo systemctl status cloudflared --no-pager
sudo journalctl -u cloudflared -n 20 --no-pager   # expect "Registered tunnel connection" x4
```

Then from anywhere:

```bash
curl -fsSI https://audit.hacknodes.xyz/ | grep -i -E "^(HTTP|server|cf-ray)"
curl -fsS https://audit.hacknodes.xyz/api/v1/csrf-token
```

Cookies: the backend sets the CSRF cookie with `Secure` only when it sees
`https`, and behind `cloudflared → nginx → uvicorn` it sees `http`. The
cookie is `SameSite=lax` without `Secure`, which browsers accept on an https
page — the same situation as on EC2 behind CloudFront. If that ever needs
tightening, make nginx send `X-Forwarded-Proto https` for tunnel traffic.

Known gotcha (Aug 2026, on another Cloudflare-fronted host): `cloudflared`
2026.8.0 stripped trailing slashes and broke framework routes; fixed in
2026.8.1. The apt repo pins nothing, so check the version after upgrades.

Optional hardening later: put **Cloudflare Access** in front of
`audit.hacknodes.xyz` (Zero Trust → Access → Applications) to require a
login before the dashboard — the API key inlined in the JS bundle is the
only thing protecting the API today.

## 7. Cutover checklist

Status 2026-09-18: zone `hacknodes.xyz` on Cloudflare (`coby`/`evelyn.ns.cloudflare.com`), delegation live at the `.xyz` registry and public resolvers, `audit` routed to the tunnel, HTTP through the edge reaches the CT's nginx. Steps 1-6 done. Universal SSL certificate (Let's Encrypt, CN=hacknodes.xyz) issued ~15 min after activation; `https://audit.hacknodes.xyz` serves `/`, `/nostr`, `/vulnerabilities` and the API from the CT (8,307 nodes, commit f37c39d). **Always Use HTTPS** is on (http → 301 https).

What is on the EC2 (inventory 2026-09-18): Ubuntu 24.04, ~1 GB RAM, the two
units + nginx, no crons, no docker, no certbot (TLS at CloudFront), no GeoIP
files, empty `output/`. The unit drop-in sets
`FRONTEND_ORIGIN=https://audit.hacknodes.xyz`, so **audit** is the canonical
hostname. (`pesquisa.hacknodes.xyz` is a different product on a different
AWS machine — out of scope here.) Nothing beyond the database and the `QUERIES*` env
values was worth bringing over.

1. ✅ Container healthy on the LAN with a static IP; `deploy.sh` green.
2. ✅ EC2 data imported (§5; repeat if the EC2 scanned again).
3. ✅ Tunnel up; `audit.hacknodes.xyz/api/v1/csrf-token` answers from the
   container (`cf-ray` header present, `server: cloudflare`).
4. ✅ `FRONTEND_ORIGIN` includes the public origin; `GET /` on the backend
   redirects there.
5. Freeze the EC2 deploy: in `.github/workflows/deploy.yml` change `on:` to
   `workflow_dispatch` (or delete the workflow) so a push to `main` no longer
   touches the EC2.
6. ✅ DNS switched (zone moved to Cloudflare, tunnel record for `audit`).
   Delete the CloudFront distribution once traffic has moved.
7. Keep the EC2 stopped (not terminated) for a week, then dismantle in the
   AWS console: instance + EBS volume, Elastic IP `98.94.124.224`, security
   group, key pair, the CloudFront distribution `d1vsfl24f8b7ew` (audit) and
   its Namecheap CNAME, and the GitHub secrets `EC2_SSH_KEY` /
   `WEB_API_KEY` once `deploy.yml` is gone.

## 8. Operations

| Task | Command |
| ---- | ------- |
| Deploy latest `main` | `ssh deploy@192.168.1.164 'cd ~/bitcoin-node-scanner && bash scripts/deploy.sh'` |
| Backend logs | `journalctl -u bitcoin-scanner -f` |
| Frontend logs | `journalctl -u bitcoin-scanner-frontend -f` |
| Run a scan | `set -a; source .env; set +a; venv/bin/python -m src.scanner --quick` then `venv/bin/python -m src.db.cli db-import output/raw_data/nodes_<ts>.json` |
| DB backup | `sqlite3 bitcoin_scanner.db ".backup backups/bns-$(date +%F).db"` — cron it and copy the folder off the container |
| Rollback code | `git checkout <sha> && bash scripts/deploy.sh --no-pull` |
| Rollback DB | stop backend, copy backup over `bitcoin_scanner.db`, start |
| Snapshot before risky changes | on frodo: `pct snapshot 113 pre-<what>` (and `pct rollback 113 pre-<what>`) |
| Console without SSH | on frodo: `pct enter 113` |

Both units are `enabled` and the container has `onboot: 1`, so a reboot of
the container or of frodo brings the app back without intervention.
