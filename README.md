# HackNodes Recon Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=bugs)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=hacknodeslab_bitcoin-node-scanner&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=hacknodeslab_bitcoin-node-scanner)
[![CI Pipeline](https://github.com/hacknodeslab/bitcoin-node-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/hacknodeslab/bitcoin-node-scanner/actions/workflows/ci.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hacknodeslab/bitcoin-node-scanner)

A security-reconnaissance platform for decentralized networks. It pairs domain
scanning engines with a shared database layer, a FastAPI REST API, and a Next.js
operator dashboard, so each new recon target reuses the same persistence,
API, and UI.

## Recon domains

| Domain | What it measures | Data source | Docs |
|--------|------------------|-------------|------|
| **Bitcoin node scanner** | Vulnerable / misconfigured Bitcoin nodes exposed on the clearnet (bad versions, exposed RPC, risk level, geo) | Shodan API — search queries or a provided IP list (`--ips`, e.g. a peer-observer export) | [docs/bitcoin-scanner.md](docs/bitcoin-scanner.md) |
| **Nostr relay CDN-recon** | Centralization — what % of Nostr relays sit behind a CDN (Cloudflare / CloudFront / Fastly) vs. exposing their origin | DNS + CDN CIDR ranges (no Shodan credits) | [docs/nostr-cdn-recon.md](docs/nostr-cdn-recon.md) |

Both domains feed the same dashboard and REST API; the Bitcoin engine adds NVD/CVE
correlation and MaxMind GeoIP enrichment.

---

## Architecture

```
   Bitcoin: Shodan ─► src/scanner.py ─┐
                                       ├─► SQLAlchemy ORM (src/db/) ─► repositories ─► FastAPI (/api/v1) ─► Next.js dashboard
   Nostr:   DNS    ─► src/nostr/ ──────┘
```

Two toolchains run as two processes:

- **FastAPI backend** (`src/`, Python/pip) — serves the REST API at `/api/v1/*`. Does
  not serve HTML. `GET /` 302-redirects to `FRONTEND_ORIGIN`.
- **Next.js dashboard** (`frontend/`, Node/pnpm) — operator UI; calls the backend.

In **dev** the two run on different ports (`:8000` + `:3000`, cross-origin via CORS).
In **prod** nginx serves both from a single origin on port 80 (`/api/` → backend,
`/` → Next.js). See [Frontend Deployment](docs/deploy-frontend.md) for the deploy
pipeline, host bootstrap, and rollback playbook.

---

## Quick start

```bash
git clone https://github.com/hacknodeslab/bitcoin-node-scanner.git
cd bitcoin-node-scanner

# Backend dependencies
pip install -r requirements.txt
```

### Run a recon domain

- **Bitcoin** → [docs/bitcoin-scanner.md](docs/bitcoin-scanner.md)
- **Nostr** → [docs/nostr-cdn-recon.md](docs/nostr-cdn-recon.md)

### Run the dashboard

Two terminals.

**Backend** (Python):
```bash
export DATABASE_URL="sqlite:///./bitcoin_scanner.db"   # or PostgreSQL URL
export WEB_API_KEY="your-strong-random-secret"
export FRONTEND_ORIGIN="http://localhost:3000"          # CORS allow-list

python -m src.web.main        # or, after installing the package: bitcoin-scanner-web
```

**Frontend** (Node):
```bash
cd frontend
pnpm install
pnpm dev
```

`frontend/.env.local`:
```
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WEB_API_KEY=<same value as backend WEB_API_KEY>
```

Open `http://localhost:3000/` for the dashboard.

---

## API

`/docs` (Swagger UI), `/redoc`, and `/openapi.json` are gated behind
`ENABLE_API_DOCS` (set to `1`/`true`/`yes` in local dev; off by default). All
`/api/v1/*` endpoints (except `/csrf-token` and `/l402/example`) require the
`X-API-Key` header; mutating verbs additionally require `X-CSRF-Token`.

Per-domain endpoints are documented in their respective docs; the full reference is
[docs/API.md](docs/API.md).

### Core environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WEB_API_KEY` | Yes | — | Secret key sent in `X-API-Key` header |
| `DATABASE_URL` | Yes | — | SQLAlchemy database URL (SQLite or PostgreSQL) |
| `WEB_HOST` | No | `127.0.0.1` | Host the server binds to |
| `WEB_PORT` | No | `8000` | Port the server listens on |
| `FRONTEND_ORIGIN` | No | `http://localhost:3000` | CORS allow-list; comma-separated for multiple |
| `ENABLE_API_DOCS` | No | off | Expose `/docs`, `/redoc`, `/openapi.json` |
| `STALE_THRESHOLD_DAYS` | No | `7` | Age in days before a node is counted as STALE |

Domain-specific variables (`SHODAN_API_KEY`, `MAXMIND_LICENSE_KEY`,
`NOSTR_CDN_CACHE_DIR`, …) are listed in the per-domain docs.

> **Security note**: do not expose the web server on a public interface without a
> TLS-terminating reverse proxy (e.g. nginx). The API key provides authentication
> but not encryption.

---

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE.md)
- [API Reference](docs/API.md)
- [Methodology](docs/METHODOLOGY.md)
- [Database Support](docs/DATABASE.md)
- [Frontend Deployment](docs/deploy-frontend.md)
- **Bitcoin node scanner** → [docs/bitcoin-scanner.md](docs/bitcoin-scanner.md)
- **Nostr relay CDN-recon** → [docs/nostr-cdn-recon.md](docs/nostr-cdn-recon.md)

---

## Testing

```bash
# Backend (Python)
python -m pytest tests/ -v
python -m pytest tests/ --cov=src --cov-report=term-missing

# Frontend (Node)
cd frontend && pnpm typecheck && pnpm test
```

---

## Prerequisites

- Python 3.8+
- Node + pnpm (for the dashboard)
- A Shodan API key for Bitcoin scanning ([shodan.io](https://account.shodan.io/)) —
  not needed for Nostr recon

---

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Ethical Use

- **Responsible Disclosure**: report 0-day vulnerabilities responsibly to the relevant security team
- **No Active Exploitation**: this tool is for passive reconnaissance only
- **Respect Privacy**: do not publish IP addresses of vulnerable nodes
- **GDPR Compliance**: handle European data in accordance with regulations

## Credits

Developed by @ifuensan with the HackNodes Lab support.

Special thanks to Shodan for providing the API, the Bitcoin Core development team,
and OSTIF & Quarkslab for their comprehensive security audit.

## Contact

- Website: [hacknodes.com](https://hacknodes.com)
- Email: support@hacknodes.com

## Disclaimer

This tool is for **security research and educational purposes only**. All data
collected is from publicly available sources (Shodan, DNS & MaxMind GeoIP). Do not
perform active penetration testing without explicit authorization.

---

**Made with ❤️ for the decentralized-network security community**
