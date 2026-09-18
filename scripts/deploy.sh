#!/usr/bin/env bash
# On-host deploy for bitcoin-node-scanner: pull, install, migrate, build the
# Next.js dashboard, activate it, restart both systemd units, smoke-test.
#
# This is the deploy path for hosts GitHub Actions cannot reach (the LXC on
# frodo, the HackNodes Proxmox on the lab LAN). It mirrors what
# .github/workflows/deploy.yml does for the EC2 host, but builds the frontend
# on the host itself instead of in a CI runner.
#
# Usage (as the deploy user, after scripts/bootstrap-host.sh):
#   bash scripts/deploy.sh                 # full deploy of origin/main
#   bash scripts/deploy.sh --no-pull       # deploy the working tree as-is
#   bash scripts/deploy.sh --backend-only
#   bash scripts/deploy.sh --frontend-only
#   BRANCH=feature/x bash scripts/deploy.sh
#
# Env overrides: REPO_DIR, FRONTEND_RUNTIME_DIR, BRANCH, NEXT_PUBLIC_API_BASE_URL.

set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FRONTEND_RUNTIME_DIR="${FRONTEND_RUNTIME_DIR:-$(dirname "$REPO_DIR")/bitcoin-scanner-frontend}"
BRANCH="${BRANCH:-main}"
DO_PULL=1
DO_BACKEND=1
DO_FRONTEND=1

for arg in "$@"; do
    case "$arg" in
        --no-pull) DO_PULL=0 ;;
        --backend-only) DO_FRONTEND=0 ;;
        --frontend-only) DO_BACKEND=0 ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Unknown argument: $arg" >&2; exit 2 ;;
    esac
done

step() { printf '\n→ %s\n' "$*"; }
die()  { echo "✗ $*" >&2; exit 1; }

cd "$REPO_DIR"
[[ -f .env ]] || die ".env missing in $REPO_DIR — copy env.example and set WEB_API_KEY at least"

# Export .env so alembic (DATABASE_URL) and the frontend build (WEB_API_KEY)
# see the same values the systemd unit loads via EnvironmentFile=.
set -a
# shellcheck source=/dev/null
source .env
set +a
[[ -n "${WEB_API_KEY:-}" ]] || die "WEB_API_KEY is empty in .env"

if (( DO_PULL )); then
    step "git: updating $BRANCH"
    git fetch --quiet origin "$BRANCH"
    git checkout --quiet "$BRANCH"
    git pull --ff-only --quiet origin "$BRANCH"
fi
echo "Deploying $(git rev-parse --short HEAD) ($(git log -1 --format=%s | cut -c1-70))"

if (( DO_BACKEND )); then
    step "backend: python deps"
    if [[ ! -x venv/bin/python ]]; then
        python3 -m venv venv
    fi
    venv/bin/pip install --quiet --upgrade pip
    venv/bin/pip install --quiet -r requirements.txt

    step "backend: alembic upgrade head"
    venv/bin/alembic upgrade head

    step "backend: restart bitcoin-scanner"
    sudo systemctl restart bitcoin-scanner
    sleep 2
    sudo systemctl is-active bitcoin-scanner >/dev/null \
        || die "bitcoin-scanner did not come up — journalctl -u bitcoin-scanner -n 100"
fi

if (( DO_FRONTEND )); then
    step "frontend: pnpm install"
    command -v pnpm >/dev/null || die "pnpm not found — run scripts/bootstrap-host.sh"
    (
        cd frontend
        pnpm install --frozen-lockfile --silent

        step "frontend: next build (same-origin, NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL:-/api/v1})"
        NEXT_PUBLIC_API_BASE_URL="${NEXT_PUBLIC_API_BASE_URL:-/api/v1}" \
        NEXT_PUBLIC_WEB_API_KEY="$WEB_API_KEY" \
        NEXT_TELEMETRY_DISABLED=1 \
            pnpm build

        step "frontend: assembling standalone artifact"
        staging="$(mktemp -d)"
        cp -a .next/standalone/. "$staging/"
        mkdir -p "$staging/.next"
        cp -a .next/static "$staging/.next/static"
        if [[ -d public ]]; then cp -a public "$staging/public"; fi

        mkdir -p "$FRONTEND_RUNTIME_DIR"
        rsync -a --delete "$staging/" "$FRONTEND_RUNTIME_DIR/"
        rm -rf "$staging"
    )

    step "frontend: restart bitcoin-scanner-frontend"
    sudo systemctl restart bitcoin-scanner-frontend
    sleep 2
    sudo systemctl is-active bitcoin-scanner-frontend >/dev/null \
        || die "bitcoin-scanner-frontend did not come up — journalctl -u bitcoin-scanner-frontend -n 100"
fi

step "smoke tests"
curl -fsS -o /dev/null "http://127.0.0.1:${WEB_PORT:-8000}/api/v1/csrf-token" && echo "✓ backend  :${WEB_PORT:-8000}"
curl -fsS -o /dev/null http://127.0.0.1:3000/ && echo "✓ frontend :3000"
curl -fsS -o /dev/null http://127.0.0.1/api/v1/csrf-token && curl -fsS -o /dev/null http://127.0.0.1/ && echo "✓ nginx    :80"

echo
echo "Deployed $(git rev-parse --short HEAD)."
