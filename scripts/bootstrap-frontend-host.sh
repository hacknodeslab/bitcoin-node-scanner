#!/usr/bin/env bash
# Idempotent bootstrap for the bitcoin-node-scanner frontend host.
#
# Installs Node 20 (NodeSource), nginx, drops in the systemd unit + nginx
# site config + sudoers rule, and prepares the runtime directory. Safe to
# re-run on a fresh or already-bootstrapped Ubuntu host.
#
# Usage (run on the EC2 host, as ubuntu with sudo access):
#   ssh ubuntu@<host>
#   cd /home/ubuntu/bitcoin-node-scanner
#   bash scripts/bootstrap-frontend-host.sh
#
# After this, push to main and the GitHub Actions deploy workflow will copy
# the built artifact into /home/ubuntu/bitcoin-node-scanner/frontend/ and
# `systemctl restart bitcoin-scanner-frontend`.

set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/ubuntu/bitcoin-node-scanner}"
# Runtime dir for the deployed Next.js artifact. Lives OUTSIDE the git
# checkout so the backend's `git pull` never collides with the deployed
# server.js / node_modules. Keep this in sync with the systemd unit's
# WorkingDirectory and the deploy.yml SSH/scp targets.
FRONTEND_RUNTIME_DIR="${FRONTEND_RUNTIME_DIR:-/home/ubuntu/bitcoin-scanner-frontend}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require_sudo() {
    if [[ $EUID -eq 0 ]]; then
        echo "Run as the ubuntu user (uses sudo internally), not as root." >&2
        exit 1
    fi
    sudo -n true 2>/dev/null || sudo -v
}

install_node() {
    if command -v node >/dev/null && [[ "$(node --version)" == v20.* ]]; then
        echo "✓ Node 20 already installed ($(node --version))"
        return
    fi
    echo "→ Installing Node 20 from NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
}

install_nginx() {
    if command -v nginx >/dev/null; then
        echo "✓ nginx already installed"
        return
    fi
    echo "→ Installing nginx..."
    sudo apt-get update
    sudo apt-get install -y nginx
}

install_systemd_unit() {
    local src="$SCRIPT_DIR/systemd/bitcoin-scanner-frontend.service"
    local dst="/etc/systemd/system/bitcoin-scanner-frontend.service"
    if [[ ! -f "$src" ]]; then
        echo "Missing $src" >&2
        exit 1
    fi
    if sudo cmp -s "$src" "$dst" 2>/dev/null; then
        echo "✓ $dst already up-to-date"
    else
        echo "→ Installing $dst"
        sudo install -m 0644 "$src" "$dst"
        sudo systemctl daemon-reload
    fi
    sudo systemctl enable bitcoin-scanner-frontend.service >/dev/null
}

install_nginx_site() {
    local src="$SCRIPT_DIR/nginx/bitcoin-scanner.conf"
    local dst="/etc/nginx/sites-available/bitcoin-scanner"
    if [[ ! -f "$src" ]]; then
        echo "Missing $src" >&2
        exit 1
    fi
    if sudo cmp -s "$src" "$dst" 2>/dev/null; then
        echo "✓ $dst already up-to-date"
    else
        echo "→ Installing $dst"
        sudo install -m 0644 "$src" "$dst"
    fi
    if [[ ! -L /etc/nginx/sites-enabled/bitcoin-scanner ]]; then
        sudo ln -sf "$dst" /etc/nginx/sites-enabled/bitcoin-scanner
    fi
    if [[ -L /etc/nginx/sites-enabled/default ]]; then
        echo "→ Removing default nginx site"
        sudo rm /etc/nginx/sites-enabled/default
    fi
    sudo nginx -t
    sudo systemctl reload nginx
}

install_sudoers() {
    local src="$SCRIPT_DIR/sudoers.d/bitcoin-scanner-frontend"
    local dst="/etc/sudoers.d/bitcoin-scanner-frontend"
    if [[ ! -f "$src" ]]; then
        echo "Missing $src" >&2
        exit 1
    fi
    if sudo cmp -s "$src" "$dst" 2>/dev/null; then
        echo "✓ $dst already up-to-date"
    else
        echo "→ Installing $dst"
        sudo install -m 0440 "$src" "$dst"
        sudo visudo -cf "$dst"
    fi
}

prepare_runtime_dir() {
    if [[ ! -d "$FRONTEND_RUNTIME_DIR" ]]; then
        echo "→ Creating $FRONTEND_RUNTIME_DIR"
        mkdir -p "$FRONTEND_RUNTIME_DIR"
    fi
    sudo chown -R ubuntu:ubuntu "$FRONTEND_RUNTIME_DIR"
}

main() {
    require_sudo
    install_node
    install_nginx
    prepare_runtime_dir
    install_systemd_unit
    install_nginx_site
    install_sudoers
    echo
    echo "Bootstrap complete."
    echo "Next: push to main to trigger the GitHub Actions deploy, or trigger it manually."
    echo "Verify after first deploy:"
    echo "  systemctl status bitcoin-scanner-frontend --no-pager"
    echo "  curl -fsS http://127.0.0.1:3000/ | head -c 200"
    echo "  curl -fsS http://127.0.0.1/  | head -c 200      # via nginx"
}

main "$@"
