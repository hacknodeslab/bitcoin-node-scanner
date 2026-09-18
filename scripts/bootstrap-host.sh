#!/usr/bin/env bash
# Idempotent bootstrap for a bitcoin-node-scanner host (backend + frontend).
#
# Works on Ubuntu (EC2) and Debian (LXC on frodo, the HackNodes Proxmox). Installs system
# packages, Node LTS + pnpm, nginx, both systemd units, the nginx site, the
# sudoers rules, and prepares the frontend runtime directory. Safe to re-run.
#
# It does NOT create the venv, .env or build the frontend — that is
# scripts/deploy.sh, which you run right after this one.
#
# Usage (as the deploy user, with sudo):
#   git clone https://github.com/hacknodeslab/bitcoin-node-scanner.git ~/bitcoin-node-scanner
#   cd ~/bitcoin-node-scanner
#   bash scripts/bootstrap-host.sh
#
# Overrides (env vars):
#   DEPLOY_USER           user the services run as (default: current user)
#   REPO_DIR              git checkout            (default: $HOME/bitcoin-node-scanner)
#   FRONTEND_RUNTIME_DIR  built Next.js artifact  (default: $HOME/bitcoin-scanner-frontend)
#   NODE_MAJOR            Node major to install   (default: 22)
#
# The shipped unit/sudoers files are written for `ubuntu` under /home/ubuntu;
# this script rewrites user, group and paths before installing, so on the EC2
# host (ubuntu) the rendered files are byte-identical to the repo copies.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_USER="${DEPLOY_USER:-$(id -un)}"
DEPLOY_GROUP="$(id -gn "$DEPLOY_USER")"
DEPLOY_HOME="$(getent passwd "$DEPLOY_USER" | cut -d: -f6)"
REPO_DIR="${REPO_DIR:-$DEPLOY_HOME/bitcoin-node-scanner}"
FRONTEND_RUNTIME_DIR="${FRONTEND_RUNTIME_DIR:-$DEPLOY_HOME/bitcoin-scanner-frontend}"
NODE_MAJOR="${NODE_MAJOR:-22}"

require_sudo() {
    if [[ $EUID -eq 0 ]]; then
        echo "Run as the deploy user (uses sudo internally), not as root." >&2
        exit 1
    fi
    sudo -n true 2>/dev/null || sudo -v
}

install_packages() {
    echo "→ Installing base packages (git, python3, venv, rsync, curl, nginx)..."
    sudo apt-get update -qq
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        git curl rsync ca-certificates gnupg \
        python3 python3-venv python3-pip \
        nginx
}

install_node() {
    if command -v node >/dev/null; then
        local major
        major="$(node --version | sed -E 's/^v([0-9]+).*/\1/')"
        if (( major >= 20 )); then
            echo "✓ Node already installed ($(node --version))"
        else
            echo "→ Node $(node --version) is too old for Next.js 16; installing Node ${NODE_MAJOR}..."
            curl --proto "=https" --tlsv1.2 -sSf -L "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
            sudo apt-get install -y -qq nodejs
        fi
    else
        echo "→ Installing Node ${NODE_MAJOR} from NodeSource..."
        curl --proto "=https" --tlsv1.2 -sSf -L "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | sudo -E bash -
        sudo apt-get install -y -qq nodejs
    fi
    if command -v pnpm >/dev/null; then
        echo "✓ pnpm already installed ($(pnpm --version))"
    else
        echo "→ Installing pnpm 10 (frontend/package.json pins pnpm@10.x)..."
        sudo npm install -g pnpm@10 >/dev/null
    fi
}

# render SRC DST MODE — rewrite the ubuntu/EC2 defaults baked into the shipped
# file for this host, then install it only if it differs from what is there.
# Returns 0 if the file changed, 1 if it was already up-to-date.
render_install() {
    local src="$1" dst="$2" mode="$3" tmp
    if [[ ! -f "$src" ]]; then
        echo "Missing $src" >&2
        exit 1
    fi
    tmp="$(mktemp)"
    sed \
        -e "s#/home/ubuntu/bitcoin-node-scanner#${REPO_DIR}#g" \
        -e "s#/home/ubuntu/bitcoin-scanner-frontend#${FRONTEND_RUNTIME_DIR}#g" \
        -e "s#^User=ubuntu\$#User=${DEPLOY_USER}#" \
        -e "s#^Group=ubuntu\$#Group=${DEPLOY_GROUP}#" \
        -e "s#^ubuntu ALL=#${DEPLOY_USER} ALL=#" \
        "$src" > "$tmp"
    if sudo cmp -s "$tmp" "$dst" 2>/dev/null; then
        echo "✓ $dst already up-to-date"
        rm -f "$tmp"
        return 1
    fi
    echo "→ Installing $dst"
    sudo install -m "$mode" "$tmp" "$dst"
    rm -f "$tmp"
    return 0
}

install_systemd_units() {
    local changed=0
    render_install "$SCRIPT_DIR/systemd/bitcoin-scanner.service" \
        /etc/systemd/system/bitcoin-scanner.service 0644 && changed=1
    render_install "$SCRIPT_DIR/systemd/bitcoin-scanner-frontend.service" \
        /etc/systemd/system/bitcoin-scanner-frontend.service 0644 && changed=1
    if (( changed )); then
        sudo systemctl daemon-reload
    fi
    sudo systemctl enable bitcoin-scanner.service bitcoin-scanner-frontend.service >/dev/null
}

install_nginx_site() {
    local dst="/etc/nginx/sites-available/bitcoin-scanner"
    render_install "$SCRIPT_DIR/nginx/bitcoin-scanner.conf" "$dst" 0644 || true
    if [[ ! -L /etc/nginx/sites-enabled/bitcoin-scanner ]]; then
        sudo ln -sf "$dst" /etc/nginx/sites-enabled/bitcoin-scanner
    fi
    if [[ -L /etc/nginx/sites-enabled/default ]]; then
        echo "→ Removing default nginx site"
        sudo rm /etc/nginx/sites-enabled/default
    fi
    sudo nginx -t
    sudo systemctl enable nginx >/dev/null
    sudo systemctl reload nginx
}

install_sudoers() {
    local f dst
    for f in bitcoin-scanner bitcoin-scanner-frontend; do
        dst="/etc/sudoers.d/$f"
        if render_install "$SCRIPT_DIR/sudoers.d/$f" "$dst" 0440; then
            sudo visudo -cf "$dst"
        fi
    done
}

prepare_dirs() {
    if [[ ! -d "$FRONTEND_RUNTIME_DIR" ]]; then
        echo "→ Creating $FRONTEND_RUNTIME_DIR"
        mkdir -p "$FRONTEND_RUNTIME_DIR"
    fi
    sudo chown -R "$DEPLOY_USER:$DEPLOY_GROUP" "$FRONTEND_RUNTIME_DIR"
    if [[ ! -d "$REPO_DIR/.git" ]]; then
        echo "⚠ $REPO_DIR is not a git checkout — clone the repo there before running scripts/deploy.sh" >&2
    fi
}

main() {
    require_sudo
    echo "Deploy user: $DEPLOY_USER ($DEPLOY_HOME)"
    echo "Repo dir:    $REPO_DIR"
    echo "Frontend:    $FRONTEND_RUNTIME_DIR"
    echo
    install_packages
    install_node
    prepare_dirs
    install_systemd_units
    install_nginx_site
    install_sudoers
    echo
    echo "Bootstrap complete."
    echo "Next:"
    echo "  cp env.example .env && \$EDITOR .env      # WEB_API_KEY, SHODAN_API_KEY, DATABASE_URL, FRONTEND_ORIGIN"
    echo "  bash scripts/deploy.sh                   # venv + migrations + frontend build + restart"
}

main "$@"
