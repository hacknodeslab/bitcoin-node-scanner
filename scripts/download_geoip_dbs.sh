#!/usr/bin/env bash
# Download MaxMind GeoLite2 databases (.mmdb files).
#
# Prerequisites:
#   - Free MaxMind account: https://www.maxmind.com/en/geolite2/signup
#   - MAXMIND_LICENSE_KEY set in .env
#
# Usage:
#   ./scripts/download_geoip_dbs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load .env from the project root
ENV_FILE="$PROJECT_ROOT/.env"
if [[ -f "$ENV_FILE" ]]; then
  set -o allexport
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +o allexport
  echo "Loaded .env from $ENV_FILE"
else
  echo "Note: .env not found at $ENV_FILE — relying on shell environment."
fi

# Resolve GEOIP_DB_DIR: if relative, interpret it from the project root
_RAW_DIR="${GEOIP_DB_DIR:-./geoip_dbs}"
if [[ "$_RAW_DIR" == /* ]]; then
  GEOIP_DB_DIR="$_RAW_DIR"
else
  GEOIP_DB_DIR="$PROJECT_ROOT/${_RAW_DIR#./}"
fi

BASE_URL="https://download.maxmind.com/app/geoip_download"
EDITION_IDS=("GeoLite2-City" "GeoLite2-ASN" "GeoLite2-Country")

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo ""
  echo "Error: MAXMIND_LICENSE_KEY is not set."
  echo ""
  echo "  Add it to your .env file:"
  echo "    MAXMIND_LICENSE_KEY=your_license_key_here"
  echo ""
  echo "  Or get a free key at: https://www.maxmind.com/en/geolite2/signup"
  exit 1
fi

mkdir -p "$GEOIP_DB_DIR"
echo "Downloading GeoLite2 databases to: $GEOIP_DB_DIR"
echo ""

for EDITION in "${EDITION_IDS[@]}"; do
  echo "Downloading $EDITION..."
  TMP_TAR="$(mktemp /tmp/geoip_XXXXXX)"

  curl --proto "=https" --silent --show-error --fail --location \
    "${BASE_URL}?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
    -o "$TMP_TAR"

  # Extract to a temp dir, move just the .mmdb (compatible with BSD tar on macOS)
  TMP_DIR="$(mktemp -d /tmp/geoip_extract_XXXXXX)"
  tar -xzf "$TMP_TAR" -C "$TMP_DIR"
  find "$TMP_DIR" -name "*.mmdb" -exec mv {} "$GEOIP_DB_DIR/" \;
  rm -rf "$TMP_DIR" "$TMP_TAR"
  echo "  ✓ ${EDITION}.mmdb"
done

echo ""
echo "Done. Files written to $GEOIP_DB_DIR:"
find "$GEOIP_DB_DIR" -maxdepth 1 -name "*.mmdb" -exec ls -lh {} \; 2>/dev/null \
  || echo "  (no .mmdb files found — check for errors above)"
