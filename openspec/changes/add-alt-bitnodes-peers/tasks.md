## 1. Source module

- [x] 1.1 Create `src/peers/__init__.py` (package docstring: peer-list sources feeding `--ips`)
- [x] 1.2 `src/peers/alt_bitnodes.py`: `parse_node_key(key) -> (ip, port) | None` (rsplit on last `:`, `ipaddress` validation/normalisation, `is_global` — excludes CJDNS `fc00::/8` —, port 1–65535, skip onion/i2p; skip reasons counted by kind) and `format_entry(ip, port)` (brackets IPv6)
- [x] 1.3 HTTP client: list snapshots with pagination (`limit=100`) until older than the window; fetch one snapshot; timeout, 3 attempts with backoff on connection errors/5xx, explicit project User-Agent via `requests` (CloudFront 403s `Python-urllib`), `ALT_BITNODES_DELAY` between downloads
- [x] 1.4 Cache: atomic write of `<ts>.txt`, valid-cache check (non-empty, readable), prune files older than the window; paths via `safe_input_write`
- [x] 1.5 `build_union(days, output)`: list → download missing → prune → union → atomic write with `#` header; returns a summary dict

## 2. CLI

- [x] 2.1 `src/peers/fetch.py`: `python -m src.peers.fetch alt-bitnodes [--days N] [--output PATH]`, env defaults `ALT_BITNODES_URL`, `ALT_BITNODES_WINDOW_DAYS`
- [x] 2.2 Exit codes (0 / 1), refused paths and list failure leave the previous output untouched; print the summary and the follow-up `--ips … --source-tag alt-bitnodes` command

## 3. Tests (all HTTP mocked)

- [x] 3.1 Parsing: IPv4, unbracketed compressed IPv6 → bracketed, non-default port, onion / i2p (port 0) / CJDNS / private / invalid skipped and counted by kind, normalisation
- [x] 3.2 Window + pagination: stops paging past the window; out-of-window snapshots never downloaded
- [x] 3.3 Cache: only missing snapshots downloaded; empty cache file refetched; old files pruned
- [x] 3.4 Failures: one snapshot 500 → reported and skipped, exit 0; listing failure → exit 1, previous output unchanged; retry on 503
- [x] 3.5 Paths: `--output` outside INPUT_DIR refused before any request
- [x] 3.6 Round trip: output file read by `src.ip_list.read_ip_list` yields the intended IPs and ports (incl. IPv6)

## 4. Docs and local check

- [x] 4.1 `.env.example` (`ALT_BITNODES_URL`, `ALT_BITNODES_WINDOW_DAYS`, `ALT_BITNODES_DELAY`), `CLAUDE.md` (command + module), `docs/bitcoin-scanner.md` (daily flow), `docs/ARCHITECTURE.md` (source in the system map)
- [x] 4.2 Run the fetcher once against the live instance and scan a small sample (`--max-ips`) to verify end to end
- [x] 4.3 `python -m pytest tests/` offline
