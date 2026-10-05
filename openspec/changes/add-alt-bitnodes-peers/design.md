## Context

alt-bitnodes (FastAPI over the upstream bitnodes crawler) exposes:

- `GET /api/v1/snapshots/?page=N&limit=M` → `{count, next, previous, results: [{url, timestamp, total_nodes, latest_height}]}`, newest first. ~1,435 snapshots retained; ~37 per day (298 in the last 8 days at the time of writing).
- `GET /api/v1/snapshots/<ts>/` (and `/latest/`) → `{timestamp, total_nodes, latest_height, nodes: {"<host>:<port>": [protocol, user_agent, connected_since, height, …]}}`, ~190 KB.

Node keys are `host:port`; IPv4 as `1.2.3.4:8333`, IPv6 **unbracketed** (`2a07:9a07:3::2:105:8333`). A sample snapshot had 1,553 IPv4 + 1,110 IPv6; ports mostly 8333 (92%), also 9333, 8332, 8334. `/api/v1/stats/window` reports 0 Tor and 0 I2P in every window (the crawler is clearnet-only today) and an 8-day union of 6,690 addresses; sampled snapshots contained no CJDNS, non-global or port-0 keys.

The API sits behind CloudFront, which answers **403 to the `Python-urllib` User-Agent**; `python-requests/*`, `curl/*` and the project UA are accepted.

The scanner's `--ips` reader (`src/ip_list.py`) is generic and, by documented design, reads an unbracketed compressed IPv6 followed by `:port` as a bare address — correct for its tolerant input, wrong for this source.

## Goals / Non-Goals

**Goals:**
- Produce `data/peers/alt-bitnodes.txt`: the union of reachable clearnet nodes seen in the last N days (default 8), in a format `--ips` reads unambiguously.
- Daily runs cheap for both sides: only new snapshots are downloaded.
- Robust to partial failures (a snapshot that fails to download doesn't abort the run).
- No change to the scanner, the reader or the database.

**Non-Goals:**
- Scheduling, auto-chaining to the scanner/importer, using snapshot metadata, onion/I2P.

## Decisions

**1. A separate fetch step that writes a file, not a scanner flag.** Keeps `--ips` file-based (re-runnable, inspectable, versionable list), keeps network fetching out of the scanner, and lets future sources (`getnodeaddresses` conversion, other crawlers) plug into the same `src/peers/` package. *Alternative:* `--alt-bitnodes` on the scanner — rejected: mixes download and scan, no artefact to repeat a run.

**2. Format-aware parsing in the source module.** `host, port = key.rsplit(":", 1)`; `ipaddress.ip_address(host)` must succeed (normalised) and be globally routable (`is_global`), which also excludes CJDNS `fc00::/8`; port must be 1–65535; `.onion` / `.i2p` (bitnodes writes I2P with port `0`) and anything else are counted as skipped, by kind. Kept defensively even though today's snapshots contain none of them, so a crawler that later reaches Tor/I2P/CJDNS can't leak unroutable entries into `--ips`. Output IPv6 as `[ip]:port`. *Alternative:* teach `ip_list.py` the alt-bitnodes shape — rejected: the ambiguity is inherent to the generic input; only the source knows the trailing group is always a port.

**3. Incremental per-snapshot cache.** `data/peers/alt-bitnodes/cache/<ts>.txt`, one normalised `host:port` per line, written atomically (temp file + `os.replace`). A run:
1. pages through the snapshot list (`limit=100`) until timestamps fall before `now - window`;
2. downloads only snapshots in the window without a valid cache file (an empty or unreadable file counts as missing);
3. deletes cache files older than the window;
4. unions all cached files in the window and writes the output.

Steady state ≈ 37 downloads (~7 MB) per day; first run ≈ 300 (~57 MB). *Alternatives:* re-download everything daily (75 MB/day, needless load); sample one snapshot per hour (misses short-lived nodes, still re-downloads) — rejected.

**4. Output file format.** Header lines starting with `#` (source URL, window, first/last snapshot UTC, snapshots used, generated at) — ignored by the reader — then `host:port` lines sorted by IP family then address for stable diffs. A node seen on several ports yields several lines; `ip_list.py` merges ports per IP. Written atomically.

**5. HTTP behaviour.** `requests` (never `urllib`, whose default UA CloudFront rejects) with timeout, 3 attempts with backoff on connection errors / 5xx, an explicit project User-Agent, and `ALT_BITNODES_DELAY` (default 0.2 s) between snapshot downloads. A failed snapshot is logged and reported in the summary; a failed **list** request aborts the run with a non-zero exit and leaves the previous output untouched.

**6. Paths.** Cache and output go through `safe_input_write` (under `INPUT_DIR`). Defaults are derived from `input_root()` (`<INPUT_DIR>/peers/…`), so a custom `INPUT_DIR` keeps working. `--output` must also resolve under `INPUT_DIR`.

**7. CLI.** `python -m src.peers.fetch <source> [--days N] [--output PATH]` with `alt-bitnodes` as the only source for now. Exit codes: 0 success (even with some failed snapshots, reported), 1 list failure / no snapshot in window / path refused. The summary prints the follow-up `--ips … --source-tag alt-bitnodes` command.

## Risks / Trade-offs

- [alt-bitnodes API shape changes] → parsing is defensive (unexpected keys/values are skipped and counted); a shape test pins the current format.
- [Snapshot retention shorter than the window] → the run uses what exists and reports the effective window in the header and summary.
- [First run load on our own server] → one-off ~300 requests with a small delay, behind CloudFront.
- [CloudFront/WAF rules change and block the client] → explicit project User-Agent; a 403 on the listing is reported clearly as an access problem rather than retried.
- [Union includes nodes that went away days ago] → intended (intermittent reachability); the scanner simply finds no Bitcoin service for them, and the header states the window.
- [Disk] → ~300 small text files (~60 KB each), pruned daily.

## Migration Plan

Additive: new package and env vars, no schema change. Rollback is deleting `src/peers/` and the cache directory.

## Open Questions

- Scheduling on frodo (systemd timer next to the services) once this is deployed.
- Whether to feed alt-bitnodes' user-agent/height into nodes as a Shodan-independent version signal (later).
