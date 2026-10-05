## ADDED Requirements

### Requirement: Fetch alt-bitnodes peers into an --ips list
The system SHALL provide `python -m src.peers.fetch alt-bitnodes [--days N] [--output PATH]` that builds the union of clearnet nodes present in the alt-bitnodes snapshots of the last N days (default `ALT_BITNODES_WINDOW_DAYS`, 8) from `ALT_BITNODES_URL` (default `https://pesquisa.hacknodes.xyz`) and writes it to `<INPUT_DIR>/peers/alt-bitnodes.txt` (or `--output`), one `host:port` per line.

#### Scenario: Union across snapshots
- **WHEN** snapshot A contains `1.1.1.1:8333` and snapshot B (both in the window) contains `1.1.1.1:8333` and `2.2.2.2:8333`
- **THEN** the output SHALL contain exactly `1.1.1.1:8333` and `2.2.2.2:8333`

#### Scenario: Snapshots outside the window are ignored
- **WHEN** a snapshot's timestamp is older than now minus N days
- **THEN** it SHALL NOT be downloaded and its nodes SHALL NOT appear in the output

#### Scenario: Output is readable by --ips
- **WHEN** the output file is passed to `python -m src.scanner --ips`
- **THEN** every IPv4 and IPv6 entry SHALL be read with its intended IP and port

### Requirement: Format-aware parsing of alt-bitnodes node keys
Node keys SHALL be split on their last `:` into host and port. The host SHALL be a valid, globally routable IP address (normalised); the port SHALL be an integer 1–65535. IPv6 addresses SHALL be written bracketed (`[ip]:port`). `.onion`, `.i2p`, CJDNS (`fc00::/8`), non-global addresses and otherwise invalid keys SHALL be skipped and counted by kind.

#### Scenario: Unbracketed IPv6 key
- **WHEN** a snapshot contains the key `2a07:9a07:3::2:105:8333`
- **THEN** the output SHALL contain `[2a07:9a07:3::2:105]:8333`

#### Scenario: Non-default port preserved
- **WHEN** a snapshot contains `5.6.7.8:9333`
- **THEN** the output SHALL contain `5.6.7.8:9333`

#### Scenario: Onion address skipped
- **WHEN** a snapshot contains `abc…xyz.onion:8333`
- **THEN** it SHALL NOT appear in the output and the summary SHALL count it as skipped (onion)

#### Scenario: I2P address skipped
- **WHEN** a snapshot contains `abc…xyz.b32.i2p:0`
- **THEN** it SHALL NOT appear in the output and the summary SHALL count it as skipped (i2p)

#### Scenario: CJDNS and non-global addresses skipped
- **WHEN** a snapshot contains `fc32:17ea:e415:c3bf:9808:149d:b5a2:c9aa:8333` or `10.0.0.5:8333`
- **THEN** neither SHALL appear in the output and the summary SHALL count them as skipped

### Requirement: Incremental snapshot cache
Each downloaded snapshot's parsed address list SHALL be cached under `<INPUT_DIR>/peers/alt-bitnodes/cache/<timestamp>.txt`, written atomically. A run SHALL download only in-window snapshots without a valid cache file, and SHALL delete cache files older than the window. An empty or unreadable cache file SHALL be treated as missing.

#### Scenario: Daily run downloads only new snapshots
- **WHEN** the cache already holds every in-window snapshot except the two newest
- **THEN** exactly two snapshot downloads SHALL be made

#### Scenario: Old cache pruned
- **WHEN** a cache file's timestamp is older than the window
- **THEN** it SHALL be deleted during the run

### Requirement: Resilient fetching
Snapshot listing and downloads SHALL use a timeout, retry with backoff on connection errors and 5xx responses, send an explicit User-Agent identifying the project (CloudFront rejects the `Python-urllib` default), and wait `ALT_BITNODES_DELAY` seconds (default 0.2) between snapshot downloads. A snapshot that still fails SHALL be skipped and reported; a failed snapshot listing SHALL abort the run with exit status 1 and leave any existing output file unchanged.

#### Scenario: One snapshot fails
- **WHEN** one of ten in-window snapshots returns HTTP 500 on every attempt
- **THEN** the output SHALL be built from the other nine, the summary SHALL report one failure, and the exit status SHALL be 0

#### Scenario: Listing unavailable
- **WHEN** `GET /api/v1/snapshots/` fails on every attempt
- **THEN** the command SHALL exit with status 1 and the previous output file SHALL be left untouched

### Requirement: Paths confined to INPUT_DIR
The cache directory and the output file (including an explicit `--output`) SHALL be written only under `INPUT_DIR`, via `src/safe_paths.py`.

#### Scenario: Output outside INPUT_DIR
- **WHEN** `--output /tmp/peers.txt` is given and `/tmp` is not under `INPUT_DIR`
- **THEN** the command SHALL exit with status 1 without fetching or writing anything

### Requirement: Run summary
The command SHALL print the window used, snapshots found / taken from cache / downloaded / failed, unique IPv4 and IPv6 addresses, skipped keys, the output path, and the follow-up command `python -m src.scanner --ips <output> --source-tag alt-bitnodes`. The output file SHALL begin with `#` comment lines recording the source URL, window, snapshot count, first/last snapshot time and generation time.

#### Scenario: Summary printed
- **WHEN** a run completes
- **THEN** stdout SHALL include the counts above and the follow-up `--ips` command with `--source-tag alt-bitnodes`
