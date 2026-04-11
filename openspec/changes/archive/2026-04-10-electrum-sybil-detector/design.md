## Context

Public Electrum servers speak JSON-RPC over TCP/SSL. The protocol is fully documented and request/response is newline-delimited JSON. The M0 prototype must run with zero pip dependencies (stdlib only: `asyncio`, `ssl`, `sqlite3`, `json`, `argparse`).

The key insight driving the design: behavioral signals (especially block notification arrival time) are only meaningful when collected simultaneously from many servers with millisecond precision. This requires a single-process asyncio event loop — not threads, not multiple processes — so all `blockchain.headers.subscribe` callbacks share the same clock.

## Goals / Non-Goals

**Goals:**
- Single-file M0 prototype, stdlib only, runs on any Python 3.10+
- Persistent asyncio connections to all seed servers with exponential backoff reconnect
- Sub-millisecond timestamping of block notifications via `asyncio.get_event_loop().time()` + wall clock anchor
- SQLite storage with WAL mode for concurrent reads during `--report`
- Clean Ctrl+C shutdown that closes all SSL connections gracefully

**Non-Goals:**
- Tor/onion support (M2)
- Server discovery beyond hardcoded seed list (M1)
- Analysis/clustering engine (M3)
- Web UI or API (future)
- Any pip dependency in M0

## Decisions

**Single asyncio event loop (not threads)**
Block notification timing is the highest-value signal. All `blockchain.headers.subscribe` callbacks must fire in the same event loop so timestamps are comparable without clock-sync overhead. Threads would introduce jitter.
Alternative considered: `concurrent.futures.ThreadPoolExecutor` — rejected due to GIL contention and timestamp jitter.

**Newline-delimited JSON over raw TCP/SSL (not a library)**
The Electrum protocol is simple enough to implement with `asyncio.open_connection()` + `ssl.create_default_context()`. Using stdlib avoids any pip dependency.
Alternative: `aiorpcx` (used by Electrum itself) — rejected for M0 due to the no-pip constraint.

**SQLite with WAL mode**
WAL allows concurrent reads (`--report`, `--dump-blocks`) while the daemon writes. Single-file, no infra. Sufficient for M0 with 20 servers.
Alternative: InfluxDB/TimescaleDB — deferred to M2 when scale requires it.

**Periodic polling vs. push**
Block notifications are push (subscribe). Fee data and ping are polled on configurable intervals (default: estimatefee every 60s, fee histogram every 30s, ping every 10s). Polling is simpler to reason about and avoids server-side subscription complexity for non-block data.

**Exponential backoff with jitter**
Reconnect delay: `min(2^attempt * base, max_delay) + random jitter`. Prevents thundering herd when a server bounces.

## Risks / Trade-offs

- [Server bans repeated reconnects] → Jitter + max_delay cap (300s) reduces footprint
- [SQLite WAL grows unbounded] → Checkpoint triggered every N writes (configurable); acceptable for M0
- [asyncio event loop blocked by slow SQLite writes] → Use `loop.run_in_executor(None, ...)` for all DB writes
- [SSL handshake failures on misconfigured servers] → Catch and log, mark server as errored, skip
- [Clock drift affecting timing analysis] → Record both monotonic (`loop.time()`) and wall-clock (`time.time_ns()`) anchored at startup; analysis uses monotonic delta

## Open Questions

- What seed server list to hardcode? (use 1209k.com scrape manually as starting point, ~20 servers)
- Fee histogram polling: 30s may be aggressive for 20 servers — tune after observing server behavior
