## 1. SQLite schema & storage layer

- [x] 1.1 Create `electrum_monitor.py` with SQLite initialization: open/create `electrum_monitor.db`, enable WAL mode, create all 7 tables (`servers`, `block_notifications`, `server_metadata`, `fee_estimates`, `relay_fees`, `fee_histograms`, `availability`) with `CREATE TABLE IF NOT EXISTS`
- [x] 1.2 Implement `DB` class (or module-level helpers) with async-safe write methods using `loop.run_in_executor(None, ...)` for all INSERT operations
- [x] 1.3 Implement `get_or_create_server(host, port, ssl)` that returns a `server_id` from the `servers` table, inserting if new

## 2. Electrum JSON-RPC client

- [x] 2.1 Implement `ElectrumConnection` class using `asyncio.open_connection()` with `ssl.create_default_context()` for SSL servers; handle both SSL and plaintext
- [x] 2.2 Implement newline-delimited JSON-RPC: `send_request(method, params)` returns a Future keyed by `id`; a reader coroutine dispatches responses and push notifications
- [x] 2.3 Implement subscription dispatch: incoming notifications with `method` field (no `id`) are routed to registered handlers
- [x] 2.4 Implement exponential backoff reconnect loop: `delay = min(2^attempt * 2, 300) + uniform(0, 5)`, reset on successful connect

## 3. Data collection per server

- [x] 3.1 On connect: query `server.version`, `server.banner`, `server.donation_address` and write to `server_metadata`; log connect event to `availability`
- [x] 3.2 Subscribe to `blockchain.headers.subscribe`: record `(server_id, height, block_hash, timestamp_ms)` using monotonic clock anchored to wall clock at startup
- [x] 3.3 Periodic ping loop (every 10s): send `server.ping`, measure RTT, write to `availability` with `event_type=ping`
- [x] 3.4 Periodic fee polling loop (every 60s): query `blockchain.estimatefee(n)` for all 11 block targets, write to `fee_estimates`; query `blockchain.relayfee`, write to `relay_fees`
- [x] 3.5 Periodic fee histogram loop (every 30s): query `mempool.get_fee_histogram`, write JSON to `fee_histograms`
- [x] 3.6 On disconnect: log disconnect event to `availability` with error message if available

## 4. Server registry & main loop

- [x] 4.1 Define hardcoded seed list of 15–20 known public Electrum servers (host, port, ssl)
- [x] 4.2 Implement `ConnectionManager` that spawns one `ElectrumConnection` task per server and tracks state in memory
- [x] 4.3 Implement `async def main()` entry point that initializes DB, starts all connection tasks, and awaits `asyncio.gather`
- [x] 4.4 Handle `asyncio.CancelledError` / SIGINT: cancel all tasks, close connections, flush DB, exit cleanly within 5 seconds

## 5. CLI interface

- [x] 5.1 Add `argparse` with `--report` flag: query DB and print per-server summary (total notifications, first/last block, avg RTT, latest fee estimates) to stdout, then exit
- [x] 5.2 Add `--dump-blocks` flag: query `block_notifications JOIN servers`, write CSV to stdout (columns: server_id, host, port, height, block_hash, timestamp_ms), then exit
- [x] 5.3 Wire argparse in `if __name__ == "__main__"`: dispatch to report/dump/daemon mode; run daemon via `asyncio.run(main())`
