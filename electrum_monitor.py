"""
electrum_monitor.py — M0 Electrum Server Sybil Detector

Connects to a hardcoded list of public Electrum servers, collects behavioral
fingerprints (block notifications, fee data, RTT, uptime) and stores them in
a local SQLite database for later sybil analysis.

Usage:
    python electrum_monitor.py            # run daemon (Ctrl+C to stop)
    python electrum_monitor.py --report   # print summary and exit
    python electrum_monitor.py --dump-blocks  # dump block CSV to stdout and exit

stdlib only — no pip dependencies required.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import random
import signal
import sqlite3
import ssl
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("electrum_monitor")

# ── Seed server list ──────────────────────────────────────────────────────────
# (host, port, use_ssl)
SEED_SERVERS: List[Tuple[str, int, bool]] = [
    # Source: https://1209k.com/bitcoin-eye/ele.php?chain=btc
    ("electrum.blockstream.info", 50002, True),
    ("electrum.blockstream.info", 50001, False),
    ("electrum.blockitall.us", 50002, True),
    ("electrum.blockitall.us", 50001, False),
    ("fulcrum2.not.fyi", 51002, True),
    ("0xrpc.io", 50002, True),
    ("bitcoin.threshold.p2p.org", 50002, True),
    ("hippo.1209k.com", 50002, True),
    ("blackie.c3-soft.com", 57002, True),
    ("blackie.c3-soft.com", 57001, False),
    ("bolt.schulzemic.net", 50002, True),
    ("bolt.schulzemic.net", 50001, False),
    ("electrum2.snel.it", 50002, True),
    ("electrum2.snel.it", 50001, False),
    ("bitcoin.aranguren.org", 50002, True),
    ("bitcoin.aranguren.org", 50001, False),
    ("btc.ocf.sh", 50002, True),
    ("btc.ocf.sh", 50001, False),
    ("electrum.loyce.club", 50002, True),
    ("electrum.loyce.club", 50001, False),
]

DB_PATH = "electrum_monitor.db"
FEE_TARGETS = [1, 2, 3, 5, 10, 25, 50, 100, 144, 504, 1008]
PING_INTERVAL = 10      # seconds
FEE_INTERVAL = 60       # seconds
HISTOGRAM_INTERVAL = 30 # seconds

# Monotonic clock anchor: wall_ns + (loop.time() - loop_anchor) * 1e9 = wall time
_WALL_ANCHOR_NS: int = 0
_LOOP_ANCHOR: float = 0.0


def monotonic_ms() -> int:
    """Return milliseconds since epoch using monotonic clock anchored at startup."""
    delta_s = asyncio.get_event_loop().time() - _LOOP_ANCHOR
    return (_WALL_ANCHOR_NS + int(delta_s * 1e9)) // 1_000_000


# ── Database ──────────────────────────────────────────────────────────────────

class DB:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        self._conn.commit()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS servers (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host        TEXT NOT NULL,
                port        INTEGER NOT NULL,
                ssl         INTEGER NOT NULL,
                first_seen  INTEGER NOT NULL,
                last_state  TEXT NOT NULL DEFAULT 'unknown',
                UNIQUE(host, port)
            );
            CREATE TABLE IF NOT EXISTS block_notifications (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id    INTEGER NOT NULL,
                height       INTEGER NOT NULL,
                block_hash   TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS server_metadata (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id         INTEGER NOT NULL,
                timestamp         INTEGER NOT NULL,
                protocol_version  TEXT,
                server_software   TEXT,
                banner            TEXT,
                donation_address  TEXT,
                features_json     TEXT
            );
            CREATE TABLE IF NOT EXISTS fee_estimates (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id    INTEGER NOT NULL,
                timestamp    INTEGER NOT NULL,
                block_target INTEGER NOT NULL,
                fee_rate     REAL
            );
            CREATE TABLE IF NOT EXISTS relay_fees (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                relay_fee REAL
            );
            CREATE TABLE IF NOT EXISTS fee_histograms (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id      INTEGER NOT NULL,
                timestamp      INTEGER NOT NULL,
                histogram_json TEXT
            );
            CREATE TABLE IF NOT EXISTS availability (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id  INTEGER NOT NULL,
                timestamp  INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                latency_ms REAL,
                error      TEXT
            );
        """)

    def get_or_create_server(self, host: str, port: int, use_ssl: bool) -> int:
        cur = self._conn.execute(
            "SELECT id FROM servers WHERE host=? AND port=?", (host, port)
        )
        row = cur.fetchone()
        if row:
            return row[0]
        now = int(time.time() * 1000)
        cur = self._conn.execute(
            "INSERT INTO servers(host, port, ssl, first_seen, last_state) VALUES(?,?,?,?,?)",
            (host, port, int(use_ssl), now, "unknown"),
        )
        self._conn.commit()
        return cur.lastrowid

    def set_server_state(self, server_id: int, state: str) -> None:
        self._conn.execute(
            "UPDATE servers SET last_state=? WHERE id=?", (state, server_id)
        )
        self._conn.commit()

    def insert_block(self, server_id: int, height: int, block_hash: str, ts_ms: int) -> None:
        self._conn.execute(
            "INSERT INTO block_notifications(server_id,height,block_hash,timestamp_ms) VALUES(?,?,?,?)",
            (server_id, height, block_hash, ts_ms),
        )
        self._conn.commit()

    def insert_metadata(
        self,
        server_id: int,
        protocol_version: Optional[str],
        server_software: Optional[str],
        banner: Optional[str],
        donation_address: Optional[str],
    ) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            """INSERT INTO server_metadata
               (server_id,timestamp,protocol_version,server_software,banner,donation_address)
               VALUES(?,?,?,?,?,?)""",
            (server_id, now, protocol_version, server_software, banner, donation_address),
        )
        self._conn.commit()

    def insert_fee_estimate(self, server_id: int, block_target: int, fee_rate: float) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            "INSERT INTO fee_estimates(server_id,timestamp,block_target,fee_rate) VALUES(?,?,?,?)",
            (server_id, now, block_target, fee_rate),
        )
        self._conn.commit()

    def insert_relay_fee(self, server_id: int, relay_fee: float) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            "INSERT INTO relay_fees(server_id,timestamp,relay_fee) VALUES(?,?,?)",
            (server_id, now, relay_fee),
        )
        self._conn.commit()

    def insert_histogram(self, server_id: int, histogram_json: str) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            "INSERT INTO fee_histograms(server_id,timestamp,histogram_json) VALUES(?,?,?)",
            (server_id, now, histogram_json),
        )
        self._conn.commit()

    def insert_availability(
        self,
        server_id: int,
        event_type: str,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        now = int(time.time() * 1000)
        self._conn.execute(
            "INSERT INTO availability(server_id,timestamp,event_type,latency_ms,error) VALUES(?,?,?,?,?)",
            (server_id, now, event_type, latency_ms, error),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ── Electrum JSON-RPC connection ──────────────────────────────────────────────

class ElectrumConnection:
    def __init__(
        self,
        host: str,
        port: int,
        use_ssl: bool,
        server_id: int,
        db: DB,
    ) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.server_id = server_id
        self.db = db
        self.label = f"{host}:{port}"

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._request_id = 0
        self._pending: Dict[int, asyncio.Future] = {}
        self._subscriptions: Dict[str, Callable] = {}
        self._connected = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def connect(self) -> None:
        if self.use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            ssl_ctx = None
        self._reader, self._writer = await asyncio.open_connection(
            self.host, self.port, ssl=ssl_ctx
        )
        self._connected = True
        self._loop = asyncio.get_event_loop()

    def is_connected(self) -> bool:
        return self._connected

    async def send_request(self, method: str, params: List[Any]) -> Any:
        self._request_id += 1
        req_id = self._request_id
        payload = json.dumps({"id": req_id, "method": method, "params": params}) + "\n"
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = fut
        self._writer.write(payload.encode())
        await self._writer.drain()
        return await fut

    def register_subscription(self, method: str, handler: Callable) -> None:
        self._subscriptions[method] = handler

    async def read_loop(self) -> None:
        try:
            while self._connected:
                line = await self._reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue

                # Push notification (no id, has method)
                if "method" in msg and "id" not in msg:
                    method = msg["method"]
                    if method in self._subscriptions:
                        asyncio.ensure_future(
                            self._subscriptions[method](msg.get("params", []))
                        )
                    continue

                # Response to a request
                req_id = msg.get("id")
                if req_id in self._pending:
                    fut = self._pending.pop(req_id)
                    if "error" in msg and msg["error"]:
                        fut.set_exception(RuntimeError(str(msg["error"])))
                    else:
                        fut.set_result(msg.get("result"))
        except Exception:
            pass
        finally:
            self._connected = False
            # Cancel all pending futures
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            self._pending.clear()

    def close(self) -> None:
        self._connected = False
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass


# ── Per-server worker ─────────────────────────────────────────────────────────

async def _collect_metadata(
    conn: ElectrumConnection,
    db: DB,
    loop: asyncio.AbstractEventLoop,
    protocol_version: Optional[str] = None,
    server_software: Optional[str] = None,
) -> None:
    """Collect server banner and donation address. read_loop must already be running."""
    try:
        banner = await asyncio.wait_for(conn.send_request("server.banner", []), timeout=10)
    except Exception:
        banner = None

    try:
        donation = await asyncio.wait_for(conn.send_request("server.donation_address", []), timeout=10)
    except Exception:
        donation = None

    await loop.run_in_executor(
        None,
        db.insert_metadata,
        conn.server_id,
        protocol_version,
        server_software,
        str(banner) if banner else None,
        str(donation) if donation else None,
    )


async def _ping_loop(conn: ElectrumConnection, db: DB, loop: asyncio.AbstractEventLoop) -> None:
    while conn.is_connected():
        await asyncio.sleep(PING_INTERVAL)
        if not conn.is_connected():
            break
        try:
            t0 = loop.time()
            await asyncio.wait_for(conn.send_request("server.ping", []), timeout=15)
            latency_ms = (loop.time() - t0) * 1000
            await loop.run_in_executor(
                None, db.insert_availability, conn.server_id, "ping", latency_ms, None
            )
        except Exception:
            pass


async def _fee_loop(conn: ElectrumConnection, db: DB, loop: asyncio.AbstractEventLoop) -> None:
    while conn.is_connected():
        for target in FEE_TARGETS:
            try:
                fee_rate = await asyncio.wait_for(
                    conn.send_request("blockchain.estimatefee", [target]), timeout=15
                )
                if isinstance(fee_rate, (int, float)):
                    await loop.run_in_executor(
                        None, db.insert_fee_estimate, conn.server_id, target, float(fee_rate)
                    )
            except Exception:
                pass
        try:
            relay_fee = await asyncio.wait_for(
                conn.send_request("blockchain.relayfee", []), timeout=15
            )
            if isinstance(relay_fee, (int, float)):
                await loop.run_in_executor(
                    None, db.insert_relay_fee, conn.server_id, float(relay_fee)
                )
        except Exception:
            pass
        await asyncio.sleep(FEE_INTERVAL)


async def _histogram_loop(conn: ElectrumConnection, db: DB, loop: asyncio.AbstractEventLoop) -> None:
    while conn.is_connected():
        try:
            histogram = await asyncio.wait_for(
                conn.send_request("mempool.get_fee_histogram", []), timeout=15
            )
            if histogram is not None:
                await loop.run_in_executor(
                    None, db.insert_histogram, conn.server_id, json.dumps(histogram)
                )
        except Exception:
            pass
        await asyncio.sleep(HISTOGRAM_INTERVAL)


async def server_worker(host: str, port: int, use_ssl: bool, server_id: int, db: DB) -> None:
    loop = asyncio.get_event_loop()
    attempt = 0
    label = f"{host}:{port}"

    while True:
        conn = ElectrumConnection(host, port, use_ssl, server_id, db)
        try:
            log.info(f"[{label}] Connecting...")
            await asyncio.wait_for(conn.connect(), timeout=30)
            attempt = 0
            log.info(f"[{label}] Connected")

            await loop.run_in_executor(None, db.set_server_state, server_id, "connected")
            await loop.run_in_executor(
                None, db.insert_availability, server_id, "connect", None, None
            )

            # ── FIX: start read_loop immediately so send_request futures resolve ──
            read_task = asyncio.ensure_future(conn.read_loop())

            # 1. Protocol handshake — MUST be the first message per Electrum spec
            protocol_version = server_software = None
            try:
                version_res = await asyncio.wait_for(
                    conn.send_request("server.version", ["electrum_monitor/1.0", "1.4"]), timeout=15
                )
                if isinstance(version_res, list):
                    server_software = version_res[0] if len(version_res) > 0 else None
                    protocol_version = version_res[1] if len(version_res) > 1 else None
                log.info(f"[{label}] Handshake OK: {server_software} proto={protocol_version}")
            except Exception as e:
                log.warning(f"[{label}] Version negotiation failed: {e}")

            # 2. Subscribe to block headers
            async def on_block_header(params: List[Any]) -> None:
                ts = monotonic_ms()
                try:
                    if isinstance(params, list) and len(params) > 0:
                        header = params[0]
                        if isinstance(header, dict):
                            height = header.get("height", 0)
                            block_hash = header.get("hex", "")[:64]
                        else:
                            height = 0
                            block_hash = str(header)[:64]
                    else:
                        return
                    log.debug(f"[{label}] Block {height} @ {ts}ms")
                    await loop.run_in_executor(
                        None, db.insert_block, server_id, height, block_hash, ts
                    )
                except Exception as e:
                    log.debug(f"[{label}] Block parse error: {e}")

            conn.register_subscription("blockchain.headers.subscribe", on_block_header)
            try:
                sub_result = await asyncio.wait_for(
                    conn.send_request("blockchain.headers.subscribe", []), timeout=15
                )
                # Initial tip is returned as the subscription result
                if isinstance(sub_result, dict):
                    await on_block_header([sub_result])
            except Exception as e:
                log.debug(f"[{label}] Subscribe error: {e}")

            # 3. Collect remaining metadata (banner, donation address)
            await _collect_metadata(conn, db, loop, protocol_version, server_software)

            # 4. Start periodic tasks
            tasks = [
                read_task,
                asyncio.ensure_future(_ping_loop(conn, db, loop)),
                asyncio.ensure_future(_fee_loop(conn, db, loop)),
                asyncio.ensure_future(_histogram_loop(conn, db, loop)),
            ]

            # Wait until read_loop ends (connection dropped)
            await tasks[0]
            for t in tasks[1:]:
                t.cancel()

            error_msg = "connection closed"

        except asyncio.CancelledError:
            conn.close()
            raise
        except Exception as e:
            error_msg = str(e)
            log.warning(f"[{label}] Error: {e}")
        finally:
            conn.close()
            try:
                await loop.run_in_executor(None, db.set_server_state, server_id, "disconnected")
                await loop.run_in_executor(
                    None, db.insert_availability, server_id, "disconnect", None, error_msg
                )
            except Exception:
                pass

        # Exponential backoff with jitter
        delay = min(2 ** attempt * 2, 300) + random.uniform(0, 5)
        attempt += 1
        log.info(f"[{label}] Reconnecting in {delay:.1f}s (attempt {attempt})")
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise


# ── Connection manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self, db: DB) -> None:
        self._db = db
        self._tasks: List[asyncio.Task] = []

    def start_all(self, servers: List[Tuple[str, int, bool]]) -> None:
        seen = set()
        for host, port, use_ssl in servers:
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            server_id = self._db.get_or_create_server(host, port, use_ssl)
            task = asyncio.ensure_future(
                server_worker(host, port, use_ssl, server_id, self._db)
            )
            self._tasks.append(task)

    def cancel_all(self) -> None:
        for t in self._tasks:
            t.cancel()


# ── Main daemon ───────────────────────────────────────────────────────────────

async def main() -> None:
    global _WALL_ANCHOR_NS, _LOOP_ANCHOR
    loop = asyncio.get_event_loop()
    _WALL_ANCHOR_NS = time.time_ns()
    _LOOP_ANCHOR = loop.time()

    db = DB(DB_PATH)
    manager = ConnectionManager(db)

    stop_event = asyncio.Event()

    def _handle_sigint() -> None:
        log.info("Shutdown requested (SIGINT)")
        stop_event.set()

    loop.add_signal_handler(signal.SIGINT, _handle_sigint)
    loop.add_signal_handler(signal.SIGTERM, _handle_sigint)

    log.info(f"Starting monitor: {len(SEED_SERVERS)} seed servers → {DB_PATH}")
    manager.start_all(SEED_SERVERS)

    await stop_event.wait()

    log.info("Shutting down...")
    manager.cancel_all()
    await asyncio.sleep(2)
    db.close()
    log.info("Done.")


# ── CLI reporting ─────────────────────────────────────────────────────────────

def cmd_report() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    servers = conn.execute("SELECT * FROM servers ORDER BY id").fetchall()
    if not servers:
        print("No data collected yet.")
        conn.close()
        return

    print(f"\n{'='*70}")
    print(f"  Electrum Monitor Report — {DB_PATH}")
    print(f"{'='*70}\n")

    for s in servers:
        sid = s["id"]
        label = f"{s['host']}:{s['port']} ({'SSL' if s['ssl'] else 'TCP'})"
        state = s["last_state"]

        # Block notifications
        blocks = conn.execute(
            "SELECT COUNT(*), MIN(timestamp_ms), MAX(timestamp_ms), MAX(height) "
            "FROM block_notifications WHERE server_id=?", (sid,)
        ).fetchone()
        n_blocks = blocks[0] or 0
        first_ts = blocks[1]
        last_ts = blocks[2]
        max_height = blocks[3]

        # Avg RTT
        avg_rtt = conn.execute(
            "SELECT AVG(latency_ms) FROM availability WHERE server_id=? AND event_type='ping'",
            (sid,)
        ).fetchone()[0]

        # Latest fee estimates
        latest_fees = conn.execute(
            """SELECT block_target, fee_rate FROM fee_estimates
               WHERE server_id=? AND timestamp=(
                 SELECT MAX(timestamp) FROM fee_estimates WHERE server_id=?
               )
               ORDER BY block_target""",
            (sid, sid)
        ).fetchall()

        print(f"  {label}  [{state}]")
        print(f"    Blocks: {n_blocks}" + (f"  latest height={max_height}" if max_height else ""))
        if first_ts and last_ts:
            print(f"    First: {_ms_to_str(first_ts)}  Last: {_ms_to_str(last_ts)}")
        print(f"    Avg RTT: {avg_rtt:.1f}ms" if avg_rtt else "    Avg RTT: —")
        if latest_fees:
            fee_str = "  ".join(f"{r['block_target']}blk={r['fee_rate']:.5f}" for r in latest_fees[:4])
            print(f"    Fees: {fee_str}")
        print()

    conn.close()


def _ms_to_str(ms: int) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")


def cmd_dump_blocks() -> None:
    conn = sqlite3.connect(DB_PATH)
    writer = csv.writer(sys.stdout)
    writer.writerow(["server_id", "host", "port", "height", "block_hash", "timestamp_ms"])
    rows = conn.execute(
        """SELECT bn.server_id, s.host, s.port, bn.height, bn.block_hash, bn.timestamp_ms
           FROM block_notifications bn
           JOIN servers s ON s.id = bn.server_id
           ORDER BY bn.timestamp_ms"""
    ).fetchall()
    writer.writerows(rows)
    conn.close()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Electrum Server Sybil Detector — M0 data collector"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print summary report and exit",
    )
    parser.add_argument(
        "--dump-blocks",
        action="store_true",
        help="Dump block notifications as CSV to stdout and exit",
    )
    args = parser.parse_args()

    if args.report:
        cmd_report()
    elif args.dump_blocks:
        cmd_dump_blocks()
    else:
        asyncio.run(main())
