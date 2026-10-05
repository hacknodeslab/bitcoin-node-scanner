"""Peer-list sources that feed the scanner's ``--ips`` mode.

Each source turns an external crawler's output into a plain ``host:port``
file under ``INPUT_DIR`` (IPv6 bracketed), so the scanner stays file-based
and the list can be inspected, versioned and re-scanned. Run a source with
``python -m src.peers.fetch <source>``.

Sources:
- ``alt-bitnodes`` — union of the reachable clearnet nodes in our own
  bitnodes crawler's snapshots over the last N days (``alt_bitnodes.py``).
"""
