## 1. Database — Model & Migration

- [x] 1.1 Add columns to `Node` in `src/db/models.py`: `hostname` (String 255), `os_info` (String 255), `isp` (String 255), `org` (String 255), `open_ports_json` (Text), `vulns_json` (Text), `tags_json` (Text), `cpe_json` (Text)
- [x] 1.2 Create `migrations/versions/006_add_enrichment_fields.py` — add all 8 columns as nullable, `down_revision` pointing to `'005_add_ip_numeric'`

## 2. Scanner — Capture Fields

- [x] 2.1 In `src/scanner.py` `parse_node_data`: add `os`, `tags`, `isp`, `org` (already in result), `hostnames` to the returned dict (some already present — verify and fill gaps)
- [x] 2.2 In `src/scanner.py` `enrich_with_host_scan`: include `os` and `tags` in the returned enrichment dict (already there — verify `all_services` includes `transport` field)

## 3. Scanner Integration — Persist Fields

- [x] 3.1 In `src/db/scanner_integration.py` `save_node`: add `hostname`, `os_info`, `isp`, `org`, `vulns_json`, `cpe_json` to the upsert dict (from `node_data`, JSON-serialising list fields)
- [x] 3.2 In `src/db/scanner_integration.py`: when `node_data` contains `enrichment` key, update `open_ports_json` and `tags_json` on the node record

## 4. Web API — Expose Fields

- [x] 4.1 In `src/web/routers/nodes.py` `NodeOut`: add `hostname`, `os_info`, `isp`, `org`, `open_ports` (List or None), `vulns` (List or None), `tags` (List or None), `cpe` (List or None)
- [x] 4.2 In `_make_node_out`: deserialise JSON columns (`open_ports_json` → `open_ports`, etc.) using `json.loads`; default to `None` if column is null

## 5. Frontend — Modal Display

- [x] 5.1 In `index.html` `openNodeModal` Shodan section: add rows for Hostname, OS, ISP, Org, CVEs (comma-separated or badge list), Tags, CPE
- [x] 5.2 In `index.html`: if `n.open_ports` is a non-empty list, render a mini ports table inside the modal (columns: Port, Transport, Product, Version)
