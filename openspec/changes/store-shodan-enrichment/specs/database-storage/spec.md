## MODIFIED Requirements

### Requirement: Node persistence
El sistema SHALL persistir información de nodos Bitcoin escaneados con deduplicación por IP y puerto. The Node record SHALL include the following additional nullable columns: `hostname` (Text), `hostnames_json` (Text, JSON array), `os_info` (Text), `isp` (Text), `org` (Text), `open_ports_json` (Text, JSON array of port objects), `vulns_json` (Text, JSON array of CVE IDs), `tags_json` (Text, JSON array), `cpe_json` (Text, JSON array). A migration `006_add_enrichment_fields` SHALL add these columns.

#### Scenario: Guardar nodo nuevo
- **WHEN** se escanea un nodo con IP que no existe en la base de datos
- **THEN** se crea registro con IP, puerto, país, ASN, versión, banner, first_seen=now, last_seen=now, y los nuevos campos de enriquecimiento si están disponibles

#### Scenario: Migration adds columns without data loss
- **WHEN** migration 006 runs on an existing database
- **THEN** all new columns are added as nullable with no existing data modified
