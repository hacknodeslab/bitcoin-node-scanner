## MODIFIED Requirements

### Requirement: Vulnerability tracking

El sistema SHALL registrar vulnerabilidades detectadas en cada nodo enlazándolas a entradas del catálogo NVD (`cve_entries`). El enlace se materializa en la tabla `node_vulnerabilities` mediante la columna `cve_entry_id` (FK a `cve_entries.id`). El enlace SHALL crearse de forma automática durante la persistencia del nodo cuando su `version` esté cubierta por el rango `affected_versions` de alguna entrada CVE filtrada por producto `bitcoin:bitcoin`. Si la versión deja de estar cubierta entre escaneos, el enlace correspondiente SHALL marcarse como resuelto (`resolved_at = now`).

#### Scenario: Registrar vulnerabilidad detectada durante upsert de nodo
- **WHEN** se persiste un nodo con `version = "0.21.0"` y existe un CVE en `cve_entries` cuyo rango cubre `0.21.0`
- **THEN** se crea (o se mantiene activa) una fila en `node_vulnerabilities` con `node_id`, `cve_entry_id`, `detected_at = now`, `detected_version = "0.21.0"`, `resolved_at = NULL`

#### Scenario: Resolver vulnerabilidad cuando el nodo se actualiza
- **WHEN** un nodo previamente enlazado a una CVE se reescanea con una `version` que ya no entra en el rango de afectación
- **THEN** la fila correspondiente en `node_vulnerabilities` recibe `resolved_at = now` y no se duplica

#### Scenario: Consultar vulnerabilidades activas de un nodo
- **WHEN** se solicitan las vulnerabilidades activas de un nodo
- **THEN** se devuelven las CVEs cuyas filas en `node_vulnerabilities` tienen `resolved_at IS NULL`, ordenadas por `cve_entries.cvss_score DESC` (NULLs al final)

#### Scenario: Versión no parseable no genera enlaces
- **WHEN** se persiste un nodo con `version = "Satoshi:dev-build"` (sin triple semver extraíble)
- **THEN** no se crean filas en `node_vulnerabilities` y no se levanta error

## ADDED Requirements

### Requirement: NVD CVE catalog with structured affected versions

El catálogo `cve_entries` SHALL almacenar, para cada CVE, la lista de versiones afectadas como JSON estructurado. Cada elemento tendrá `cpe` (string CPE 2.3 original), y opcionalmente `version` (versión exacta extraída del CPE), `start_inc`, `start_exc`, `end_inc`, `end_exc` (límites del rango). Solo SHALL conservarse entradas cuyo CPE product sea `bitcoin:bitcoin` (Bitcoin Core).

#### Scenario: Refresh almacena rango estructurado
- **WHEN** `NVDService._refresh()` recibe un CVE con `cpeMatch.versionStartIncluding = "0.20.0"` y `versionEndExcluding = "0.21.2"`
- **THEN** la entrada en `cve_entries.affected_versions` incluye un objeto con `start_inc = "0.20.0"` y `end_exc = "0.21.2"`

#### Scenario: Refresh descarta CPEs ajenos a Bitcoin Core
- **WHEN** un CVE devuelve `cpe:2.3:a:copay:copay_bitcoin_wallet:*` como única entrada
- **THEN** la CVE se omite del catálogo (no se inserta fila en `cve_entries`)

### Requirement: Backfill command for CVE linking

El sistema SHALL exponer el subcomando CLI `python -m src.db.cli db-link-cves` que recorre todos los nodos persistidos y aplica el matcher CVE para crear/resolver enlaces en `node_vulnerabilities`.

#### Scenario: Backfill puebla nodos existentes
- **WHEN** la BD contiene 412 nodos sin enlaces y `cve_entries` poblado, y se ejecuta `db-link-cves`
- **THEN** se crean filas en `node_vulnerabilities` para todos los pares (nodo, CVE) cuya versión esté cubierta, y el comando reporta el conteo de enlaces creados y resueltos

#### Scenario: Backfill limitado a un scan
- **WHEN** se invoca `db-link-cves --scan-id 5`
- **THEN** solo se procesan los nodos asociados al scan 5 (vía `scan_nodes`)

## REMOVED Requirements

### Requirement: Legacy `vulnerabilities` table as primary CVE store

**Reason:** El catálogo NVD (`cve_entries`) ya cubre toda la información de CVEs y se mantiene fresco vía `NVDService`. Mantener una tabla paralela `vulnerabilities` introduce dos fuentes de verdad y bloquea el matching automático.

**Migration:** Una revisión Alembic copia los enlaces existentes en `node_vulnerabilities` mapeando `vulnerabilities.cve_id` → `cve_entries.cve_id`; los que no encuentren equivalente se descartan con log. Tras la copia se dropean la columna `vulnerability_id` y la tabla `vulnerabilities`. Tras el deploy se ejecuta `python -m src.db.cli db-link-cves` para repoblar enlaces de nodos preexistentes.
