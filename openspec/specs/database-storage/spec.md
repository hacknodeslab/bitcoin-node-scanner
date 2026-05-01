## ADDED Requirements

### Requirement: Database connection management

El sistema SHALL soportar conexión a PostgreSQL y SQLite mediante URL de conexión estándar. La conexión SHALL usar connection pooling para optimizar rendimiento.

#### Scenario: Conexión exitosa a PostgreSQL
- **WHEN** DATABASE_URL está configurado con `postgresql://user:pass@host:port/dbname`
- **THEN** el sistema establece conexión con pool de conexiones activo

#### Scenario: Conexión exitosa a SQLite
- **WHEN** DATABASE_URL está configurado con `sqlite:///path/to/database.db`
- **THEN** el sistema crea o abre el archivo de base de datos SQLite

#### Scenario: Base de datos no configurada
- **WHEN** DATABASE_URL no está definido
- **THEN** el sistema funciona en modo archivo-only sin intentar conexión a base de datos

#### Scenario: Conexión fallida
- **WHEN** DATABASE_URL está configurado pero la conexión falla
- **THEN** el sistema registra error en log y continúa en modo archivo-only con advertencia

### Requirement: Node persistence

El sistema SHALL persistir información de nodos Bitcoin escaneados con deduplicación por IP y puerto.

#### Scenario: Guardar nodo nuevo
- **WHEN** se escanea un nodo con IP que no existe en la base de datos
- **THEN** se crea registro con IP, puerto, país, ASN, versión, banner, first_seen=now, last_seen=now

#### Scenario: Actualizar nodo existente
- **WHEN** se escanea un nodo con IP que ya existe en la base de datos
- **THEN** se actualiza last_seen, versión, y otros campos cambiantes; first_seen permanece intacto

#### Scenario: Persistir metadatos geográficos
- **WHEN** se guarda un nodo
- **THEN** se almacena country_code, country_name, city, latitude, longitude, asn, asn_name

### Requirement: Scan session tracking

El sistema SHALL crear un registro de sesión de escaneo que agrupa todos los nodos encontrados en una ejecución.

#### Scenario: Crear sesión de escaneo
- **WHEN** se inicia un nuevo escaneo
- **THEN** se crea registro de scan con timestamp, queries ejecutadas, y metadatos de configuración

#### Scenario: Asociar nodos a sesión
- **WHEN** se encuentran nodos durante un escaneo
- **THEN** cada nodo se vincula a la sesión mediante tabla de relación scan_nodes

#### Scenario: Registrar estadísticas de sesión
- **WHEN** finaliza un escaneo
- **THEN** se actualiza la sesión con total_nodes, critical_nodes, credits_used, duration_seconds

### Requirement: Vulnerability tracking

El sistema SHALL registrar vulnerabilidades detectadas en cada nodo enlazándolas a entradas del catálogo NVD (`cve_entries`). El enlace se materializa en la tabla `node_vulnerabilities` mediante la columna `cve_id` (FK a `cve_entries.cve_id`). El enlace SHALL crearse de forma automática durante la persistencia del nodo cuando su `version` esté cubierta por el rango `affected_versions` de alguna entrada CVE filtrada por productos Bitcoin Core (`bitcoin:bitcoin`, `bitcoin:bitcoin_core`, `bitcoincore:bitcoin_core`). Si la versión deja de estar cubierta entre escaneos, el enlace correspondiente SHALL marcarse como resuelto (`resolved_at = now`).

#### Scenario: Registrar vulnerabilidad detectada durante upsert de nodo
- **WHEN** se persiste un nodo con `version = "0.21.0"` y existe un CVE en `cve_entries` cuyo rango cubre `0.21.0`
- **THEN** se crea (o se mantiene activa) una fila en `node_vulnerabilities` con `node_id`, `cve_id`, `detected_at = now`, `detected_version = "0.21.0"`, `resolved_at = NULL`

#### Scenario: Resolver vulnerabilidad cuando el nodo se actualiza
- **WHEN** un nodo previamente enlazado a una CVE se reescanea con una `version` que ya no entra en el rango de afectación
- **THEN** la fila correspondiente en `node_vulnerabilities` recibe `resolved_at = now` y no se duplica

#### Scenario: Consultar vulnerabilidades activas de un nodo
- **WHEN** se solicitan las vulnerabilidades activas de un nodo
- **THEN** se devuelven las CVEs cuyas filas en `node_vulnerabilities` tienen `resolved_at IS NULL`, ordenadas por `cve_entries.cvss_score DESC` (NULLs al final)

#### Scenario: Versión no parseable no genera enlaces
- **WHEN** se persiste un nodo con `version = "Satoshi:dev-build"` (sin triple semver extraíble)
- **THEN** no se crean filas en `node_vulnerabilities` y no se levanta error

### Requirement: NVD CVE catalog with structured affected versions

El catálogo `cve_entries` SHALL almacenar, para cada CVE, la lista de versiones afectadas como JSON estructurado. Cada elemento tendrá `cpe` (string CPE 2.3 original), y opcionalmente `version` (versión exacta extraída del CPE), `start_inc`, `start_exc`, `end_inc`, `end_exc` (límites del rango). Solo SHALL conservarse entradas cuyo CPE product sea Bitcoin Core (`bitcoin:bitcoin`, `bitcoin:bitcoin_core`, `bitcoincore:bitcoin_core`). Las entradas pure catch-all (CPE con `version=*` o `-` y sin bounds de rango) SHALL descartarse para evitar falsos positivos masivos.

#### Scenario: Refresh almacena rango estructurado
- **WHEN** `NVDService._refresh()` recibe un CVE con `cpeMatch.versionStartIncluding = "0.20.0"` y `versionEndExcluding = "0.21.2"`
- **THEN** la entrada en `cve_entries.affected_versions` incluye un objeto con `start_inc = "0.20.0"` y `end_exc = "0.21.2"`

#### Scenario: Refresh descarta CPEs ajenos a Bitcoin Core
- **WHEN** un CVE devuelve `cpe:2.3:a:copay:copay_bitcoin_wallet:*` como única entrada
- **THEN** la CVE se omite del catálogo (no se inserta fila en `cve_entries`)

#### Scenario: Refresh descarta entradas pure catch-all
- **WHEN** un CVE devuelve `cpe:2.3:a:bitcoin:bitcoin_core:*:*:*:*:*:*:*:*` sin `versionStart*` ni `versionEnd*`
- **THEN** esa entrada se descarta y, si la CVE no tiene otras entradas válidas, se omite del catálogo

### Requirement: Backfill command for CVE linking

El sistema SHALL exponer el subcomando CLI `python -m src.db.cli db-link-cves` que recorre todos los nodos persistidos y aplica el matcher CVE para crear/resolver enlaces en `node_vulnerabilities`.

#### Scenario: Backfill puebla nodos existentes
- **WHEN** la BD contiene nodos sin enlaces y `cve_entries` poblado, y se ejecuta `db-link-cves`
- **THEN** se crean filas en `node_vulnerabilities` para todos los pares (nodo, CVE) cuya versión esté cubierta, y el comando reporta el conteo de enlaces creados y resueltos

#### Scenario: Backfill limitado a un scan
- **WHEN** se invoca `db-link-cves --scan-id 5`
- **THEN** solo se procesan los nodos asociados al scan 5 (vía `scan_nodes`)

### Requirement: Bulk operations

El sistema SHALL soportar operaciones bulk para inserción eficiente de grandes volúmenes de datos.

#### Scenario: Inserción bulk de nodos
- **WHEN** se procesan más de 100 nodos en un escaneo
- **THEN** se usa bulk insert en batches de 100 registros para optimizar rendimiento

#### Scenario: Transacciones atómicas
- **WHEN** ocurre error durante inserción bulk
- **THEN** se hace rollback de toda la transacción y se registra error


### Requirement: Example node flag column
The `nodes` table SHALL include an `is_example` column of type `BOOLEAN`, `NOT NULL`, with default `FALSE`, and SHALL be indexed to support efficient `WHERE is_example = ?` filtering.

#### Scenario: Fresh database has the column
- **WHEN** a fresh database is created via SQLAlchemy `Base.metadata.create_all`
- **THEN** the `nodes` table SHALL contain an `is_example` boolean column with `NOT NULL DEFAULT 0` (SQLite) or `NOT NULL DEFAULT FALSE` (PostgreSQL)

#### Scenario: Existing database is upgraded in-place
- **WHEN** the application starts against an existing database whose `nodes` table lacks the `is_example` column
- **THEN** the system SHALL issue an `ALTER TABLE nodes ADD COLUMN is_example BOOLEAN NOT NULL DEFAULT 0` (or PostgreSQL equivalent) and continue startup without manual intervention

#### Scenario: Concurrent startup migrations are serialized
- **WHEN** two processes invoke `init_db()` concurrently against the same PostgreSQL instance
- **THEN** the system SHALL acquire `pg_advisory_xact_lock` before issuing any DDL, hold it for the duration of `Base.metadata.create_all` plus the additive migration, and release it on transaction commit/rollback so only one process runs DDL at a time

#### Scenario: DDL failures fail fast
- **WHEN** `Base.metadata.create_all` or the additive migration raises any exception during `init_db()`
- **THEN** the exception SHALL propagate to the caller (the function MUST NOT log-and-return-False) so the surrounding process can exit instead of continuing against a half-migrated schema

#### Scenario: Index exists for filter queries
- **WHEN** the `nodes` table has been created or upgraded
- **THEN** an index SHALL exist on `is_example` so that `SELECT ... WHERE is_example = false` does not require a full table scan
