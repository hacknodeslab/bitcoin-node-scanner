## Why

El catálogo NVD se descarga (100 CVEs en `cve_entries`), pero ningún nodo queda enlazado: la tabla `node_vulnerabilities` solo tiene 1 fila de ejemplo creada a mano, y el dashboard muestra "sin vulnerabilidades" para los 412 nodos reales. La causa es doble: (1) `node_vulnerabilities.vulnerability_id` apunta a la tabla legacy `vulnerabilities` y no a `cve_entries`, así que el catálogo NVD vive desconectado del grafo; (2) `scanner_integration.py` nunca compara `node.version` con `affected_versions` tras hacer upsert. El producto promete "scanner + risk analyzer + CVE lookup" pero hoy entrega una vista vacía.

## What Changes

- Unificar el modelo de CVE: el join `node_vulnerabilities` SHALL apuntar a `cve_entries`. **BREAKING** para la tabla `vulnerabilities` legacy — se elimina (o se vacía) y `VulnerabilityRepository` se reescribe sobre `CVEEntry`.
- Tras refrescar el catálogo NVD, el sistema SHALL mantener un índice derivado `version → [cve_id]` para evitar full-scans en cada upsert.
- `DatabaseScannerMixin` SHALL invocar el matcher tras cada upsert de nodo (`_save_node_to_db` y `_save_nodes_bulk`), creando filas en `node_vulnerabilities` para cada CVE cuyo `affected_versions` cubra `node.version`. Los enlaces vigentes que ya no apliquen tras un cambio de versión SHALL marcarse `resolved_at`.
- Añadir un comando CLI `db-link-cves` que reconstruye los enlaces para nodos ya persistidos (backfill puntual y reparación tras un refresco de NVD).
- El endpoint `/api/v1/nodes/{id}` y la respuesta paginada de `/api/v1/nodes` SHALL incluir las CVEs activas por nodo (cve_id, severity, cvss_score) — hoy solo exponen `is_vulnerable` booleano.

## Capabilities

### New Capabilities
*(ninguna — es trabajo sobre capabilities existentes)*

### Modified Capabilities
- `database-storage`: el modelo y el flujo de "Vulnerability tracking" cambian — el join apunta a `cve_entries` y la creación/resolución de enlaces queda definida como parte del ciclo de upsert de nodo.
- `web-api`: la respuesta de nodos incluye CVEs activas; se añade endpoint para forzar el rematching.

## Impact

- Código: `src/db/models.py` (FK de `NodeVulnerability` y posible deprecación de `Vulnerability`), `src/db/repositories/vulnerability_repository.py` (reescritura sobre `CVEEntry`), `src/db/scanner_integration.py` (gancho de matching), `src/nvd/service.py` (índice de versiones tras refresh), `src/db/cli.py` (nuevo subcomando `db-link-cves`), `src/web/routers/nodes.py` y `src/web/routers/vulnerabilities.py` (exposición de CVEs por nodo).
- Datos: requiere migración Alembic (cambio de FK); la fila legacy en `vulnerabilities` se descarta o reasigna al CVE equivalente en `cve_entries`.
- Dashboard (`frontend/`): sin cambios de contrato a nivel de capability nuevo, pero el detalle de nodo empezará a renderizar CVEs reales.
- Pruebas: `tests/test_web_api.py` y los tests del scanner deberán cubrir la nueva vinculación.
