## Context

El proyecto ya descarga CVEs de NVD a `cve_entries` y persiste nodos con su `version` (string como `Satoshi:25.0.0`). Pero entre ambos no hay puente:

- `node_vulnerabilities.vulnerability_id` → FK a `vulnerabilities` (modelo legacy con 1 fila de prueba), no a `cve_entries`.
- `VulnerabilityRepository.find_affecting_version()` hace `if version in affected_versions`. Como `affected_versions` guarda **CPE 2.3** (`cpe:2.3:a:bitcoin:bitcoin:*:*:*:*:*:*:*:*`), nunca matchea contra `"25.0.0"`.
- `NVDClient._parse_cve` descarta los rangos `versionStartIncluding` / `versionEndExcluding` de `cpeMatch`, así que la información necesaria para matchear ni siquiera llega a la BD.
- Nada en `scanner_integration.py` invoca matching tras un upsert.

Hay que decidir qué hacer con la tabla legacy `vulnerabilities`, cómo modelar los rangos CPE, y dónde correr el matching para no inflar el coste por nodo escaneado.

## Goals / Non-Goals

**Goals:**
- Cada nodo persistido SHALL tener filas en `node_vulnerabilities` para cada CVE NVD cuyo rango de versiones incluya su `version`.
- El catálogo NVD (`cve_entries`) es la única fuente de verdad sobre CVEs.
- Matching ocurre dentro de la sesión de scan (latencia incremental despreciable) y mediante un comando CLI de backfill.
- Cuando un nodo cambia de versión a una no afectada, los enlaces previos quedan `resolved_at`.

**Non-Goals:**
- No vamos a inventar CVEs propios ni a soportar otra fuente que no sea NVD.
- No se implementa parser CPE 2.3 completo — solo el subconjunto necesario para Bitcoin Core (`cpe:2.3:a:bitcoin:bitcoin:<version>:...`) más los rangos `versionStartIncluding`/`-Excluding` y `versionEndIncluding`/`-Excluding`.
- No se reescriben los tests del scanner desde cero — se añaden los tests del matcher.

## Decisions

### D1. Eliminar la tabla `vulnerabilities` legacy y repuntar la FK a `cve_entries`

El modelo `Vulnerability` actual existía antes de NVD y no se usa en producción. Mantener dos tablas paralelas no aporta nada.

- `NodeVulnerability.vulnerability_id` se renombra a `cve_entry_id` con FK a `cve_entries.id`.
- `VulnerabilityRepository` se reescribe sobre `CVEEntry`. Las funciones `link_to_node`, `resolve_for_node`, `get_active_for_node`, `get_nodes_by_vulnerability` se conservan firma-compatibles con `CVEEntry` en lugar de `Vulnerability`.
- La migración Alembic descarta `vulnerabilities` después de migrar la única fila existente (si su `cve_id` matchea algo en `cve_entries`, se reapunta el enlace; si no, se descarta).

**Alternativa considerada:** mantener `vulnerabilities` como vista materializada de `cve_entries`. Rechazada — añade una capa sin valor y hace que cualquier escritura desde NVD requiera doble escritura.

### D2. Enriquecer `affected_versions` con rangos CPE estructurados

`NVDClient._parse_cve` empezará a leer también `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding` de cada `cpeMatch`. La columna `cve_entries.affected_versions` (JSON text) pasa a almacenar:

```json
[
  {"cpe": "cpe:2.3:a:bitcoin:bitcoin:0.21.0:...", "version": "0.21.0"},
  {"cpe": "cpe:2.3:a:bitcoin:bitcoin:*:*:...", "start_inc": "0.20.0", "end_exc": "0.21.2"}
]
```

Solo se conservan entradas cuyo CPE product sea `bitcoin:bitcoin` o `bitcoincore:bitcoin_core` (filtro estricto para evitar matches contra `copay`, etc., que hoy contaminan el set).

**Alternativa considerada:** parsear CPE en cada match. Rechazada — coste por nodo se dispara y el parsing es estable (se puede pagar una vez al refrescar el catálogo).

### D3. Matcher con índice precomputado por sesión

Tras `NVDService._refresh()` (o en arranque cuando el caché está caliente), el servicio expone:

```python
class CVEMatcher:
    def matches_for(self, version: str) -> list[int]:  # cve_entry ids
```

El matcher se construye una vez por scan (en `DatabaseScannerMixin.__init__` o lazy en el primer upsert), parseando todas las entradas filtradas y evaluando rango. Coste: O(N_cves) por construcción + O(N_cves) por nodo en el peor caso, pero en la práctica un dict `version_exact → ids` cubre la mayoría y solo los rangos pasan al loop.

**Alternativa considerada:** SQL `LIKE`/JSON queries. Rechazada — Postgres y SQLite divergen en JSON, y la cardinalidad (≤ unos cientos de CVEs) hace trivial el matcher en memoria.

### D4. Hook de matching dentro del flujo de upsert

`DatabaseScannerMixin._save_node_to_db` y `_save_nodes_bulk` llaman al matcher tras escribir el nodo:

1. Calcular `expected_cve_ids = matcher.matches_for(node.version)`.
2. Leer `current_cve_ids = SELECT cve_entry_id FROM node_vulnerabilities WHERE node_id=? AND resolved_at IS NULL`.
3. `to_add = expected - current` → insertar.
4. `to_resolve = current - expected` → `UPDATE ... SET resolved_at = now()`.

Esto cubre el caso de nodo que cambia de `0.20.0` (vulnerable) a `25.0.0` (limpio) entre scans.

### D5. Comando CLI `db-link-cves` para backfill

`python -m src.db.cli db-link-cves [--scan-id N]` recorre nodos persistidos y aplica el mismo algoritmo. Sirve para:
- La migración inicial (412 nodos ya en BD).
- Reparación tras un refresco de NVD que añada o modifique CVEs.

### D6. Exposición en API

`/api/v1/nodes/{id}` añade `cves: [{cve_id, severity, cvss_score, detected_at}]`. La lista paginada `/api/v1/nodes` añade `cve_count` y `top_cve` (el de mayor `cvss_score`) — no la lista completa, para no inflar la respuesta. `/api/v1/vulnerabilities/{cve_id}/nodes` se reescribe sobre `CVEEntry`.

## Risks / Trade-offs

- **CPE strings con `*` para version**: representan "todas las versiones del producto" — tras filtrar por producto `bitcoin:bitcoin`, eso significa "afecta a todas las versiones de Bitcoin Core". Riesgo: matchear CVEs muy antiguos contra todos los nodos modernos. → Mitigación: si una entrada CPE tiene `version=*` y no incluye rango (`start_*`/`end_*`), se considera *unbounded* y solo matchea cuando explícitamente no hay otra entrada más específica para esa CVE. Si la CVE tiene **alguna** entrada con rango, se prefieren las entradas con rango.
- **Versión del nodo no parseable**: `node.version` viene del banner Shodan y a veces es `Satoshi:0.21.99-dev` o `Knots:25.0.0`. → Mitigación: usar `src/utils.py:71` (regex `(\d+).(\d+).(\d+)`) para extraer la triple semver; si no se puede, no se matchea (ya cubierto por el booleano `is_dev_version`).
- **Migración destructiva**: dropear `vulnerabilities`. → Mitigación: la fila existente se mapea por `cve_id` o se descarta con log. Es un proyecto de investigación, no hay datos de producción que perder; aun así, la migración Alembic incluye `downgrade()`.
- **Coste por scan**: ~100 CVEs × 412 nodos = 41 200 comparaciones — irrelevante. Si el catálogo crece a miles, el matcher sigue siendo lineal por nodo, aceptable.

## Migration Plan

1. Alembic revision: añadir columna `cve_entry_id` a `node_vulnerabilities`, copiar `vulnerability_id` mapeado por `cve_id` cuando exista en `cve_entries`, dropear FK antigua y la columna, dropear tabla `vulnerabilities`.
2. Tras el deploy, ejecutar `python -m src.db.cli db-link-cves` una vez para poblar enlaces de los 412 nodos existentes.
3. Rollback: el `downgrade()` recrea `vulnerabilities` vacía y vuelve a poner `vulnerability_id`. Los enlaces creados por matcher se pierden (aceptable — son derivables).

## Open Questions

- ¿Queremos exponer también CVEs *resueltas* en el detalle del nodo (historial), o solo activas? Por ahora: solo activas en `/api/v1/nodes/{id}`, con `?include_resolved=true` opcional.
- ¿El backfill `db-link-cves` debe ejecutarse automáticamente tras `_refresh` del catálogo NVD, o solo a mano? Propuesta: auto-trigger si el refresh detectó nuevas filas, configurable por flag `NVD_AUTO_RELINK` (default true).
