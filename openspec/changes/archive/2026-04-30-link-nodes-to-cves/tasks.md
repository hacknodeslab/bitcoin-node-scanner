## 1. Modelo de datos y migración

- [x] 1.1 Modificar `src/db/models.py`: en `NodeVulnerability` renombrar `vulnerability_id` → `cve_entry_id` con FK a `cve_entries.id`; eliminar la clase `Vulnerability` y sus relaciones; añadir `relationship` desde `Node` y `CVEEntry` hacia `NodeVulnerability` por la nueva columna.
- [x] 1.2 Crear revisión Alembic en `alembic/versions/` que: (a) añada `cve_entry_id` a `node_vulnerabilities`, (b) copie enlaces vigentes mapeando `vulnerabilities.cve_id` → `cve_entries.cve_id` (descartando los huérfanos con log), (c) drop de la FK y columna `vulnerability_id`, (d) drop de la tabla `vulnerabilities`. Implementar `downgrade()` correspondiente.
- [x] 1.3 Actualizar `src/db/__init__.py` y todos los `import` que referencian `Vulnerability` para que usen `CVEEntry` (ej. `src/db/analysis.py`).

## 2. Parsing CPE y catálogo NVD

- [x] 2.1 En `src/nvd/client.py:_parse_cve` extraer de cada `cpeMatch` los campos `criteria` (CPE), `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`. Filtrar solo aquellos cuyo CPE product sea `bitcoin:bitcoin`. Si tras el filtro no queda ninguna entrada, retornar `None` para esa CVE (será omitida).
- [x] 2.2 Cambiar `CVEEntry.affected_versions` (en `src/nvd/models.py`) a `List[Dict[str, str]]` con claves `cpe`, `version` (opcional), `start_inc`, `start_exc`, `end_inc`, `end_exc` (todas opcionales).
- [x] 2.3 En `src/nvd/service.py:_refresh` saltar (no insertar) CVEs cuya lista filtrada esté vacía. Serializar la nueva estructura como JSON.
- [x] 2.4 Tests en `tests/test_nvd_client.py` (crear si no existe) que verifiquen: (a) extracción de rango con `versionStartIncluding`/`versionEndExcluding`, (b) descarte de CPEs ajenos a Bitcoin Core, (c) CVE 100% no-bitcoin se omite.

## 3. Matcher de versiones

- [x] 3.1 Crear `src/nvd/matcher.py` con `class CVEMatcher`: constructor recibe lista de `CVEEntryModel`, parsea su `affected_versions`, y construye índices internos (`exact_index: dict[tuple[int,int,int], set[int]]` y `range_index: list[(start, end, cve_entry_id)]`). Método `matches_for(version: str) -> set[int]` extrae la triple semver vía regex (`src/utils.py:71`); si no hay match retorna `set()`. Reglas: si una CVE tiene alguna entrada con rango/versión específica, las entradas `version=*` sin rango se ignoran para esa CVE (evita catch-all).
- [x] 3.2 Helper de comparación semver `_cmp(a, b)` que compare tuplas `(major, minor, patch)`; tratar versiones vacías o `*` como bordes abiertos.
- [x] 3.3 Tests en `tests/test_cve_matcher.py`: (a) match exacto, (b) match en rango cerrado, (c) versión justo en el límite excluyente no matchea, (d) `version=*` sin rango actúa como catch-all solo si la CVE no tiene otra entrada más específica, (e) versión inválida del nodo no produce errores.

## 4. Reescritura del repositorio de vulnerabilidades

- [x] 4.1 Reescribir `src/db/repositories/vulnerability_repository.py` para operar sobre `CVEEntry` en lugar de `Vulnerability`. Conservar firmas: `link_to_node(node, cve_entry, detected_version=None)`, `resolve_for_node(node, cve_entry)`, `resolve_all_for_node(node)`, `get_active_for_node(node)`, `get_nodes_by_cve(cve_entry)`, `count_affected_nodes(cve_entry)`. Eliminar `create`, `find_by_cve_id` (delegar a query directa sobre `CVEEntry`), `find_affecting_version` (sustituido por `CVEMatcher`).
- [x] 4.2 Añadir método `sync_node_links(node, expected_cve_entry_ids: set[int]) -> tuple[int, int]` que aplique el diff active-vs-expected: inserta los nuevos, marca `resolved_at` los que sobran. Devuelve `(added, resolved)`.
- [x] 4.3 Actualizar `src/db/analysis.py:188-194` (consulta de top vulnerabilities) para usar `CVEEntry` y `cve_entry_id`.
- [x] 4.4 Tests en `tests/test_vulnerability_repository.py` (crear o ampliar) cubriendo `sync_node_links` con creación, resolución y no-op.

## 5. Hook de matching en el flujo de scan

- [x] 5.1 En `src/db/scanner_integration.py:DatabaseScannerMixin` añadir atributo `_cve_matcher: Optional[CVEMatcher] = None` y método `_get_cve_matcher(session)` que lo construye lazy a partir de `select(CVEEntry)`.
- [x] 5.2 En `_save_node_to_db`, tras `node_repo.upsert(...)`, calcular `expected = matcher.matches_for(node.version)` y llamar a `vulnerability_repository.sync_node_links(node, expected)`.
- [x] 5.3 En `_save_nodes_bulk`, tras el bulk upsert, releer los nodos persistidos y llamar a `sync_node_links` por cada uno (usar la misma sesión; coste lineal aceptable según design D3).
- [x] 5.4 Test de integración en `tests/test_db_scanner_integration.py`: scan que persiste un nodo `0.20.0` con CVE en rango → fila activa en `node_vulnerabilities`; reescaneo del mismo nodo con `25.0.0` → fila previa con `resolved_at` set.

## 6. Comando CLI de backfill

- [x] 6.1 Añadir subcomando `db-link-cves` a `src/db/cli.py` con flag opcional `--scan-id INT`. Implementación: construye un `CVEMatcher` único, recorre nodos (todos o los del scan), llama a `sync_node_links` por cada uno, y al final imprime totales (`linked`, `resolved`, `skipped_unparseable`).
- [x] 6.2 Documentar el comando en `CLAUDE.md` (sección Common Commands) y en `README.md` si lista comandos CLI.
- [x] 6.3 Test en `tests/test_db_cli.py` (crear si no existe) que invoque el comando contra una BD seed con N nodos y M CVEs y verifique los enlaces resultantes.

## 7. Auto-relink tras refresh NVD

- [x] 7.1 En `NVDService._refresh`, detectar si hubo cambios (filas insertadas o `last_modified` actualizadas). Si `os.getenv("NVD_AUTO_RELINK", "true").lower() in {"1","true","yes"}` y hubo cambios, invocar el equivalente programático del backfill (sin pasar por CLI).
- [x] 7.2 Documentar la variable `NVD_AUTO_RELINK` en `CLAUDE.md` (sección Required/Optional Environment Variables).

## 8. Exposición en API

- [x] 8.1 Añadir endpoint `GET /api/v1/nodes/{id}` en `src/web/routers/nodes.py` que devuelva el nodo + lista de CVEs (vía `vulnerability_repository.get_active_for_node`). Añadir query param `include_resolved: bool = False`.
- [x] 8.2 En el response model de la lista paginada `GET /api/v1/nodes`, añadir `cve_count` y `top_cve`. Usar una subconsulta agregada para no incurrir en N+1.
- [x] 8.3 Reescribir `src/web/routers/vulnerabilities.py` para añadir `GET /api/v1/vulnerabilities/{cve_id}/nodes`. Si el `cve_id` no existe en `cve_entries`, retornar 404.
- [x] 8.4 Tests en `tests/test_web_api.py`: detalle de nodo con/sin CVEs, lista con `cve_count`/`top_cve`, endpoint de nodos por CVE incluyendo el caso 404.

## 9. Migración manual y verificación

- [x] 9.1 Ejecutar `alembic upgrade head` localmente contra `bitcoin_scanner.db` y verificar que `vulnerabilities` desaparece y `node_vulnerabilities.cve_entry_id` existe.
- [x] 9.2 Ejecutar `python -m src.db.cli db-link-cves` y comprobar (`sqlite3` o endpoint) que los 412 nodos reciben enlaces consistentes.
- [x] 9.3 Levantar `python -m src.web.main` + `pnpm dev` y verificar manualmente en el detalle de nodo del dashboard que las CVEs se renderizan.

## 10. Validación final

- [x] 10.1 `python -m pytest tests/ -v` en verde.
- [x] 10.2 `openspec validate link-nodes-to-cves --strict` sin errores.
