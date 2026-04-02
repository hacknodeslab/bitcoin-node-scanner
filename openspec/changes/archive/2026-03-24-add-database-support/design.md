## Context

El Bitcoin Node Scanner actualmente almacena resultados de escaneo en archivos JSON en el directorio `output/`. Esta aproximación funciona para escaneos individuales pero tiene limitaciones significativas:

- No permite consultas estructuradas sobre datos históricos
- No hay deduplicación de nodos entre escaneos
- No se pueden detectar tendencias de vulnerabilidades a lo largo del tiempo
- El rendimiento degrada con volúmenes grandes de datos
- No hay integridad referencial entre entidades relacionadas

El proyecto usa Python 3.8+, tiene 83% de cobertura de tests, y sigue patrones de diseño modulares con clases separadas para Scanner, Analyzer, y Reporter.

## Goals / Non-Goals

**Goals:**
- Persistencia estructurada de nodos, escaneos, y vulnerabilidades en base de datos relacional
- Consultas eficientes para análisis histórico y detección de tendencias
- Soporte dual PostgreSQL (producción) y SQLite (desarrollo/tests)
- Sistema de migraciones para evolución controlada del esquema
- Integración no-intrusiva con el flujo de escaneo existente
- Mantener compatibilidad con exportación a JSON/CSV existente

**Non-Goals:**
- Reemplazar completamente la exportación a archivos (se mantiene como opción)
- Implementar API REST (será un cambio futuro separado)
- Soporte para bases de datos NoSQL (MongoDB, etc.)
- Replicación o clustering de base de datos
- Interfaz web para consultas (será un cambio futuro)

## Decisions

### 1. SQLAlchemy 2.0 como ORM

**Decisión**: Usar SQLAlchemy 2.0 con patrón declarativo para modelos de datos.

**Alternativas consideradas**:
- Raw SQL con psycopg2: Más control pero más código boilerplate y propenso a errores
- Django ORM: Demasiado pesado, requiere estructura Django completa
- Peewee: Menos maduro, comunidad más pequeña
- SQLModel: Buena opción pero menos documentación y ecosistema

**Rationale**: SQLAlchemy es el estándar de facto en Python, soporta múltiples backends (PostgreSQL/SQLite), tiene excelente documentación, y la versión 2.0 ofrece tipado mejorado y async opcional.

### 2. Alembic para migraciones

**Decisión**: Usar Alembic para gestión de migraciones de esquema.

**Alternativas consideradas**:
- Migraciones manuales con SQL: Difícil de rastrear y revertir
- Flask-Migrate: Requiere Flask
- Django migrations: Requiere Django

**Rationale**: Alembic es el compañero natural de SQLAlchemy, soporta migraciones automáticas y manuales, y tiene sistema de revisiones con historial.

### 3. Esquema de datos normalizado

**Decisión**: Usar esquema normalizado con tablas separadas para nodos, escaneos, vulnerabilidades, y relaciones.

```
scans (id, timestamp, query_used, total_nodes, credits_used)
  |
  +-- scan_nodes (scan_id, node_id) -- relación muchos a muchos
  |
nodes (id, ip, port, first_seen, last_seen, country, asn, version, ...)
  |
  +-- node_vulnerabilities (node_id, vulnerability_id, detected_at)
  |
vulnerabilities (id, cve_id, affected_versions, severity, description)
```

**Alternativas consideradas**:
- Esquema desnormalizado: Mejor rendimiento de lectura pero redundancia y problemas de actualización
- Documento JSON por nodo: Flexible pero difícil de consultar eficientemente

**Rationale**: Normalización permite consultas flexibles, evita redundancia, y facilita análisis relacional. El overhead de JOINs es aceptable para el volumen esperado.

### 4. Connection pooling con pool_pre_ping

**Decisión**: Usar connection pool de SQLAlchemy con `pool_pre_ping=True` para manejo de conexiones stale.

**Rationale**: Previene errores por conexiones cerradas, especialmente importante para escaneos de larga duración.

### 5. Patrón Repository para acceso a datos

**Decisión**: Implementar clases Repository que encapsulan operaciones de base de datos.

```python
class NodeRepository:
    def upsert(self, node_data: dict) -> Node
    def find_by_ip(self, ip: str) -> Optional[Node]
    def find_vulnerable(self, since: datetime) -> List[Node]

class ScanRepository:
    def create(self, metadata: dict) -> Scan
    def get_statistics(self, start: datetime, end: datetime) -> dict
```

**Rationale**: Separa lógica de negocio de acceso a datos, facilita testing con mocks, y centraliza queries.

### 6. Modo opcional de base de datos

**Decisión**: La base de datos será opt-in mediante variable de entorno `DATABASE_URL`. Si no está configurada, el scanner funciona como antes (solo archivos).

**Rationale**: Mantiene compatibilidad hacia atrás, permite uso simple sin infraestructura adicional.

## Risks / Trade-offs

**[Complejidad adicional]** → El proyecto crece en dependencias y configuración. Mitigation: Documentación clara, SQLite como opción simple para desarrollo.

**[Rendimiento de escritura]** → Insertar muchos nodos puede ser lento. Mitigation: Usar bulk inserts con `session.bulk_save_objects()`.

**[Migración de datos existentes]** → Usuarios con datos en JSON querrán importarlos. Mitigation: Script de migración `scripts/import_json_to_db.py`.

**[Dependencia de PostgreSQL en CI]** → Tests de integración requieren PostgreSQL. Mitigation: Usar SQLite para tests unitarios, PostgreSQL service en GitHub Actions solo para integration tests.

**[Schema drift]** → Cambios manuales a la base de datos pueden causar problemas. Mitigation: Alembic migrations como única forma de modificar esquema, documentación de proceso.

## Migration Plan

1. **Fase 1 - Infraestructura**: Agregar dependencias, crear modelos SQLAlchemy, configurar Alembic
2. **Fase 2 - Integración**: Modificar scanner para guardar en DB cuando DATABASE_URL existe
3. **Fase 3 - Queries**: Implementar consultas de análisis histórico
4. **Fase 4 - CLI**: Agregar comandos para consultas desde terminal
5. **Fase 5 - Documentación**: Guías de setup y uso

**Rollback**: Si DATABASE_URL no está configurada, el sistema funciona exactamente como antes. No hay cambios breaking.
