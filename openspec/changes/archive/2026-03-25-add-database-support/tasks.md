## 1. Setup y Dependencias

- [x] 1.1 Agregar sqlalchemy>=2.0, psycopg2-binary, alembic a requirements.txt
- [x] 1.2 Crear estructura de directorios: src/db/, migrations/
- [x] 1.3 Inicializar Alembic con `alembic init migrations`
- [x] 1.4 Configurar alembic.ini para leer DATABASE_URL de entorno

## 2. Modelos SQLAlchemy

- [x] 2.1 Crear src/db/models.py con clase Base declarativa
- [x] 2.2 Implementar modelo Node con campos: id, ip, port, country_code, country_name, city, lat, lon, asn, asn_name, version, banner, risk_level, first_seen, last_seen
- [x] 2.3 Implementar modelo Scan con campos: id, timestamp, queries_executed, total_nodes, critical_nodes, credits_used, duration_seconds
- [x] 2.4 Implementar modelo Vulnerability con campos: id, cve_id, affected_versions, severity, description
- [x] 2.5 Implementar tabla de relación ScanNode (scan_id, node_id)
- [x] 2.6 Implementar tabla de relación NodeVulnerability (node_id, vulnerability_id, detected_at, resolved_at)
- [x] 2.7 Agregar índices en: nodes.ip, nodes.last_seen, nodes.country_code, scans.timestamp

## 3. Conexión y Session Management

- [x] 3.1 Crear src/db/connection.py con función get_engine() que lee DATABASE_URL
- [x] 3.2 Implementar SessionLocal factory con connection pooling (pool_pre_ping=True)
- [x] 3.3 Implementar context manager get_db_session() para manejo de transacciones
- [x] 3.4 Agregar detección automática de tipo de base de datos (PostgreSQL vs SQLite)
- [x] 3.5 Implementar fallback silencioso cuando DATABASE_URL no está configurado

## 4. Repositorios

- [x] 4.1 Crear src/db/repositories/node_repository.py con NodeRepository
- [x] 4.2 Implementar NodeRepository.upsert() con lógica de deduplicación por IP+port
- [x] 4.3 Implementar NodeRepository.find_by_ip(), find_vulnerable(), find_by_country()
- [x] 4.4 Implementar NodeRepository.bulk_upsert() para inserciones masivas
- [x] 4.5 Crear src/db/repositories/scan_repository.py con ScanRepository
- [x] 4.6 Implementar ScanRepository.create(), complete(), get_by_date_range()
- [x] 4.7 Crear src/db/repositories/vulnerability_repository.py
- [x] 4.8 Implementar VulnerabilityRepository para gestión de CVEs

## 5. Migraciones

- [x] 5.1 Crear migración inicial con todas las tablas y relaciones
- [x] 5.2 Crear script scripts/migrate.py para aplicar migraciones programáticamente
- [x] 5.3 Documentar proceso de migraciones en docs/DATABASE.md

## 6. Integración con Scanner

- [x] 6.1 Modificar BitcoinNodeScanner.__init__() para inicializar conexión DB si disponible
- [x] 6.2 Crear método _save_to_database() en BitcoinNodeScanner
- [x] 6.3 Modificar scan_all_queries() para crear sesión de scan en DB
- [x] 6.4 Modificar parse_node_data() para guardar nodos en DB además de memoria
- [x] 6.5 Actualizar generate_statistics() para guardar estadísticas en DB
- [x] 6.6 Mantener compatibilidad: si no hay DB, funciona igual que antes

## 7. Análisis Histórico

- [x] 7.1 Crear src/db/analysis.py con clase HistoricalAnalyzer
- [x] 7.2 Implementar get_vulnerability_trends(start_date, end_date, granularity)
- [x] 7.3 Implementar get_version_distribution(date) y get_version_evolution(version)
- [x] 7.4 Implementar get_geographic_distribution(start_date, end_date)
- [x] 7.5 Implementar get_node_lifecycle(ip) para historial de nodo específico
- [x] 7.6 Implementar get_summary_statistics(start_date, end_date) para dashboard

## 8. Importación de Datos Existentes

- [x] 8.1 Crear scripts/import_json_to_db.py
- [x] 8.2 Implementar parseo de archivos JSON existentes en output/
- [x] 8.3 Implementar importación con barra de progreso y estadísticas
- [x] 8.4 Manejar duplicados actualizando last_seen y preservando first_seen

## 9. CLI para Consultas

- [x] 9.1 Agregar subcomando `python -m src.scanner db-stats` para estadísticas
- [x] 9.2 Agregar subcomando `python -m src.scanner db-trends` para tendencias
- [x] 9.3 Agregar subcomando `python -m src.scanner db-export` para exportar datos históricos
- [x] 9.4 Agregar subcomando `python -m src.scanner db-import` para importar JSON

## 10. Tests

- [x] 10.1 Crear tests/test_db_models.py con tests de modelos
- [x] 10.2 Crear tests/test_db_repositories.py con tests de repositorios (usando SQLite in-memory)
- [x] 10.3 Crear tests/test_db_analysis.py con tests de análisis histórico
- [x] 10.4 Crear tests/test_db_integration.py con tests de integración scanner+db
- [x] 10.5 Agregar fixtures compartidos para datos de prueba en conftest.py

## 11. CI/CD

- [x] 11.1 Agregar servicio PostgreSQL a .github/workflows/ci.yml
- [x] 11.2 Configurar DATABASE_URL en CI para tests de integración
- [x] 11.3 Agregar job separado para tests de integración con PostgreSQL

## 12. Documentación

- [x] 12.1 Crear docs/DATABASE.md con guía de configuración
- [x] 12.2 Actualizar README.md con sección de base de datos
- [x] 12.3 Documentar variables de entorno nuevas
- [x] 12.4 Agregar ejemplos de consultas SQL útiles
