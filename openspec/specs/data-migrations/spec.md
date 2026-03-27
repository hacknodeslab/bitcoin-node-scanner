## ADDED Requirements

### Requirement: Schema migration system

El sistema SHALL usar Alembic para gestionar migraciones de esquema de base de datos.

#### Scenario: Inicializar sistema de migraciones
- **WHEN** se ejecuta `alembic init` por primera vez
- **THEN** se crea directorio `migrations/` con configuración de Alembic

#### Scenario: Crear migración automática
- **WHEN** se modifican modelos SQLAlchemy
- **THEN** `alembic revision --autogenerate` crea script de migración con cambios detectados

#### Scenario: Aplicar migraciones pendientes
- **WHEN** se ejecuta `alembic upgrade head`
- **THEN** se aplican todas las migraciones pendientes en orden cronológico

#### Scenario: Revertir migración
- **WHEN** se ejecuta `alembic downgrade -1`
- **THEN** se revierte la última migración aplicada

### Requirement: Initial schema creation

El sistema SHALL crear el esquema inicial de base de datos mediante migración.

#### Scenario: Crear tablas iniciales
- **WHEN** se aplica migración inicial en base de datos vacía
- **THEN** se crean tablas: nodes, scans, scan_nodes, vulnerabilities, node_vulnerabilities

#### Scenario: Crear índices de rendimiento
- **WHEN** se crean tablas
- **THEN** se crean índices en: nodes.ip, nodes.last_seen, nodes.country_code, scans.timestamp

#### Scenario: Verificar integridad referencial
- **WHEN** se crean tablas
- **THEN** se definen foreign keys con ON DELETE CASCADE donde apropiado

### Requirement: JSON data import

El sistema SHALL permitir importar datos históricos de archivos JSON existentes.

#### Scenario: Importar archivo de nodos JSON
- **WHEN** se ejecuta `python -m src.database import path/to/nodes.json`
- **THEN** se parsean nodos del JSON y se insertan en base de datos con deduplicación

#### Scenario: Importar directorio de escaneos
- **WHEN** se ejecuta `python -m src.database import-dir output/`
- **THEN** se procesan todos los archivos JSON del directorio creando sesiones de escaneo

#### Scenario: Manejar duplicados en importación
- **WHEN** se importa JSON con nodos que ya existen
- **THEN** se actualizan campos cambiantes y se preserva first_seen original

#### Scenario: Reportar progreso de importación
- **WHEN** se ejecuta importación de datos
- **THEN** se muestra barra de progreso y estadísticas finales (imported, updated, errors)

### Requirement: Migration safety

El sistema SHALL garantizar seguridad en migraciones de producción.

#### Scenario: Migración con verificación previa
- **WHEN** se ejecuta migración en producción
- **THEN** se verifica backup reciente existe antes de proceder

#### Scenario: Migración transaccional
- **WHEN** falla una migración a mitad de ejecución
- **THEN** se hace rollback automático dejando base de datos en estado anterior

#### Scenario: Registro de migraciones
- **WHEN** se aplica una migración
- **THEN** se registra en tabla alembic_version con timestamp y checksum

### Requirement: Schema version tracking

El sistema SHALL rastrear versión actual del esquema.

#### Scenario: Consultar versión de esquema
- **WHEN** se ejecuta `alembic current`
- **THEN** se muestra identificador de la migración actualmente aplicada

#### Scenario: Verificar migraciones pendientes
- **WHEN** se inicia la aplicación
- **THEN** se verifica si hay migraciones pendientes y se muestra advertencia si las hay

#### Scenario: Historial de migraciones
- **WHEN** se ejecuta `alembic history`
- **THEN** se muestra lista completa de migraciones con estado (aplicada/pendiente)
