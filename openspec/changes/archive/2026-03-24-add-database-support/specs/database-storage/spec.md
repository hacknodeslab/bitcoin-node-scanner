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

El sistema SHALL registrar vulnerabilidades detectadas en cada nodo con referencia a CVEs conocidos.

#### Scenario: Registrar vulnerabilidad detectada
- **WHEN** se detecta que un nodo ejecuta versión vulnerable
- **THEN** se crea relación node_vulnerability con CVE_id, severity, detected_at

#### Scenario: Actualizar estado de vulnerabilidad
- **WHEN** un nodo previamente vulnerable se actualiza a versión segura
- **THEN** se marca la vulnerabilidad como resolved_at=now

#### Scenario: Consultar nodos vulnerables activos
- **WHEN** se solicitan nodos con vulnerabilidades no resueltas
- **THEN** se retornan nodos donde resolved_at IS NULL

### Requirement: Bulk operations

El sistema SHALL soportar operaciones bulk para inserción eficiente de grandes volúmenes de datos.

#### Scenario: Inserción bulk de nodos
- **WHEN** se procesan más de 100 nodos en un escaneo
- **THEN** se usa bulk insert en batches de 100 registros para optimizar rendimiento

#### Scenario: Transacciones atómicas
- **WHEN** ocurre error durante inserción bulk
- **THEN** se hace rollback de toda la transacción y se registra error
