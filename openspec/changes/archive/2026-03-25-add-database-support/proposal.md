## Why

El proyecto actualmente almacena resultados de escaneo en archivos JSON planos, lo que impide realizar análisis históricos, detectar tendencias de vulnerabilidades a lo largo del tiempo, y escalar a volúmenes grandes de datos. Una base de datos permitirá persistencia estructurada, consultas eficientes, y análisis temporal de la seguridad de la red Bitcoin.

## What Changes

- Agregar nuevo módulo `src/database.py` con soporte para PostgreSQL como base de datos principal
- Implementar modelos de datos para nodos, escaneos, vulnerabilidades y estadísticas
- Crear sistema de migraciones para evolución del esquema
- Modificar `BitcoinNodeScanner` para guardar resultados en base de datos además de archivos
- Agregar comandos CLI para consultas históricas y análisis de tendencias
- Implementar conexión pooling para rendimiento óptimo
- Agregar soporte opcional para SQLite como alternativa ligera para desarrollo/pruebas

## Capabilities

### New Capabilities

- `database-storage`: Persistencia de nodos escaneados, vulnerabilidades detectadas, y metadatos de escaneo en PostgreSQL/SQLite
- `historical-analysis`: Consultas para análisis temporal: tendencias de vulnerabilidades, evolución de versiones, distribución geográfica histórica
- `data-migrations`: Sistema de migraciones para evolución del esquema de base de datos

### Modified Capabilities

(ninguna - esta funcionalidad es completamente nueva y no modifica especificaciones existentes)

## Impact

- **Código**: Nuevo módulo `src/database.py`, modificaciones en `scanner.py` para integración
- **Dependencias**: Agregar `sqlalchemy>=2.0`, `psycopg2-binary`, `alembic` a requirements.txt
- **Configuración**: Nuevas variables de entorno para conexión a base de datos (DATABASE_URL)
- **Tests**: Nuevos tests unitarios e integración con base de datos en memoria (SQLite)
- **Documentación**: Actualizar README, crear guía de configuración de base de datos
- **CI/CD**: Agregar servicio PostgreSQL para tests de integración en GitHub Actions
