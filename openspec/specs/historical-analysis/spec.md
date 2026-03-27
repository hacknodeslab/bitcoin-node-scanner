## ADDED Requirements

### Requirement: Vulnerability trend analysis

El sistema SHALL permitir analizar tendencias de vulnerabilidades a lo largo del tiempo.

#### Scenario: Tendencia de vulnerabilidades por período
- **WHEN** se solicita análisis de vulnerabilidades para rango de fechas
- **THEN** se retorna conteo de nodos vulnerables agrupados por día/semana/mes

#### Scenario: Comparación entre períodos
- **WHEN** se comparan dos períodos de tiempo
- **THEN** se muestra diferencia porcentual en nodos vulnerables, nuevos CVEs detectados, y nodos remediados

#### Scenario: Top vulnerabilidades activas
- **WHEN** se solicitan vulnerabilidades más comunes
- **THEN** se retorna lista ordenada por cantidad de nodos afectados con CVE_id, count, y severity

### Requirement: Version distribution history

El sistema SHALL rastrear la distribución de versiones de Bitcoin Core a lo largo del tiempo.

#### Scenario: Distribución de versiones en fecha específica
- **WHEN** se solicita distribución de versiones para una fecha
- **THEN** se retorna porcentaje de nodos por versión mayor (0.21.x, 0.22.x, etc.) en esa fecha

#### Scenario: Evolución de adopción de versiones
- **WHEN** se solicita evolución de versión específica
- **THEN** se muestra gráfico de adopción (porcentaje de nodos) desde primera detección hasta ahora

#### Scenario: Tiempo promedio de actualización
- **WHEN** se analiza comportamiento de actualización
- **THEN** se calcula tiempo promedio que tardan nodos en actualizar a versiones nuevas

### Requirement: Geographic distribution tracking

El sistema SHALL mantener histórico de distribución geográfica de nodos.

#### Scenario: Mapa histórico por país
- **WHEN** se solicita distribución por país para rango de fechas
- **THEN** se retorna conteo de nodos por país con cambio respecto a período anterior

#### Scenario: Concentración por ASN
- **WHEN** se analiza concentración de infraestructura
- **THEN** se identifican ASNs con mayor cantidad de nodos y su evolución temporal

#### Scenario: Nuevos nodos por región
- **WHEN** se solicitan nodos nuevos por región
- **THEN** se listan nodos detectados por primera vez en período, agrupados por país

### Requirement: Node lifecycle tracking

El sistema SHALL rastrear el ciclo de vida de nodos individuales.

#### Scenario: Historial de nodo específico
- **WHEN** se consulta historial de una IP
- **THEN** se muestra timeline con first_seen, cambios de versión, vulnerabilidades detectadas, last_seen

#### Scenario: Nodos desaparecidos
- **WHEN** se solicitan nodos no vistos en X días
- **THEN** se listan nodos con last_seen anterior a threshold configurado

#### Scenario: Tasa de churn
- **WHEN** se analiza estabilidad de la red
- **THEN** se calcula porcentaje de nodos nuevos vs desaparecidos por período

### Requirement: Statistical queries

El sistema SHALL proveer queries estadísticas agregadas para dashboards y reportes.

#### Scenario: Resumen ejecutivo
- **WHEN** se solicita resumen de período
- **THEN** se retorna: total_nodes, vulnerable_nodes, critical_nodes, new_nodes, updated_nodes, countries, top_asns

#### Scenario: Métricas de seguridad
- **WHEN** se calculan métricas de seguridad
- **THEN** se incluye: vulnerability_rate, exposed_rpc_rate, dev_version_rate, average_node_age

#### Scenario: Exportar datos históricos
- **WHEN** se solicita exportación de datos históricos
- **THEN** se genera CSV/JSON con datos filtrados por rango de fechas y criterios
