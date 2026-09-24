---
name: cortex-xdr-triage
description: Investigación y triage de incidentes en Cortex XDR usando el MCP cortex-xdr. Úsalo cuando el usuario pida revisar casos/incidentes abiertos, analizar un incidente o alerta, saber qué usuario/equipo está involucrado, qué gatilló un caso, qué ha pasado y cómo mitigarlo, hacer threat hunting con XQL, o generar un dashboard/tablero SOC de los casos prioritarios. Solo Cortex XDR.
---

# Cortex XDR — Triage e investigación de incidentes

Guía para investigar y priorizar incidentes de Cortex XDR con el MCP `cortex-xdr`, de forma
**eficiente en tokens** y con salidas accionables. Trabaja en español, con términos técnicos en inglés.

## Principios

1. **Resumen antes que detalle.** Trae primero la lista de incidentes/casos y prioriza; recién
   entonces profundiza en los prioritarios. No hagas fetch masivo de todo.
2. **Datos completos, no inventados.** Nunca inventes IDs, hosts, usuarios ni hashes. Si un dato
   no viene de una tool, dilo. Preserva los IOCs **verbatim**.
3. **Seguridad primero.** Las tools de *lectura* corren libremente. Cualquier acción de
   **contención o cambio** (aislar, bloquear, cuarentena, cerrar casos, cambiar políticas)
   **se confirma con el usuario antes de ejecutarla** y se explica el impacto (blast radius).
4. **Nunca** muestres ni registres la API key.

## Flujo de trabajo

### 1. Listar y priorizar
- `get_incidents` (o `get_cases` / `get_issues`) filtrando por estado abierto / bajo investigación.
- Ordena por **score** y **severidad**. Identifica críticos, altos y sin asignar.
- Presenta un resumen corto: cuántos críticos/altos/medios y cuáles requieren atención YA
  (score alto + sin asignar, o infraestructura crítica aunque el score sea medio).

### 2. Investigar cada incidente prioritario
Para cada uno, enriquece con lo mínimo necesario:
- `get_incident_details` → resumen, alertas asociadas, hosts, MITRE.
- `get_alerts` (con límite) → qué disparó el caso, procesos, líneas de comando.
- `get_endpoint_details` / `get_endpoint_context` → **equipo/host** y **usuario** afectado.
- `build_incident_timeline` → **qué ha pasado** (secuencia del ataque).
- `xql_run_query` (`xql_get_results`) → detalle puntual (p. ej. procesos, conexiones, logins).
- Cuando aplique: `correlate_ioc`, `get_wildfire_verdict`, `hunt_*` (persistence, lateral_movement,
  credential_dumping, suspicious_powershell, etc.).

### 3. Entregar el análisis por incidente
Estructura fija por caso:
- **Usuario** afectado / comprometido.
- **Equipo / Host** (nombre + IP).
- **Qué lo gatilló** (la alerta/técnica inicial).
- **Qué ha pasado** (narrativa breve del timeline + tácticas MITRE ATT&CK).
- **Cómo mitigarlo** — pasos concretos citando las tools reales:
  `isolate_endpoint`, `blocklist_files`, `quarantine_file`, `scan_endpoint`,
  reset de credenciales, bloqueo de IP/dominio, etc. Marca cuáles requieren confirmación.

### 4. (Opcional) Dashboard SOC
Si el usuario quiere un tablero visual como el de la consola de Palo Alto, genera un **Artifact**
usando la plantilla `assets/dashboard-template.html` de este skill:
- Reemplaza el arreglo `INCIDENTS` del `<script>` con los incidentes reales obtenidos (mismos
  campos: `id, sev, status, assignee, title, icon, updated, desc, score, alerts, highsev, hosts,
  wildfire?, tactics[], user, host, hostip, trigger, story, mitigation[]`).
- Ajusta las KPIs (críticos/altos/medios/en investigación) al conteo real.
- Es **dark-first** y theme-aware; no cambies la estructura de estilos, solo los datos.

## Tools de acción (requieren confirmación explícita)
`isolate_endpoint`, `unisolate_endpoint`, `bulk_isolate_endpoints`, `blocklist_files`,
`allowlist_files`, `quarantine_file`, `run_script`, `update_incident`, `resolve_case`,
`assign_policy`, `create_bioc_rule`, `add_iocs`. Explica qué hace y a qué activos afecta; espera el "sí".

## Errores comunes
- 401/403 → revisa `CORTEX_MCP_AUTH_TYPE` (advanced/standard) y las credenciales.
- Solo se ven tools builtin → el MCP debe arrancar con `cwd` en la raíz del repo.
