# Cortex XDR REST API — referencia para MCP (`cortex_send_request`)

Fuente oficial: **Cortex XDR REST API** (Palo Alto Networks). Validado contra un tenant real de Cortex XDR (Standard).

## Reglas de oro (obligatorias)

| Regla | Detalle |
|-------|---------|
| **Método** | Casi todo es **POST**. `healthcheck` es **GET**. |
| **URL** | `https://api-<FQDN>/public_api/v1/<ruta>/` — prefijo `api-` obligatorio, ruta **debe terminar en `/`**. |
| **Body** | `{ "request_data": { ... } }` salvo excepciones documentadas. |
| **Headers** | `Authorization`: API Key · `x-xdr-auth-id`: ID de la key · `Content-Type`: application/json |
| **Paginación** | `search_from` / `search_to` con **span ≤ 100**. |
| **Case-sensitive** | Campos como `platform` y `profile_type` son **case-sensitive** (`Windows` no `windows`). |

## Paths validados contra la API real

### Audit Log ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Audit Management Log | `audits/management_logs/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Audit Agent Report | `audits/agents_reports/` | `{}` | ✅ 200 |

### Authentication Settings ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Auth Settings | `authentication-settings/get/settings/` | `{}` | ✅ 200 |
| Get IdP Metadata | `authentication-settings/get/metadata/` | `{}` | ✅ 200 |

**⚠️ Path INCORRECTO:** `authentication/get_authentication_settings/` → 500 Waitress. Usar el path de arriba.

### Dataset Management ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get All Datasets | `xql/get_datasets/` | `{}` | ✅ 200 |

### Endpoint Management ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get All Endpoints | `endpoints/get_endpoints/` | `{}` | ✅ 200 |
| Get Endpoint | `endpoints/get_endpoint/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Policy | `endpoints/get_policy/` | `{"endpoint_id": "<id>"}` | ✅ 200 |
| Get Violations | `device_control/get_violations/` | `{}` | ✅ 200 |

**⚠️ Paths INCORRECTOS:** `endpoints/get_violations/` → 500. Usar `device_control/get_violations/`.

### Endpoint Security Profiles
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Profiles | `endpoints/get_profiles/` | `{"type": "prevention"}` | ❌ 402 "feature not supported" |

### Legacy Exceptions ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Exception Modules | `legacy_exceptions/get_modules/` | `{}` | ✅ 200 (42 items) |
| Fetch Exception Rules | `legacy_exceptions/fetch/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |

**⚠️ Paths INCORRECTOS:** `endpoint_exceptions/get_exception_modules/`, `endpoint_exceptions/get_exception_rules/` → 500 Waitress.

### Disable Injection/Prevention ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Disable Inj+Prev Rules | `disable_injection_prevention_rules/fetch/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Disable Prevention Rules | `disable_prevention/fetch/` | `{"search_from": 0, "search_to": 100, "filters": []}` | ✅ 200 |
| Disable Prevention Modules | `disable_prevention/get_modules/` | `{"platform": "windows"}` | ✅ 200 (47 items) |

**⚠️ Paths INCORRECTOS:** `endpoint_exceptions/get_disable_*` → 500 Waitress.

### Prevention Profile Modules ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Prevention Profile Modules | `profiles/prevention/get_modules/` | `{"profile_type": "Exploit", "platform": "Windows"}` | ✅ 200 |

**⚠️ Params case-sensitive:** `profile_type` debe ser `Exploit`/`Malware`/`Restrictions`/`Agent Settings`. `platform` debe ser `Windows`/`macOS`/`Linux`/`Android`/`iOS`/`Serverless Function`.
**⚠️ Path INCORRECTO:** `prevention_profiles/get_modules/` → 500 Waitress.

### Distributions ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Distribution Version | `distributions/get_versions/` | `{}` | ✅ 200 |
| Get Distributions | `distributions/get_distributions/` | `{}` | ✅ 200 |
| Get Distribution Status | `distributions/get_status/` | `{"distribution_id": "<id>"}` | ✅ 200 (requiere ID válido) |
| Get Distribution URL | `distributions/get_dist_url/` | `{"distribution_id": "<id>", "package_type": "x64"}` | Requiere ID válido |

### Policies
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Policies | `policies/get_policies/` | `{}` | ❌ 500 Waitress |

**Nota:** `policies/get_policies/` da 500 Waitress en este tenant. `policy/get/` da 403 "Insufficient permissions". **Fallback:** derivar desde `endpoints/get_endpoint` → `assigned_prevention_policy`.

### Endpoint Groups
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Endpoint Groups | `endpoints/get_endpoint_groups/` | `{"search_from": 0, "search_to": 100}` | ❌ 500 Waitress |

**Fallback:** derivar desde `endpoints/get_endpoint` → `group_name`. MCP `cortex_get_endpoint_groups` lo hace automáticamente.

### Incident Management ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get All Incidents | `incidents/get_incidents/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get All Alerts | `alerts/get_alerts/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Alerts Multi Events v1 | `alerts/get_alerts_multi_events/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Alerts Multi Events v2 | `alerts/get_alerts_multi_events/` (v2) | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Extra Incident Data | `incidents/get_incident_extra_data/` | `{"incident_id": "<id>"}` | ✅ 200 (requiere ID válido) |

**⚠️ Path INCORRECTO:** `incidents/get_extra_data/` → 500 Waitress. Usar `incidents/get_incident_extra_data/`.

### Lookup Datasets ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Data From Lookup | `xql/lookups/get_data/` | `{"dataset_name": "<name>"}` | ✅ 200 (requiere dataset válido) |

**⚠️ Path INCORRECTO:** `lookup/get_data/` → 500 Waitress. Usar `xql/lookups/get_data/`.

### Response Actions ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Action Status | `actions/get_action_status/` | `{"group_action_id": <id>}` | ✅ 200 |
| File Retrieval Details | `actions/file_retrieval_details/` | `{"group_action_id": <id>}` | ✅ 200 |

### Script Execution ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Scripts | `scripts/get_scripts/` | `{"search_from": 0, "search_to": 100}` | ✅ 200 |
| Get Script Metadata | `scripts/get_script_metadata/` | `{"script_uid": "<uid>"}` | ✅ (requiere uid válido) |

### Syslog Servers ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Syslog Servers | `integrations/syslog/get/` | `{"filters": [{"field": "id", "operator": "eq", "value": 1}]}` | ✅ 200 |

**⚠️ Path INCORRECTO:** `syslog/get_servers/` → 500 Waitress. Usar `integrations/syslog/get/`.
**⚠️ Requiere `filters`** obligatorio. Operadores válidos: `eq`, `neq`, `in`, `nin`, `gte`, `lte`, `range`, `relative_timestamp`.

### System Management ✅
| Endpoint | Path | Method | Body ejemplo | Status |
|---|---|---|---|---|
| System Health Check | `healthcheck/` | **GET** | (sin body) | ✅ 200 |
| Get Tenant Info | `system/get_tenant_info/` | POST | `{}` | ✅ 200 |
| Get Users | `rbac/get_users/` | POST | `{}` | ✅ 200 |
| Get Roles | `rbac/get_roles/` | POST | `{"role_names": ["Viewer"]}` | ✅ 200 |
| Get User Groups | `rbac/get_user_group/` | POST | `{"group_names": ["<name>"]}` | ✅ (requiere grupo existente) |

**⚠️ Paths INCORRECTOS:** `system/get_health_check/` → 500. `rbac/get_user_groups/` (plural) → 500. Usar `healthcheck/` (GET) y `rbac/get_user_group/` (singular).

### Risk Score
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Get Risk Score | `get_risk_score/` | `{"id": "<user/endpoint>"}` | ❌ 500 "No identity threat" |
| Get Risky Users | `get_risky_users/` | `{}` | ❌ 500 "No identity threat" |
| Get Risky Hosts | `get_risky_hosts/` | `{}` | ❌ 500 "No identity threat" |

**Nota:** Paths son correctos pero requieren licencia **Identity Threat Module** (no habilitada en este tenant).
**⚠️ Paths INCORRECTOS:** `risk_score/get_risk_score/` → 500 Waitress. Los paths correctos NO llevan prefijo `risk_score/`.

### XQL Query ✅
| Endpoint | Path | Body ejemplo | Status |
|---|---|---|---|
| Start XQL Query | `xql/start_xql_query/` | `{"query": "...", "time_from": ..., "time_to": ...}` | ✅ 200 |
| Get XQL Results | `xql/get_query_results/` | `{"query_id": "<id>"}` | ✅ 200 |
| Get XQL Quota | `xql/get_quota/` | `{}` | ✅ 200 |

## Resumen de paths incorrectos que usábamos

| Path INCORRECTO (causaba 500 Waitress) | Path CORRECTO (200 OK) |
|---|---|
| `authentication/get_authentication_settings/` | `authentication-settings/get/settings/` |
| `authentication/get_idp_metadata/` | `authentication-settings/get/metadata/` |
| `endpoints/get_violations/` | `device_control/get_violations/` |
| `endpoint_exceptions/get_exception_modules/` | `legacy_exceptions/get_modules/` |
| `endpoint_exceptions/get_exception_rules/` | `legacy_exceptions/fetch/` |
| `endpoint_exceptions/get_disable_injection_prevention_rules/` | `disable_injection_prevention_rules/fetch/` |
| `endpoint_exceptions/get_disable_prevention_rules/` | `disable_prevention/fetch/` |
| `endpoint_exceptions/get_disable_prevention_modules/` | `disable_prevention/get_modules/` |
| `prevention_profiles/get_modules/` | `profiles/prevention/get_modules/` |
| `incidents/get_extra_data/` | `incidents/get_incident_extra_data/` |
| `lookup/get_data/` | `xql/lookups/get_data/` |
| `system/get_health_check/` | `healthcheck/` (método GET) |
| `rbac/get_user_groups/` (plural) | `rbac/get_user_group/` (singular) |
| `risk_score/get_risk_score/` | `get_risk_score/` |
| `risk_score/get_risky_users/` | `get_risky_users/` |
| `risk_score/get_risky_hosts/` | `get_risky_hosts/` |
| `syslog/get_servers/` | `integrations/syslog/get/` |

## Endpoints que NO funcionan en este tenant (no son paths incorrectos)

| Path | Razón |
|---|---|
| `policies/get_policies/` | 500 Waitress (permisos insuficientes de la key) |
| `endpoints/get_endpoint_groups/` | 500 Waitress (igual) |
| `endpoints/get_profiles/` | 402 "feature not supported" |
| `get_risk_score/`, `get_risky_users/`, `get_risky_hosts/` | "No identity threat" (requiere Identity Threat Module) |
| `forensics/get_triage_presets/` | 500 Waitress |

## Documentación oficial

- [Cortex XDR REST API](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Cortex-XDR-REST-API)
- [Get Started](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Started-with-Cortex-XDR-APIs)
- [Authentication methods](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Authentication-methods)

---
*Validado contra un tenant real de Cortex XDR (Standard).*
