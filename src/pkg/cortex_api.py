"""
Reglas de oro de la API Cortex XDR (Cortex XDR REST API).
Toda petición debe cumplir estos requisitos o será rechazada con 403/404.

1. Trailing Slash: La URL DEBE terminar en /
2. Request Wrapper: Todo el JSON del body dentro de la llave "request_data"
3. Headers: x-xdr-auth-id (API Key ID), Authorization (API Key), Content-Type: application/json

Documentación maestra: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Cortex-XDR-REST-API

Índice local (MCP): entities/resources/cortex_rest_api_reference.md — enlaces a Audit, Auth,
Datasets, Endpoints, Incidents, Response, Scripts, Syslog, System, XQL.

XQL: algunos tenants usan xql/start_xql_query + xql/get_query_results; otros xql_queries/run +
xql_queries/get_results (ver Running XQL Query APIs). cortex_xql_query prueba ambas.

Paginación endpoints (get_endpoint, get_endpoint_groups, etc.):
  Debe cumplirse **0 < (search_to - search_from) <= 100**. Rangos mayores (p. ej. 500) suelen
  provocar **500 Internal Server Error** en el servidor Cortex.
"""


# Límite documentado / observado en tenants PAN para búsquedas de endpoints y grupos
CORTEX_ENDPOINT_SEARCH_MAX_SPAN = 100


def clamp_endpoint_search_window(search_from: int, search_to: int) -> tuple[int, int]:
    """Ajusta search_from/search_to al máximo permitido (span <= 100, mínimo 1)."""
    s_from = max(0, int(search_from))
    s_to = int(search_to)
    span = s_to - s_from
    if span <= 0:
        return s_from, s_from + CORTEX_ENDPOINT_SEARCH_MAX_SPAN
    if span > CORTEX_ENDPOINT_SEARCH_MAX_SPAN:
        return s_from, s_from + CORTEX_ENDPOINT_SEARCH_MAX_SPAN
    return s_from, s_to


def normalize_cortex_path(path: str, api_version: str = "v1") -> str:
    """
    Limpieza de path y forzado de trailing slash.
    La API Cortex rechaza URLs sin / al final.

    Args:
        path: Ruta bajo public_api (ej. "policies/get_policies", "endpoints/get_endpoint").
        api_version: v1 o v2.

    Returns:
        Path completo con trailing slash: /public_api/v1/{path}/
    """
    path_clean = (path or "").strip().strip("/")
    if not path_clean:
        raise ValueError("Cortex API path no puede estar vacío")
    return f"/public_api/{api_version}/{path_clean}/"


def build_cortex_payload(data: dict | None) -> dict:
    """
    Wrapper obligatorio para el body. Todo el contenido va dentro de "request_data".

    Args:
        data: Contenido a enviar (filtros, IDs, etc.). Si es None, se usa {}.

    Returns:
        {"request_data": data} o {"request_data": {}}
    """
    return {"request_data": data if data is not None else {}}


def get_cortex_headers(api_key: str, api_key_id: str) -> dict:
    """
    Headers estrictos requeridos por la API Cortex XDR.

    Args:
        api_key: API Key (string).
        api_key_id: ID de la API Key (string).

    Returns:
        Dict con Content-Type, x-xdr-auth-id, Authorization.
    """
    return {
        "Content-Type": "application/json",
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": (api_key or "").strip(),
    }
