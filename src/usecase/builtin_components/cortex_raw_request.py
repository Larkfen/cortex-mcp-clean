"""
Envío de peticiones a la API Cortex XDR (public_api/v1).
Reglas de oro: trailing slash obligatorio, body en request_data, headers x-xdr-auth-id + Authorization.
Índice REST oficial (enlaces por módulo): recurso MCP cortex-xdr://reference/rest-api
o archivo entities/resources/cortex_rest_api_reference.md.
"""
import asyncio
import json
import logging
import re
import time
from typing import Annotated

import httpx
from fastmcp import Context
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from pkg.cortex_api import (
    CORTEX_ENDPOINT_SEARCH_MAX_SPAN,
    build_cortex_payload,
    clamp_endpoint_search_window,
)
from pkg.util import create_response, read_resource
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

# Paginación máxima al derivar grupos desde get_endpoint (inventarios grandes; ~2k páginas = 200k endpoints)
_DERIVE_GROUPS_MAX_PAGES_DEFAULT = 2000


def _path_suggests_endpoint_group_listing(path: str) -> bool:
    p = (path or "").strip("/").lower()
    return "get_endpoint_groups" in p


def _path_suggests_policies_listing(path: str) -> bool:
    p = (path or "").strip("/").lower()
    return p.startswith("policies/get_policies") or p.endswith("get_policies")


def _derived_groups_success_response(exc: PAPIServerError, derived: dict) -> str:
    """Respuesta tipo éxito cuando get_endpoint_groups falla y se usa get_endpoint."""
    return create_response(
        data={
            "reply": {
                "endpoint_groups": derived["groups"],
                "total_count": len(derived["groups"]),
                "derived_from_get_endpoint": True,
                "endpoints_without_group_count": derived["endpoints_without_group_count"],
                "total_endpoints_reported": derived.get("total_count_reported"),
                "pages_fetched_derive": derived.get("pages_fetched"),
            },
            "warnings": [
                "endpoints/get_endpoint_groups falló en este tenant (error 5xx del servidor Cortex). "
                "La lista de grupos se construyó agregando group_name desde endpoints/get_endpoint "
                "(misma fuente que la consola para membresía). "
                "Los objetos no incluyen endpoint_group_id de la API de grupos; para add_endpoints_to_group "
                "necesitas el ID desde la consola o soporte PAN si el endpoint oficial no se restaura."
            ],
            "_cortex_mcp_official_get_endpoint_groups_error": str(exc),
        }
    )


async def _derive_policies_from_get_endpoint(ctx: Context, *, max_pages: int = 200) -> dict:
    """Deriva lista de políticas desde endpoints/get_endpoint (assigned_prevention_policy, assigned_extensions_policy)."""
    fetcher = await get_fetcher(ctx)
    prevention: dict[str, int] = {}
    extensions: dict[str, int] = {}
    total_count: int | None = None
    search_from = 0
    pages_fetched = 0

    for page in range(max(1, max_pages)):
        s_from, s_to = clamp_endpoint_search_window(search_from, search_from + CORTEX_ENDPOINT_SEARCH_MAX_SPAN)
        data = await fetcher.send_request(
            "endpoints/get_endpoint",
            method="POST",
            data=build_cortex_payload({"search_from": s_from, "search_to": s_to}),
            api_version="v1",
        )
        if not isinstance(data, dict):
            break
        reply = data.get("reply") or {}
        if not isinstance(reply, dict):
            break
        if total_count is None:
            tc = reply.get("total_count")
            if isinstance(tc, int):
                total_count = tc
        endpoints = reply.get("endpoints") or []
        if not isinstance(endpoints, list):
            break
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            pp = ep.get("assigned_prevention_policy")
            if isinstance(pp, str) and pp.strip():
                prevention[pp] = prevention.get(pp, 0) + 1
            xp = ep.get("assigned_extensions_policy")
            if isinstance(xp, str) and xp.strip():
                extensions[xp] = extensions.get(xp, 0) + 1
        pages_fetched = page + 1
        search_from = s_to
        if len(endpoints) < CORTEX_ENDPOINT_SEARCH_MAX_SPAN:
            break
        if total_count is not None and search_from >= total_count:
            break

    policies_out = sorted(
        ({"name": n, "type": "prevention", "assigned_count": c} for n, c in prevention.items()),
        key=lambda x: (-x["assigned_count"], x["name"].lower()),
    )
    extensions_out = sorted(
        ({"name": n, "type": "extensions", "assigned_count": c} for n, c in extensions.items()),
        key=lambda x: (-x["assigned_count"], x["name"].lower()),
    )
    return {
        "source": "derived_from_endpoints_get_endpoint",
        "policies": policies_out + extensions_out,
        "prevention_count": len(prevention),
        "extensions_count": len(extensions),
        "pages_fetched": pages_fetched,
        "total_endpoints_reported": total_count,
    }


def _derived_policies_success_response(exc: PAPIServerError, derived: dict) -> str:
    return create_response(
        data={
            "reply": {
                "policies": derived["policies"],
                "total_count": len(derived["policies"]),
                "derived_from_get_endpoint": True,
                "prevention_count": derived["prevention_count"],
                "extensions_count": derived["extensions_count"],
            },
            "warnings": [
                "policies/get_policies falló en este tenant (500 Waitress). "
                "Lista de políticas derivada de assigned_prevention_policy y assigned_extensions_policy "
                "en endpoints/get_endpoint. No incluye policy_id — para asignar políticas se necesita "
                "el ID de la consola Cortex o una API key con más permisos."
            ],
            "_cortex_mcp_official_get_policies_error": str(exc),
        }
    )


async def cortex_send_request(
    ctx: Context,
    path: Annotated[
        str,
        Field(
            description=(
                "Ruta bajo public_api/v1 según doc oficial Cortex XDR REST API (NO improvisar). "
                "Ejemplos: policies/get_policies, endpoints/get_endpoint, incidents/get_incidents, "
                "alerts/get_alerts, xql_queries/run, audit_* según TOC. "
                "Lee el recurso cortex-xdr://reference/rest-api para índice completo y enlaces. "
                "Trailing slash se aplica en el cliente."
            )
        ),
    ],
    request_data: Annotated[dict, Field(description="Cuerpo request_data a enviar (se envuelve en request_data)")],
    method: Annotated[str, Field(description="Método HTTP", default="POST")] = "POST",
    api_version: Annotated[str, Field(description="Versión API: v1 o v2", default="v1")] = "v1",
    trailing_slash: Annotated[bool | None, Field(description="Por defecto True (obligatorio en Cortex). False solo si el endpoint no lo requiere.", default=None)] = None,
) -> str:
    """
    Envía una petición a la API Cortex XDR (public_api) con reglas de oro: trailing slash, body request_data.
    Cubre **todos** los endpoints REST documentados que usen el wrapper estándar; consulta el recurso
    cortex-xdr://reference/rest-api o https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Cortex-XDR-REST-API
    """
    try:
        fetcher = await get_fetcher(ctx)
        if isinstance(request_data, dict):
            rd_in = dict(request_data)
            pnorm = (path or "").strip("/").lower()
            if (
                method.upper() == "POST"
                and "search_from" in rd_in
                and "search_to" in rd_in
                and (
                    "get_endpoint_groups" in pnorm
                    or pnorm.endswith("get_endpoint")
                    or "/get_endpoint" in pnorm
                )
            ):
                sf, st = clamp_endpoint_search_window(rd_in["search_from"], rd_in["search_to"])
                if sf != rd_in["search_from"] or st != rd_in["search_to"]:
                    logger.warning(
                        "cortex_send_request: ajustado search_from/search_to de %s/%s a %s/%s (máx. span %s)",
                        rd_in["search_from"],
                        rd_in["search_to"],
                        sf,
                        st,
                        CORTEX_ENDPOINT_SEARCH_MAX_SPAN,
                    )
                rd_in["search_from"], rd_in["search_to"] = sf, st
            body = build_cortex_payload(rd_in)
        else:
            body = build_cortex_payload(request_data)
        data = await fetcher.send_request(
            path, method=method, data=body, api_version=api_version, trailing_slash=trailing_slash
        )
        if isinstance(data, dict):
            return create_response(data=data)
        return create_response(data={"reply": str(data), "raw": True})
    except PAPIServerError as e:
        if method.upper() == "POST":
            if _path_suggests_endpoint_group_listing(path):
                logger.warning("cortex_send_request: get_endpoint_groups 5xx; derivando: %s", e)
                try:
                    derived = await _derive_endpoint_groups_from_get_endpoint(
                        ctx, platform=None, max_pages=_DERIVE_GROUPS_MAX_PAGES_DEFAULT
                    )
                    return _derived_groups_success_response(e, derived)
                except Exception as fe:
                    logger.exception("cortex_send_request: fallback grupos falló: %s", fe)
            elif _path_suggests_policies_listing(path):
                logger.warning("cortex_send_request: get_policies 5xx; derivando: %s", e)
                try:
                    derived = await _derive_policies_from_get_endpoint(ctx)
                    return _derived_policies_success_response(e, derived)
                except Exception as fe:
                    logger.exception("cortex_send_request: fallback policies falló: %s", fe)
        logger.exception("cortex_send_request error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except (PAPIConnectionError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_send_request error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_send_request error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_universal_api(
    ctx: Context,
    path: Annotated[str, Field(description="Path exacto bajo public_api/v1 (ej. policies/get_policies, policy para Create Public Policy).")],
    request_data: Annotated[dict, Field(description="Cuerpo: dentro de request_data (estándar) o body en raíz si use_raw_body=True (ej. Create Public Policy).")] = None,
    method: Annotated[str, Field(description="Método HTTP", default="POST")] = "POST",
    api_version: Annotated[str, Field(description="v1 o v2", default="v1")] = "v1",
    use_raw_body: Annotated[
        bool,
        Field(description="True para Platform API que espera body en raíz sin request_data (ej. POST /public_api/v1/policy/).", default=False),
    ] = False,
) -> str:
    """
    Proxy universal a la API Cortex XDR. Por defecto aplica wrapper request_data.
    use_raw_body=True para Create Public Policy (path policy): body en raíz según doc.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if use_raw_body:
            body = request_data if request_data is not None else {}
            headers = {"X-Cortex-Raw-Body": "true"}
        else:
            if isinstance(request_data, dict):
                rd_in = dict(request_data)
                pnorm = (path or "").strip("/").lower()
                if (
                    method.upper() == "POST"
                    and "search_from" in rd_in
                    and "search_to" in rd_in
                    and (
                        "get_endpoint_groups" in pnorm
                        or pnorm.endswith("get_endpoint")
                        or "/get_endpoint" in pnorm
                    )
                ):
                    sf, st = clamp_endpoint_search_window(rd_in["search_from"], rd_in["search_to"])
                    rd_in["search_from"], rd_in["search_to"] = sf, st
                body = build_cortex_payload(rd_in)
            else:
                body = build_cortex_payload(request_data)
            headers = None
        data = await fetcher.send_request(path, method=method, data=body, headers=headers, api_version=api_version)
        if isinstance(data, dict):
            return create_response(data=data)
        return create_response(data={"reply": str(data), "raw": True})
    except PAPIServerError as e:
        if not use_raw_body and method.upper() == "POST":
            if _path_suggests_endpoint_group_listing(path):
                logger.warning("cortex_universal_api: get_endpoint_groups 5xx; derivando: %s", e)
                try:
                    derived = await _derive_endpoint_groups_from_get_endpoint(
                        ctx, platform=None, max_pages=_DERIVE_GROUPS_MAX_PAGES_DEFAULT
                    )
                    return _derived_groups_success_response(e, derived)
                except Exception as fe:
                    logger.exception("cortex_universal_api: fallback grupos falló: %s", fe)
            elif _path_suggests_policies_listing(path):
                logger.warning("cortex_universal_api: get_policies 5xx; derivando: %s", e)
                try:
                    derived = await _derive_policies_from_get_endpoint(ctx)
                    return _derived_policies_success_response(e, derived)
                except Exception as fe:
                    logger.exception("cortex_universal_api: fallback policies falló: %s", fe)
        logger.exception("cortex_universal_api error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except (PAPIConnectionError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_universal_api error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_universal_api error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


def _resolve_policy_id_from_reply(reply: dict, policy_name: str):
    """Extrae el policy_id de la respuesta de policies/get_policies (path oficial)."""
    if isinstance(reply, list):
        policies = reply
    else:
        policies = reply.get("policies") or reply.get("policy_list") or reply.get("reply") or []
    if isinstance(policies, dict):
        policies = policies.get("policies") or policies.get("policy_list") or []
    for p in policies:
        if not isinstance(p, dict):
            continue
        name = (p.get("name") or p.get("policy_name") or p.get("profile_name") or "").strip()
        if name and name.lower() == policy_name.strip().lower():
            pid = p.get("id") or p.get("policy_id") or p.get("profile_id")
            if pid is not None:
                return str(pid) if not isinstance(pid, str) else pid
    return None


async def _get_endpoint_ids_by_hostnames(ctx: Context, hostnames: list[str]) -> list[str]:
    """Paso 2 del flujo: obtener endpoint_id desde hostnames vía endpoints/get_endpoint/."""
    fetcher = await get_fetcher(ctx)
    # API Cortex: search_size = search_to - search_from debe cumplir 0 < search_size <= 100
    data = await fetcher.send_request(
        "endpoints/get_endpoint",
        method="POST",
        data=build_cortex_payload({
            "search_from": 0,
            "search_to": 100,
            "filters": [{"field": "hostname", "operator": "in", "value": hostnames}],
        }),
        api_version="v1",
    )
    if not isinstance(data, dict):
        return []
    reply = data.get("reply") or {}
    endpoints = reply.get("endpoints") if isinstance(reply, dict) else []
    return [e.get("endpoint_id") for e in endpoints if isinstance(e, dict) and e.get("endpoint_id")]


async def cortex_assign_prevention_policy(
    ctx: Context,
    endpoint_id_list: Annotated[
        list[str],
        Field(description="Lista de endpoint_id. O bien pase hostnames y deje esto vacío."),
    ] = None,
    hostnames: Annotated[
        list[str] | None,
        Field(description="Hostnames a resolver (ej. Audit01, Audit02). Se llama a endpoints/get_endpoint para obtener endpoint_id."),
    ] = None,
    prevention_policy_name: Annotated[str, Field(description="Nombre de la política, ej. Windows Default")] = "Windows Default",
    policy_id: Annotated[
        str | None,
        Field(description="Opcional. Si se conoce, evita Paso 1 (get_policies)."),
    ] = None,
) -> str:
    """
    Asigna una política de prevención a endpoints. Flujo obligatorio:
    Paso 1: policies/get_policies/ (filtrar por nombre) → policy_id.
    Paso 2: endpoints/get_endpoint/ (filtrar por hostname si se pasan hostnames) → endpoint_id_list.
    Paso 3: policies/assign_to_endpoints/ con policy_id y endpoint_id_list (NUNCA nombres).
    """
    fetcher = await get_fetcher(ctx)
    endpoint_ids = list(endpoint_id_list or [])

    if hostnames:
        resolved = await _get_endpoint_ids_by_hostnames(ctx, hostnames)
        endpoint_ids = list(set(endpoint_ids) | set(resolved))
    if not endpoint_ids:
        return create_response(
            data={"error": "Faltan endpoint_id_list o hostnames resolubles.", "assigned": False},
            is_error=True,
        )

    # Paso 1: policy_id por nombre (solo path oficial policies/get_policies)
    if not policy_id:
        try:
            data = await fetcher.send_request(
                "policies/get_policies",
                method="POST",
                data=build_cortex_payload({"search_from": 0, "search_to": 200, "policy_type": "prevention"}),
                api_version="v1",
            )
            if isinstance(data, dict):
                reply = data.get("reply") or data
                if isinstance(reply, list):
                    reply = {"policies": reply}
                policy_id = _resolve_policy_id_from_reply(reply if isinstance(reply, dict) else {}, prevention_policy_name)
        except (PAPIAuthenticationError, PAPIClientRequestError, PAPIClientError, PAPIConnectionError, PAPIServerError, PAPIResponseError):
            pass
    if not policy_id:
        return create_response(
            data={
                "error": f"No se encontró policy_id para '{prevention_policy_name}'. Usar policies/get_policies o pasar policy_id desde consola Cortex.",
                "assigned": False,
            },
            is_error=True,
        )

    # Paso 3: asignar (solo path oficial policies/assign_to_endpoints)
    try:
        data = await fetcher.send_request(
            "policies/assign_to_endpoints",
            method="POST",
            data=build_cortex_payload({"policy_id": policy_id, "endpoint_id_list": endpoint_ids}),
            api_version="v1",
        )
        if isinstance(data, dict) and data.get("reply") is not None:
            return create_response(data={"assigned": True, "reply": data, "policy_id_used": policy_id})
        return create_response(data={"error": str(data) if data else "empty", "assigned": False}, is_error=True)
    except (PAPIAuthenticationError, PAPIClientRequestError, PAPIClientError) as e:
        err = str(e)
        if "403" in err or "Insufficient permissions" in err:
            return create_response(
                data={
                    "error": err,
                    "assigned": False,
                    "hint": "API key Advanced puede ser necesaria para escritura en políticas.",
                },
                is_error=True,
            )
        return create_response(data={"error": err, "assigned": False}, is_error=True)
    except (PAPIConnectionError, PAPIServerError, PAPIResponseError) as e:
        return create_response(data={"error": str(e), "assigned": False}, is_error=True)


async def cortex_create_audit_group(ctx: Context) -> str:
    """
    Crea un grupo de endpoints con solo Audit01 y Audit02 (nombre: Audit - Pruebas C2).
    Usa endpoints/get_endpoint/ y endpoint_groups/create/.
    """
    fetcher = await get_fetcher(ctx)
    try:
        data = await fetcher.send_request(
            "endpoints/get_endpoint",
            method="POST",
            data=build_cortex_payload({
                "search_from": 0,
                "search_to": 100,
                "filters": [{"field": "hostname", "operator": "in", "value": ["Audit01", "Audit02"]}],
            }),
            api_version="v1",
        )
    except Exception as e:
        return create_response(data={"error": str(e), "created": False}, is_error=True)
    if not isinstance(data, dict):
        return create_response(data={"error": "No se pudieron obtener endpoints Audit", "created": False}, is_error=True)
    reply = data.get("reply") or {}
    endpoints = reply.get("endpoints") if isinstance(reply, dict) else []
    endpoint_ids = [e.get("endpoint_id") for e in endpoints if isinstance(e, dict) and e.get("endpoint_id")]
    if len(endpoint_ids) < 2:
        return create_response(
            data={
                "error": f"Solo se encontraron {len(endpoint_ids)} endpoints (Audit01, Audit02). Comprueba el filtro.",
                "created": False,
            },
            is_error=True,
        )
    group_name = "Audit - Pruebas C2"
    variants = [
        {"name": group_name, "filters": [{"field": "hostname", "operator": "in", "value": ["Audit01", "Audit02"]}]},
        {"name": group_name, "endpoint_id_list": endpoint_ids},
        {"group_name": group_name, "endpoint_id_list": endpoint_ids},
        {"name": group_name, "endpoint_ids": endpoint_ids},
    ]
    for req in variants:
        try:
            out = await fetcher.send_request(
                "endpoint_groups/create",
                method="POST",
                data=build_cortex_payload(req),
                api_version="v1",
            )
            if isinstance(out, dict) and (out.get("reply") is not None or out.get("reply") == {}):
                return create_response(data={"created": True, "reply": out, "group_name": group_name})
        except (PAPIClientRequestError, PAPIClientError, PAPIServerError, PAPIResponseError, PAPIConnectionError):
            continue
    return create_response(
        data={
            "created": False,
            "reason": "La API endpoint_groups/create devolvió error en todas las variantes (en este tenant suele ser 500).",
            "pasos_consola": [
                "Cortex XDR → Settings → Endpoint management → Endpoint groups",
                "Create group / Nuevo grupo",
                "Nombre: Audit - Pruebas C2",
                "Criterio: Endpoint name contains 'audit' (o equals Audit01 OR equals Audit02)",
                "Guardar y comprobar que solo aparecen Audit01 y Audit02.",
            ],
            "endpoint_ids_para_referencia": endpoint_ids,
        }
    )


def _xql_normalize_query(q: str) -> str:
    """En este tenant la sintaxis correcta es 'dataset = xdr_data'; si el usuario usa 'dataset xdr_data' se normaliza."""
    if not q or "dataset =" in q:
        return q
    return re.sub(r"\bdataset\s+xdr_data\b", "dataset = xdr_data", q, count=1, flags=re.IGNORECASE)


def _xql_extract_run_id(data: dict) -> str | None:
    """Extrae execution_id / query_id de la respuesta de start XQL (variantes de tenant)."""
    if not isinstance(data, dict):
        return None
    reply = data.get("reply")
    if isinstance(reply, str) and reply.strip():
        return reply.strip()
    if isinstance(reply, dict):
        for key in ("execution_id", "query_id", "id"):
            v = reply.get(key)
            if v:
                return str(v)
    return None


async def get_cortex_rest_api_reference() -> str:
    """Recurso MCP: índice REST oficial, enlaces por módulo y paths frecuentes."""
    try:
        return read_resource("cortex_rest_api_reference.md")
    except FileNotFoundError:
        return "# cortex_rest_api_reference.md no encontrado en entities/resources.\n"


def _extract_groups_from_get_endpoint_groups_reply(reply) -> list | None:
    """Interpreta la respuesta de endpoints/get_endpoint_groups (formato variable por versión)."""
    if reply is None:
        return None
    if isinstance(reply, list):
        return reply
    if not isinstance(reply, dict):
        return None
    for key in (
        "endpoint_groups",
        "groups",
        "endpoint_group_list",
        "reply",
        "data",
    ):
        v = reply.get(key)
        if isinstance(v, list):
            return v
        if isinstance(v, dict) and "endpoint_groups" in v:
            eg = v.get("endpoint_groups")
            if isinstance(eg, list):
                return eg
    return None


def _extract_total_count_from_reply(reply) -> int | None:
    if isinstance(reply, dict):
        for key in ("total_count", "total", "total_groups"):
            v = reply.get(key)
            if isinstance(v, int):
                return v
    return None


async def _derive_endpoint_groups_from_get_endpoint(
    ctx: Context,
    *,
    platform: str | None,
    max_pages: int,
) -> dict:
    """
    Si get_endpoint_groups falla, agrega group_name desde endpoints/get_endpoint
    (todas las páginas hasta max_pages o total_count).
    """
    fetcher = await get_fetcher(ctx)
    filters: list = []
    if platform:
        p = platform.strip().lower()
        if p in ("windows", "linux", "macos", "android"):
            filters.append({"field": "platform", "operator": "in", "value": [p]})

    group_members: dict[str, int] = {}
    endpoints_without_group = 0
    total_count: int | None = None
    search_from = 0
    pages_fetched = 0

    for page in range(max(1, max_pages)):
        s_from, s_to = clamp_endpoint_search_window(search_from, search_from + CORTEX_ENDPOINT_SEARCH_MAX_SPAN)
        req: dict = {"search_from": s_from, "search_to": s_to}
        if filters:
            req["filters"] = filters
        data = await fetcher.send_request(
            "endpoints/get_endpoint",
            method="POST",
            data=build_cortex_payload(req),
            api_version="v1",
        )
        if not isinstance(data, dict):
            break
        reply = data.get("reply") or {}
        if not isinstance(reply, dict):
            break
        if total_count is None:
            tc = reply.get("total_count")
            if isinstance(tc, int):
                total_count = tc
        endpoints = reply.get("endpoints") or []
        if not isinstance(endpoints, list):
            break
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            gnames = ep.get("group_name") or []
            if not gnames:
                endpoints_without_group += 1
            else:
                for g in gnames:
                    if isinstance(g, str) and g.strip():
                        group_members[g] = group_members.get(g, 0) + 1
        pages_fetched = page + 1
        search_from = s_to
        if len(endpoints) < CORTEX_ENDPOINT_SEARCH_MAX_SPAN:
            break
        if total_count is not None and search_from >= total_count:
            break

    groups_out = sorted(
        (
            {
                "name": name,
                "member_count_in_sample": count,
                "endpoint_group_id": None,
                "note": "Conteo de apariciones en get_endpoint (un endpoint puede tener varios grupos).",
            }
            for name, count in group_members.items()
        ),
        key=lambda x: (-x["member_count_in_sample"], x["name"].lower()),
    )
    return {
        "source": "derived_from_endpoints_get_endpoint",
        "reason": (
            "Lista inferida de group_name en get_endpoint; usar cuando la API oficial "
            "de grupos no está disponible o falla."
        ),
        "platform_filter": platform,
        "pages_fetched": pages_fetched,
        "total_count_reported": total_count,
        "endpoints_without_group_count": endpoints_without_group,
        "groups": groups_out,
    }


async def cortex_get_endpoint_groups(
    ctx: Context,
    search_from: Annotated[int, Field(description="Inicio de página (offset base 0).", default=0)] = 0,
    search_to: Annotated[
        int,
        Field(
            description=(
                "Fin exclusivo; el span (search_to - search_from) se limita a 100 como exige la API. "
                "Valores mayores provocan 500 en muchos tenants."
            ),
            default=100,
        ),
    ] = 100,
    fallback_derived: Annotated[
        bool,
        Field(
            description=(
                "Si True y la API oficial devuelve error (p. ej. 500), devuelve grupos derivados vía "
                "endpoints/get_endpoint agregando group_name."
            ),
            default=True,
        ),
    ] = True,
    derived_platform: Annotated[
        str | None,
        Field(
            description=(
                "Solo para fallback: filtrar por plataforma (windows, linux, macos, android) o None para todas."
            ),
            default=None,
        ),
    ] = None,
    derived_max_pages: Annotated[
        int,
        Field(
            description="Máx. páginas de 100 en fallback derivado (cubre hasta max_pages×100 endpoints).",
            default=_DERIVE_GROUPS_MAX_PAGES_DEFAULT,
        ),
    ] = _DERIVE_GROUPS_MAX_PAGES_DEFAULT,
    try_api_v2: Annotated[bool, Field(description="Probar también public_api/v2/endpoints/get_endpoint_groups/", default=True)] = True,
) -> str:
    """
    Lista grupos de endpoints. Usa paginación válida (máx. 100 por página).

    Muchos 500 en get_endpoint_groups se debían a search_to - search_from > 100.

    Si la API sigue fallando, con fallback_derived=True agrega nombres de grupo desde get_endpoint.
    """
    fetcher = await get_fetcher(ctx)
    s_from, s_to = clamp_endpoint_search_window(search_from, search_to)
    body = {"search_from": s_from, "search_to": s_to}

    variants: list[tuple[str, str]] = [
        ("endpoints/get_endpoint_groups", "v1"),
    ]
    if try_api_v2:
        variants.append(("endpoints/get_endpoint_groups", "v2"))

    last_err: str | None = None
    for path, ver in variants:
        try:
            data = await fetcher.send_request(
                path,
                method="POST",
                data=build_cortex_payload(body),
                api_version=ver,
            )
        except (PAPIServerError, PAPIClientRequestError, PAPIClientError) as e:
            last_err = str(e)
            continue
        except (PAPIConnectionError, PAPIAuthenticationError, PAPIResponseError) as e:
            last_err = str(e)
            break

        if not isinstance(data, dict):
            last_err = f"Respuesta inesperada ({type(data).__name__}): {data!r}"
            continue

        reply = data.get("reply")
        groups = _extract_groups_from_get_endpoint_groups_reply(reply)
        if groups is not None:
            return create_response(
                data={
                    "source": f"api_{ver}",
                    "path": path,
                    "search_window": {"search_from": s_from, "search_to": s_to},
                    "raw_reply": data,
                    "groups": groups,
                    "hint": "Para más páginas, llama de nuevo incrementando search_from en pasos de hasta 100.",
                }
            )
        if isinstance(reply, dict) and reply.get("err_code") is not None:
            last_err = str(reply.get("err_msg") or reply)
            continue
        last_err = f"{ver} {path}: estructura reply no reconocida (revisar raw en logs o probar otra versión API)."
        continue

    if fallback_derived:
        derived = await _derive_endpoint_groups_from_get_endpoint(
            ctx, platform=derived_platform, max_pages=derived_max_pages
        )
        return create_response(
            data={
                "official_api_error": last_err,
                "fallback": True,
                **derived,
            }
        )

    return create_response(
        data={
            "error": last_err or "get_endpoint_groups falló y fallback_derived=False",
            "hint": "Usa search_to - search_from <= 100. Prueba cortex_get_endpoint_groups con fallback_derived=True.",
        },
        is_error=True,
    )


async def cortex_xql_query(
    ctx: Context,
    query_string: Annotated[str, Field(description="Consulta XQL (ej. dataset = xdr_data | filter ... | limit 100). En este tenant usar 'dataset = xdr_data'.")],
    time_from: Annotated[int | None, Field(description="Inicio del rango (epoch ms). Opcional; por defecto hace 24h.")] = None,
    time_to: Annotated[int | None, Field(description="Fin del rango (epoch ms). Opcional; por defecto ahora.")] = None,
    time_period: Annotated[dict | None, Field(description="Ignorado; este tenant usa time_from/time_to. Rango relativo no soportado en xql/start_xql_query.")] = None,
    get_results: Annotated[bool, Field(description="Si True, espera y devuelve resultados; si False, solo execution_id.", default=True)] = True,
) -> str:
    """
    Ejecuta XQL con compatibilidad dual según doc REST y tenants reales:
    - Variante A: xql/start_xql_query (campo `query`) + xql/get_query_results (campo `query_id`).
    - Variante B: xql_queries/run (campo `query_string`) + xql_queries/get_results (campo `execution_id`).
    Si la primera falla con 404/error de cliente, prueba la segunda automáticamente.
    """
    try:
        fetcher = await get_fetcher(ctx)
        query = _xql_normalize_query(query_string)
        now_ms = int(time.time() * 1000)
        t_from = time_from if time_from is not None else (now_ms - 24 * 3600 * 1000)
        t_to = time_to if time_to is not None else now_ms

        variants: list[tuple[str, dict, str, str, str]] = [
            # start_path, start_body_inner, results_path, results_id_field, label
            (
                "xql/start_xql_query",
                {"query": query, "time_from": t_from, "time_to": t_to},
                "xql/get_query_results",
                "query_id",
                "xql/start_xql_query",
            ),
            (
                "xql_queries/run",
                {"query_string": query, "time_from": t_from, "time_to": t_to},
                "xql_queries/get_results",
                "execution_id",
                "xql_queries/run",
            ),
        ]

        data: dict | None = None
        execution_id: str | None = None
        results_path = "xql/get_query_results"
        results_id_field = "query_id"
        variant_used = ""

        last_err: str | None = None
        for start_path, body_inner, res_path, res_field, label in variants:
            try:
                data = await fetcher.send_request(
                    start_path,
                    method="POST",
                    data=build_cortex_payload(body_inner),
                    api_version="v1",
                )
            except (PAPIClientRequestError, PAPIClientError) as e:
                err = str(e)
                last_err = err
                if "404" in err or "400" in err or "Not Found" in err:
                    continue
                raise
            if not isinstance(data, dict):
                last_err = "Respuesta no dict"
                continue
            execution_id = _xql_extract_run_id(data)
            if execution_id:
                results_path = res_path
                results_id_field = res_field
                variant_used = label
                break

        if not execution_id:
            return create_response(
                data={
                    "error": "No se pudo iniciar XQL con ninguna variante (xql/start_xql_query ni xql_queries/run).",
                    "last_error": last_err,
                    "hint": "Revisa Running XQL Query APIs en la doc REST y permisos de la API key.",
                },
                is_error=True,
            )

        if not get_results:
            return create_response(
                data={
                    "execution_id": execution_id,
                    "run_reply": data,
                    "variant": variant_used,
                    "results_path": results_path,
                    "results_id_field": results_id_field,
                }
            )

        for _ in range(40):
            results_data = await fetcher.send_request(
                results_path,
                method="POST",
                data=build_cortex_payload({results_id_field: execution_id}),
                api_version="v1",
            )
            if not isinstance(results_data, dict):
                await asyncio.sleep(3)
                continue
            reply = results_data.get("reply") or {}
            if isinstance(reply, dict):
                status = (reply.get("status") or "").upper()
                if status == "SUCCESS":
                    return create_response(
                        data={
                            "execution_id": execution_id,
                            "variant": variant_used,
                            "run_reply": data,
                            "results": results_data,
                        }
                    )
                if status == "FAIL":
                    return create_response(
                        data={"error": "XQL query FAIL", "reply": reply, "execution_id": execution_id, "variant": variant_used},
                        is_error=True,
                    )
            await asyncio.sleep(3)
        return create_response(
            data={"error": "Timeout esperando resultados XQL", "execution_id": execution_id, "variant": variant_used},
            is_error=True,
        )
    except (PAPIConnectionError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_xql_query error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_xql_query error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_create_public_policy(
    ctx: Context,
    name: Annotated[str, Field(description="Nombre de la política")],
    description: Annotated[str, Field(description="Descripción")],
    rule_matching_type: Annotated[str, Field(description="Ej. ALL o ANY según doc")] = "ALL",
    asset_matching_type: Annotated[str, Field(description="Ej. ALL o ANY según doc")] = "ALL",
    enabled: Annotated[bool, Field(description="Política habilitada", default=True)] = True,
    associated_rule_ids: Annotated[list[str] | None, Field(description="IDs de reglas asociadas (opcional)")] = None,
    associated_asset_group_ids: Annotated[list[str] | None, Field(description="IDs de grupos de activos (opcional)")] = None,
    labels: Annotated[list[str] | None, Field(description="Etiquetas (opcional)")] = None,
) -> str:
    """
    Crea una política con POST /public_api/v1/policy/ (Create Public Policy).
    La Platform API espera body en raíz, sin request_data. Doc: docs-cortex Create Public Policy.
    """
    try:
        fetcher = await get_fetcher(ctx)
        body = {
            "name": name,
            "description": description,
            "rule_matching_type": rule_matching_type,
            "asset_matching_type": asset_matching_type,
            "enabled": enabled,
        }
        if associated_rule_ids is not None:
            body["associated_rule_ids"] = associated_rule_ids
        if associated_asset_group_ids is not None:
            body["associated_asset_group_ids"] = associated_asset_group_ids
        if labels is not None:
            body["labels"] = labels
        data = await fetcher.send_request(
            "policy",
            method="POST",
            data=body,
            headers={"X-Cortex-Raw-Body": "true"},
            api_version="v1",
        )
        if isinstance(data, dict):
            return create_response(data=data)
        return create_response(data={"reply": str(data), "raw": True})
    except (PAPIConnectionError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_create_public_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_create_public_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_response_action(
    ctx: Context,
    action: Annotated[str, Field(description="Acción: isolate | scan | run_script")],
    endpoint_ids: Annotated[list[str], Field(description="Lista de endpoint_id")],
    action_id: Annotated[str | None, Field(description="Para run_script: ID del script en Cortex. Opcional para isolate/scan.")] = None,
    script_params: Annotated[dict | None, Field(description="Para run_script: parámetros del script. Opcional.")] = None,
) -> str:
    """
    Acciones de respuesta: isolate (endpoints/isolate/), scan (endpoints/scan/), run_script (endpoints/run_script/).
    Paths oficiales; body con endpoint_id_list y, para run_script, script_id y opcionalmente parameters.
    """
    if action not in ("isolate", "scan", "run_script"):
        return create_response(data={"error": f"action debe ser isolate, scan o run_script; recibido: {action}"}, is_error=True)
    if not endpoint_ids:
        return create_response(data={"error": "endpoint_ids es obligatorio."}, is_error=True)
    path_map = {"isolate": "endpoints/isolate", "scan": "endpoints/scan", "run_script": "endpoints/run_script"}
    path = path_map[action]
    request_data = {"endpoint_id_list": endpoint_ids}
    if action == "run_script" and action_id:
        request_data["script_id"] = action_id
        if script_params is not None:
            request_data["parameters"] = script_params
    try:
        fetcher = await get_fetcher(ctx)
        data = await fetcher.send_request(
            path,
            method="POST",
            data=build_cortex_payload(request_data),
            api_version="v1",
        )
        if isinstance(data, dict):
            return create_response(data=data)
        return create_response(data={"reply": str(data), "raw": True})
    except (PAPIConnectionError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_response_action error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_response_action error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_block_list_add(
    ctx: Context,
    file_hash_list: Annotated[str, Field(description="Uno o más SHA256 separados por coma (ej. hash1,hash2) o un solo hash.")],
    comment: Annotated[str | None, Field(description="Comentario opcional (ej. caso 2783, AnyDesk no corporativo).")] = None,
) -> str:
    """
    Añade hashes SHA256 a la Block List de Cortex. Usa hash_exceptions/blocklist (Cortex Help Center);
    si falla, prueba block_list/add_files y artifacts/add_to_block_list.
    """
    hashes_str = (file_hash_list or "").strip()
    if not hashes_str:
        return create_response(data={"error": "file_hash_list no puede estar vacío."}, is_error=True)
    hashes_list = [h.strip() for h in hashes_str.split(",") if h.strip()]
    if not hashes_list:
        return create_response(data={"error": "Ningún hash válido en file_hash_list."}, is_error=True)
    fetcher = await get_fetcher(ctx)
    attempts = [
        ("hash_exceptions/blocklist", {"hash_list": hashes_list, **({"comment": comment} if comment else {})}),
        ("block_list/add_files", {"file_hash_list": ",".join(hashes_list), **({"comment": comment} if comment else {})}),
        ("block_list/add_files", {"file_hash_list": ",".join(hashes_list)}),
        ("artifacts/add_to_block_list", {"hashes": hashes_list, **({"comment": comment} if comment else {})}),
        ("artifacts/add_to_block_list", {"hashes": hashes_list}),
    ]
    last_error = None
    for path, req in attempts:
        try:
            data = await fetcher.send_request(
                path,
                method="POST",
                data=build_cortex_payload(req),
                api_version="v1",
            )
            if isinstance(data, dict) and data.get("reply") is not None:
                return create_response(data={"added": True, "path_used": path, "reply": data})
            last_error = data
        except (PAPIConnectionError, PAPIAuthenticationError, PAPIClientRequestError, PAPIClientError) as e:
            last_error = str(e)
            if "500" not in str(e) and "403" not in str(e):
                return create_response(data={"error": str(e)}, is_error=True)
        except (PAPIServerError, PAPIResponseError) as e:
            last_error = str(e)
    return create_response(
        data={
            "added": False,
            "error": "Todos los intentos (hash_exceptions/blocklist, block_list/add_files, artifacts/add_to_block_list) fallaron. Añadir hashes manualmente en Cortex → Settings → Block List.",
            "last_error": str(last_error),
            "hashes": hashes_list,
        },
        is_error=True,
    )


async def cortex_allow_list_add(
    ctx: Context,
    file_hash_list: Annotated[str, Field(description="Uno o más SHA256 (64 hex) separados por coma.")],
    comment: Annotated[str | None, Field(description="Comentario (ej. caso 3080 deploy-agent-remote.sh signage).")] = None,
) -> str:
    """
    Añade hashes SHA256 a la Allow List (archivos permitidos / no bloquear por hash).
    Endpoint público: POST public_api/v1/hash_exceptions/allowlist/ con request_data.hash_list.
    No sustituye excepciones BIOC: si el bloqueo es por comportamiento (bash + /tmp), puede no aplicar.
    """
    hashes_str = (file_hash_list or "").strip()
    if not hashes_str:
        return create_response(data={"error": "file_hash_list no puede estar vacío."}, is_error=True)
    hashes_list = [h.strip().lower() for h in hashes_str.split(",") if h.strip()]
    for h in hashes_list:
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            return create_response(
                data={"error": f"Hash inválido (debe ser SHA256 64 hex): {h[:20]}..."},
                is_error=True,
            )
    req: dict = {"hash_list": hashes_list}
    if comment:
        req["comment"] = comment
    try:
        fetcher = await get_fetcher(ctx)
        data = await fetcher.send_request(
            "hash_exceptions/allowlist",
            method="POST",
            data=build_cortex_payload(req),
            api_version="v1",
        )
        if isinstance(data, dict):
            return create_response(data={"added": True, "path_used": "hash_exceptions/allowlist", "reply": data})
        return create_response(data={"reply": str(data)}, is_error=True)
    except (PAPIConnectionError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_allow_list_add error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_allow_list_add error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_create_prevention_profile(
    ctx: Context,
    name: Annotated[str, Field(description="Nombre del perfil (ej. Audit_Prevention_Profile_C2)")],
    description: Annotated[str, Field(description="Descripción del perfil")] = "",
    platform: Annotated[str, Field(description="Plataforma: windows, macos o linux")] = "windows",
    package_type: Annotated[str, Field(description="Tipo de paquete; normalmente advanced_protection")] = "advanced_protection",
) -> str:
    """
    Crea un Prevention Profile (perfil de protección) vía Public API.
    Endpoint OBLIGATORIO: POST /public_api/v1/policies/create_policy/
    Body OBLIGATORIO: request_data con name, description, platform, type: "prevention", settings.package_type.
    Doc: https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR-Platform-APIs/Create-Public-Policy
    Tras crearla, guarda el policy_id de la respuesta para asignar con policies/assign_to_endpoints/.
    """
    request_data = {
        "name": name,
        "description": description or "",
        "platform": platform.lower(),
        "type": "prevention",
        "settings": {"package_type": package_type},
    }
    if platform.lower() not in ("windows", "macos", "linux"):
        return create_response(data={"error": f"platform debe ser windows, macos o linux; recibido: {platform}"}, is_error=True)
    try:
        fetcher = await get_fetcher(ctx)
        data = await fetcher.send_request(
            "policies/create_policy",
            method="POST",
            data=build_cortex_payload(request_data),
            api_version="v1",
        )
        if isinstance(data, dict):
            return create_response(data=data)
        return create_response(data={"reply": str(data), "raw": True})
    except (PAPIConnectionError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError, PAPIAuthenticationError) as e:
        logger.exception("cortex_create_prevention_profile error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("cortex_create_prevention_profile error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def cortex_add_prevention_profile_webapp(
    ctx: Context,
    profile_name: Annotated[str, Field(description="Nombre del Prevention Profile")],
    profile_description: Annotated[str, Field(description="Descripción (puede estar vacía)")] = "",
    cookies: Annotated[str, Field(description="Cabecera Cookie completa (DevTools, sesión Cortex)")] = "",
    csrf_token: Annotated[str, Field(description="Valor de x-csrf-token")] = "",
    xsrf_token: Annotated[str, Field(description="Valor de x-xsrf-token (Bearer ...)")] = "",
    webapp_base_url: Annotated[str, Field(description="Base URL del webapp (ej. https://your-tenant.xdr.us.paloaltonetworks.com)", default="https://your-tenant.xdr.us.paloaltonetworks.com")] = "https://your-tenant.xdr.us.paloaltonetworks.com",
    new_profile_data: Annotated[str | None, Field(description="JSON completo de new_profile_data (desde Payload de add_profile). Si no se pasa, se usa plantilla mínima; puede dar err 901.")] = None,
) -> str:
    """
    Crea un Prevention Profile vía API webapp (POST add_profile).
    Requiere sesión del navegador: cookies, csrf_token, xsrf_token (copiados de DevTools).
    Si new_profile_data no se pasa, se envía plantilla mínima; la API puede devolver 901
    (Invalid profile schema). Para éxito seguro, pasa el JSON completo del Payload de una
    petición add_profile exitosa en la consola.
    """
    if not cookies or not csrf_token or not xsrf_token:
        return create_response(
            data={"error": "cookies, csrf_token y xsrf_token son obligatorios (sesión desde DevTools)."},
            is_error=True,
        )
    url = f"{webapp_base_url.rstrip('/')}/api/webapp/profiles/add_profile"
    if new_profile_data:
        try:
            data = json.loads(new_profile_data) if isinstance(new_profile_data, str) else new_profile_data
            if "new_profile_data" in data:
                data = data["new_profile_data"]
            data["PROFILE_NAME"] = profile_name
            data["PROFILE_DESCRIPTION"] = profile_description or ""
            payload = {"new_profile_data": data}
        except (TypeError, ValueError) as e:
            return create_response(data={"error": f"new_profile_data no es JSON válido: {e}"}, is_error=True)
    else:
        payload = {
            "new_profile_data": {
                "PROFILE_NAME": profile_name,
                "PROFILE_TYPE": "MALWARE",
                "PROFILE_PLATFORM": "AGENT_OS_WINDOWS",
                "PROFILE_DESCRIPTION": profile_description or "",
                "PROFILE_IS_DEFAULT": False,
                "PROFILE_MODULES": {
                    "aspFiles": {"mode": {"value": "disabled", "isDefault": True, "defaultValue": "disabled"}, "upload": {"value": "enabled", "isDefault": True, "defaultValue": "enabled"}, "quarantine": {"value": "quarantine_disabled", "isDefault": True, "defaultValue": "quarantine_disabled"}, "actionOnUnknown": {"value": "unknown_local_analysis", "isDefault": True, "defaultValue": "unknown_local_analysis"}, "whitelistFolders": [], "onWriteProtection": {"value": "disabled", "isDefault": True, "defaultValue": "disabled"}},
                    "manualScan": {"mode": {"value": "enabled", "isDefault": True, "defaultValue": "enabled"}},
                    "ransomware": {"mode": {"value": "block", "isDefault": True, "defaultValue": "block"}, "quarantine": {"value": "disabled", "isDefault": True, "defaultValue": "disabled"}, "smbWhitelist": [], "smbEncryption": {"value": "enabled", "isDefault": True, "defaultValue": "enabled"}, "protectionMode": {"value": "normal", "isDefault": True, "defaultValue": "normal"}},
                },
            }
        }
    headers = {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "cookie": cookies,
        "x-csrf-token": csrf_token,
        "x-xsrf-token": xsrf_token,
        "x-requested-with": "XMLHttpRequest",
        "origin": webapp_base_url.rstrip("/"),
        "referer": f"{webapp_base_url.rstrip('/')}/endpoints/profiles/new/windows/malware",
    }
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            r = await client.post(url, json=payload, headers=headers)
            if r.status_code == 200:
                out = r.json() if r.text else {}
                return create_response(data=out)
            text = r.text or ""
            try:
                err_body = r.json()
                return create_response(data={"error": err_body, "status_code": r.status_code}, is_error=True)
            except Exception:
                return create_response(data={"error": text[:1000], "status_code": r.status_code}, is_error=True)
    except Exception as e:
        logger.exception("cortex_add_prevention_profile_webapp error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


class CortexRawRequestModule(BaseModule):
    """Expone: cortex_send_request, cortex_get_endpoint_groups, cortex_universal_api, cortex_assign_prevention_policy, cortex_create_audit_group, cortex_xql_query, cortex_response_action, cortex_block_list_add, cortex_allow_list_add, cortex_create_public_policy, cortex_create_prevention_profile, cortex_add_prevention_profile_webapp."""

    def register_tools(self):
        self._add_tool(cortex_send_request)
        self._add_tool(cortex_get_endpoint_groups)
        self._add_tool(cortex_universal_api)
        self._add_tool(cortex_assign_prevention_policy)
        self._add_tool(cortex_create_audit_group)
        self._add_tool(cortex_xql_query)
        self._add_tool(cortex_response_action)
        self._add_tool(cortex_block_list_add)
        self._add_tool(cortex_allow_list_add)
        self._add_tool(cortex_create_public_policy)
        self._add_tool(cortex_create_prevention_profile)
        self._add_tool(cortex_add_prevention_profile_webapp)

    def register_resources(self):
        self._add_resource(
            get_cortex_rest_api_reference,
            uri="cortex-xdr://reference/rest-api",
            name="Cortex XDR REST API reference",
            description=(
                "Índice oficial (enlaces por módulo: Audit, Auth, Datasets, Endpoints, Incidents, "
                "Response, Scripts, Syslog, System, XQL), reglas de oro y paths frecuentes para cortex_send_request."
            ),
            mime_type="text/markdown",
        )
