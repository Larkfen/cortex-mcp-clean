"""
Políticas en Cortex: listar nombres de políticas obtenidos desde endpoints.
No usa el endpoint policy/get_policy_list (que puede devolver 403);
extrae assigned_prevention_policy y assigned_extensions_policy de get_filtered_endpoints.
"""
import json
import logging
from typing import Annotated

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)


async def list_policies_from_endpoints(
    ctx: Context,
    search_to: Annotated[int, Field(description="Número máximo de endpoints a consultar (API exige 1-100)", default=100)] = 100,
) -> str:
    """
    Lista los nombres de políticas de Prevention y Extensions que están asignadas a endpoints.
    Obtiene los datos desde endpoints/get_endpoint (no usa policy/get_policy_list).
    Útil cuando el endpoint directo de políticas no está disponible.

    Returns:
        JSON con listas: prevention_policies, extensions_policies, y total de endpoints consultados.
    """
    # Cortex exige 0 < search_size <= 100 (search_to en el request)
    size = max(1, min(int(search_to), 100))
    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": size,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        data = await fetcher.send_request("endpoints/get_endpoint", data=payload)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing policies from endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list policies from endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)

    reply = data.get("reply", data) if isinstance(data, dict) else {}
    endpoints = reply.get("endpoints") if isinstance(reply, dict) else []
    if not isinstance(endpoints, list):
        endpoints = []

    prevention = set()
    extensions = set()
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        p = ep.get("assigned_prevention_policy")
        if p and str(p).strip():
            prevention.add(str(p).strip())
        e = ep.get("assigned_extensions_policy")
        if e and str(e).strip():
            extensions.add(str(e).strip())

    result = {
        "prevention_policies": sorted(prevention),
        "extensions_policies": sorted(extensions),
        "endpoints_queried": len(endpoints),
        "source": "get_filtered_endpoints",
    }
    return create_response(data=result)


class PoliciesModule(BaseModule):
    """Módulo que expone listado de políticas derivadas de endpoints."""

    def register_tools(self):
        self._add_tool(list_policies_from_endpoints)

    def register_resources(self):
        pass
