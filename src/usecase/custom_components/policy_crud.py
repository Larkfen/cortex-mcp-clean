"""
Policy management tools for Cortex XDR tenant.

LIMITATION CONFIRMED 2026-06-19:
  This is a Cortex XDR deployment (not XSIAM). The Cortex XDR REST API does NOT
  expose policy CRUD (create/update/delete) via API keys regardless of permissions.
  - profiles/* endpoints → 500 (don't exist in Cortex XDR)
  - endpoint_policy/* endpoints → 500 (don't exist in Cortex XDR)
  - policy/create_policy → 403 by design (console-only in Cortex XDR)

  Policy management in Cortex XDR is console-only or requires session cookies
  (webapp API). The existing tool cortex_add_prevention_profile_webapp covers
  the session-based approach.

  What IS available via REST API:
    - list_policies: read policy names + assigned endpoint counts (via endpoint fallback)
    - get_policy_overview: full coverage view derived from endpoint data
    - assign_policy (existing in policies_mgmt.py): assign policy by name to endpoint IDs
"""
import logging
from typing import Annotated, Optional

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError, PAPIClientError, PAPIClientRequestError,
    PAPIConnectionError, PAPIResponseError, PAPIServerError,
)
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

_PAPI_ERRORS = (
    PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
    PAPIClientRequestError, PAPIResponseError, PAPIClientError,
)


async def list_policies(
    ctx: Context,
    policy_name: Annotated[Optional[str], Field(description="Filter by policy name (optional, case-insensitive substring match)")] = None,
) -> str:
    """
    Lists all Prevention and Extensions policies in the Cortex XDR tenant.

    Derives policy data from endpoint assignments since the direct policy API
    is not available in this Cortex XDR deployment. Returns policy names,
    types (prevention/extensions), and how many endpoints use each.

    To assign a policy to endpoints, use the existing assign_policy tool.
    To create or modify policies, use the Cortex XDR web console.

    Args:
        ctx: FastMCP context.
        policy_name: Optional substring filter on policy name.

    Returns:
        JSON with policy list and assigned endpoint counts.
    """
    try:
        fetcher = await get_fetcher(ctx)
        ep_payload = {"request_data": {"search_from": 0, "search_to": 100}}
        data = await fetcher.send_request("endpoints/get_endpoint", data=ep_payload)
        reply = data.get("reply", data) if isinstance(data, dict) else {}
        endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []

        prevention: dict[str, int] = {}
        extensions: dict[str, int] = {}

        for ep in endpoints:
            p = (ep.get("assigned_prevention_policy") or "").strip()
            e = (ep.get("assigned_extensions_policy") or "").strip()
            if p:
                prevention[p] = prevention.get(p, 0) + 1
            if e:
                extensions[e] = extensions.get(e, 0) + 1

        policies = [
            {"name": n, "type": "prevention", "assigned_count": c}
            for n, c in sorted(prevention.items(), key=lambda x: -x[1])
        ] + [
            {"name": n, "type": "extensions", "assigned_count": c}
            for n, c in sorted(extensions.items(), key=lambda x: -x[1])
        ]

        if policy_name:
            policies = [p for p in policies if policy_name.lower() in p["name"].lower()]

        return create_response(data={
            "policies": policies,
            "total_count": len(policies),
            "prevention_count": len(prevention),
            "extensions_count": len(extensions),
        })
    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error listing policies: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list policies: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_policy_overview(
    ctx: Context,
) -> str:
    """
    Full policy coverage overview for the Cortex XDR tenant.

    Shows which prevention and extensions policies are in use, how many endpoints
    each covers, and which endpoints have no policy assigned.

    Args:
        ctx: FastMCP context.

    Returns:
        JSON with policy coverage summary and unprotected endpoints.
    """
    try:
        fetcher = await get_fetcher(ctx)
        ep_payload = {"request_data": {"search_from": 0, "search_to": 100}}
        data = await fetcher.send_request("endpoints/get_endpoint", data=ep_payload)
        reply = data.get("reply", data) if isinstance(data, dict) else {}
        endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []

        prevention: dict[str, int] = {}
        extensions: dict[str, int] = {}
        no_prevention: list[str] = []
        no_extensions: list[str] = []

        for ep in endpoints:
            name = ep.get("endpoint_name") or ep.get("endpoint_id") or "unknown"
            p = (ep.get("assigned_prevention_policy") or "").strip()
            e = (ep.get("assigned_extensions_policy") or "").strip()
            if p:
                prevention[p] = prevention.get(p, 0) + 1
            else:
                no_prevention.append(name)
            if e:
                extensions[e] = extensions.get(e, 0) + 1
            else:
                no_extensions.append(name)

        return create_response(data={
            "prevention_policies": [
                {"name": n, "assigned_endpoints": c}
                for n, c in sorted(prevention.items(), key=lambda x: -x[1])
            ],
            "extensions_policies": [
                {"name": n, "assigned_endpoints": c}
                for n, c in sorted(extensions.items(), key=lambda x: -x[1])
            ],
            "endpoints_without_prevention_policy": no_prevention[:20],
            "endpoints_without_extensions_policy": no_extensions[:20],
            "summary": {
                "total_endpoints_evaluated": len(endpoints),
                "unique_prevention_policies": len(prevention),
                "unique_extensions_policies": len(extensions),
                "unprotected_prevention": len(no_prevention),
                "unprotected_extensions": len(no_extensions),
            },
        })
    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error in get_policy_overview: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get policy overview: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class PolicyCRUDModule(BaseModule):
    """
    Policy visibility tools for Cortex XDR.

    NOTE: Create/update/delete operations are not available via the Cortex XDR
    REST API — use the web console for policy management.

    Tools:
        - list_policies: All policies with assigned endpoint counts.
        - get_policy_overview: Full coverage view — who has what, who has nothing.
    """

    def register_tools(self):
        self._add_tool(list_policies)
        self._add_tool(get_policy_overview)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
