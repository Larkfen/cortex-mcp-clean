"""
Webapp API tools for Cortex XDR policy, profile, and device control management.

These tools use /api/webapp/ which requires browser session cookies.
Extract cookies + tokens from an active Cortex XDR session in DevTools
(Network tab → any /api/webapp/ request → Request Headers).

ENDPOINTS CONFIRMED 2026-06-19 (reverse-engineered from network monitoring + JS bundle analysis):

  READ (generic, all sections):
    GET  /api/webapp/get_view_def?table_name=TABLE_NAME
    POST /api/webapp/get_data?type=grid&table_name=TABLE_NAME  — body: {filter_data: {}}

  TABLE NAMES:
    AGENT_POLICY_TABLE                   → /endpoints/policies
    AGENT_PROFILES_TABLE                 → /endpoints/profiles
    AGENT_EXCEPTION_RULES_TABLE_ADVANCED → /endpoints/global-exceptions
    DEVICE_CONTROL_POLICY_TABLE          → /device-control/policies
    DEVICE_CONTROL_PROFILES_TABLE        → /device-control/profiles
    CUSTOM_DEVICE_MANAGEMENT             → /device-control/permanent-exceptions + /device-control/device-management
    DEVICE_CONTROL_TEMP_EXCEPTIONS       → /device-control/temp-exceptions

  WRITE (confirmed from JS bundle chunk-JCUQ26G7.js / chunk-2LSQYUXO.js):
    POST /api/webapp/agent/policy/update_policy         — {update_data: {DATA, POLICY_HASH}}
    POST /api/webapp/agent/policy/get_by_id             — {policy_id, render}
    POST /api/webapp/agent/policy/get_profiles_details  — {policy_id}
    POST /api/webapp/device_control/update_policy       — {update_data: {DATA, POLICY_HASH}}
    POST /api/webapp/device_control/get_policy_by_id    — {policy_id, render}
    POST /api/webapp/device_control/policy/get_profiles_details — {policy_id}
    POST /api/webapp/profiles/add_profile               — (existing in cortex_add_prevention_profile_webapp)
"""
import json
import logging
import os
from typing import Annotated, Optional

import httpx
from fastmcp import Context, FastMCP
from pydantic import Field

from pkg.util import create_response
from usecase.base_module import BaseModule

logger = logging.getLogger(__name__)

# Host del webapp de Cortex. Configúralo con la variable de entorno
# CORTEX_WEBAPP_HOST (ej. https://<tu-tenant>.xdr.<region>.paloaltonetworks.com).
_WEBAPP_HOST = os.environ.get("CORTEX_WEBAPP_HOST", "https://your-tenant.xdr.us.paloaltonetworks.com")
_WEBAPP_BASE = f"{_WEBAPP_HOST}/api/webapp"

_TABLE_SHORTCUTS = {
    "agent_policies": "AGENT_POLICY_TABLE",
    "agent_profiles": "AGENT_PROFILES_TABLE",
    "global_exceptions": "AGENT_EXCEPTION_RULES_TABLE_ADVANCED",
    "dc_policies": "DEVICE_CONTROL_POLICY_TABLE",
    "dc_profiles": "DEVICE_CONTROL_PROFILES_TABLE",
    "dc_permanent_exceptions": "CUSTOM_DEVICE_MANAGEMENT",
    "dc_temp_exceptions": "DEVICE_CONTROL_TEMP_EXCEPTIONS",
    "dc_device_management": "CUSTOM_DEVICE_MANAGEMENT",
}


def _headers(cookies: str, csrf_token: str, xsrf_token: str, referer_path: str = "/endpoints/policies") -> dict:
    return {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "cookie": cookies,
        "x-csrf-token": csrf_token,
        "x-xsrf-token": xsrf_token,
        "x-requested-with": "XMLHttpRequest",
        "origin": _WEBAPP_HOST,
        "referer": f"{_WEBAPP_HOST}{referer_path}",
    }


async def _post(url: str, payload: dict, cookies: str, csrf_token: str, xsrf_token: str, referer: str = "/endpoints/policies") -> dict:
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(url, json=payload, headers=_headers(cookies, csrf_token, xsrf_token, referer))
        r.raise_for_status()
        return r.json() if r.text else {}


async def webapp_list_table(
    ctx: Context,
    table_name: Annotated[str, Field(description=(
        "Table name shortcut or raw TABLE_NAME constant. "
        "Shortcuts: agent_policies, agent_profiles, global_exceptions, "
        "dc_policies, dc_profiles, dc_permanent_exceptions, dc_temp_exceptions, dc_device_management. "
        "Or pass the raw constant e.g. AGENT_POLICY_TABLE."
    ))],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools (e.g. 'INGRESS_SESSION_ID=...; INGRESS_BYPASS_TOKEN=...')")],
    csrf_token: Annotated[str, Field(description="x-csrf-token header value from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token header value from DevTools")],
    search_from: Annotated[int, Field(description="Pagination offset (default 0)", default=0)] = 0,
    search_to: Annotated[int, Field(description="Page size (default 100, max 500)", default=100)] = 100,
) -> str:
    """
    Lists items from any Cortex XDR policy/profile/device-control table via the webapp API.

    Use this to read agent policies, agent profiles, global exceptions, device control
    policies, profiles, devices, or exceptions — all in one tool.

    Requires session cookies from an active browser session (copy from DevTools).

    Shortcuts: agent_policies, agent_profiles, global_exceptions,
               dc_policies, dc_profiles, dc_permanent_exceptions,
               dc_temp_exceptions, dc_device_management.

    Args:
        ctx: FastMCP context.
        table_name: Table shortcut or raw TABLE_NAME constant.
        cookies: Full Cookie header from DevTools.
        csrf_token: x-csrf-token value.
        xsrf_token: x-xsrf-token value.
        search_from: Pagination start (default 0).
        search_to: Page size (default 100).

    Returns:
        JSON with table data, column definitions, and total count.
    """
    resolved = _TABLE_SHORTCUTS.get(table_name.lower(), table_name.upper())
    url = f"{_WEBAPP_BASE}/get_data?type=grid&table_name={resolved}"
    payload = {
        "filter_data": {},
        "search_from": search_from,
        "search_to": min(search_to, 500),
    }
    try:
        data = await _post(url, payload, cookies, csrf_token, xsrf_token)
        return create_response(data={"table_name": resolved, "result": data})
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_list_table error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_get_agent_policy(
    ctx: Context,
    policy_id: Annotated[str, Field(description="Agent policy ID (from webapp_list_table agent_policies)")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
    render: Annotated[bool, Field(description="Return rendered/display format (default True)", default=True)] = True,
) -> str:
    """
    Fetches full details of an agent (prevention/extensions) policy by ID.

    Returns the complete policy configuration including all rules, profile assignments,
    and metadata. Use the policy_id from webapp_list_table('agent_policies').

    Args:
        ctx: FastMCP context.
        policy_id: Agent policy ID.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.
        render: Return rendered display format (default True).

    Returns:
        JSON with full policy definition including rules and profile assignments.
    """
    url = f"{_WEBAPP_BASE}/agent/policy/get_by_id"
    try:
        data = await _post(url, {"policy_id": policy_id, "render": render}, cookies, csrf_token, xsrf_token)
        return create_response(data=data)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_get_agent_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_update_agent_policy(
    ctx: Context,
    policy_hash: Annotated[str, Field(description="Policy hash/ID from webapp_get_agent_policy — uniquely identifies the policy version to update")],
    policy_data: Annotated[str, Field(description="Full policy DATA JSON as a string — copy the DATA field from webapp_get_agent_policy response, modify fields, paste here")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
) -> str:
    """
    Updates an agent (prevention/extensions) policy via the webapp API.

    Workflow:
      1. Call webapp_list_table('agent_policies') to list policies.
      2. Call webapp_get_agent_policy(policy_id) to get the full policy definition.
      3. Modify the DATA fields you want to change.
      4. Call this tool with the POLICY_HASH and modified DATA.

    The POLICY_HASH is required for optimistic locking — it prevents overwriting
    concurrent changes. Get it from webapp_get_agent_policy response.

    Args:
        ctx: FastMCP context.
        policy_hash: Policy version hash (from get_agent_policy response).
        policy_data: Modified policy DATA as JSON string.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.

    Returns:
        JSON with update result.
    """
    try:
        data = json.loads(policy_data) if isinstance(policy_data, str) else policy_data
    except json.JSONDecodeError as e:
        return create_response(data={"error": f"policy_data is not valid JSON: {e}"}, is_error=True)

    url = f"{_WEBAPP_BASE}/agent/policy/update_policy"
    payload = {"update_data": {"DATA": data, "POLICY_HASH": policy_hash}}
    try:
        result = await _post(url, payload, cookies, csrf_token, xsrf_token)
        return create_response(data=result)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_update_agent_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_get_agent_policy_profiles(
    ctx: Context,
    policy_id: Annotated[str, Field(description="Agent policy ID to get associated profiles for")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
) -> str:
    """
    Returns the profiles associated with an agent policy.

    Shows which prevention/extensions profiles are assigned to a policy,
    useful when planning profile assignments or policy changes.

    Args:
        ctx: FastMCP context.
        policy_id: Agent policy ID.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.

    Returns:
        JSON with list of profiles linked to the policy.
    """
    url = f"{_WEBAPP_BASE}/agent/policy/get_profiles_details"
    try:
        data = await _post(url, {"policy_id": policy_id}, cookies, csrf_token, xsrf_token)
        return create_response(data=data)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_get_agent_policy_profiles error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_get_dc_policy(
    ctx: Context,
    policy_id: Annotated[str, Field(description="Device control policy ID (from webapp_list_table dc_policies)")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
    render: Annotated[bool, Field(description="Return rendered/display format (default True)", default=True)] = True,
) -> str:
    """
    Fetches full details of a Device Control policy by ID.

    Returns the complete device control policy including USB rules, Bluetooth rules,
    and all device permissions. Use policy_id from webapp_list_table('dc_policies').

    Args:
        ctx: FastMCP context.
        policy_id: Device control policy ID.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.
        render: Return rendered display format.

    Returns:
        JSON with full device control policy definition.
    """
    url = f"{_WEBAPP_BASE}/device_control/get_policy_by_id"
    try:
        data = await _post(url, {"policy_id": policy_id, "render": render}, cookies, csrf_token, xsrf_token,
                           referer="/device-control/policies")
        return create_response(data=data)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_get_dc_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_update_dc_policy(
    ctx: Context,
    policy_hash: Annotated[str, Field(description="Policy hash from webapp_get_dc_policy — required for optimistic locking")],
    policy_data: Annotated[str, Field(description="Full policy DATA JSON as a string — from webapp_get_dc_policy, modified as needed")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
) -> str:
    """
    Updates a Device Control policy via the webapp API.

    Workflow:
      1. webapp_list_table('dc_policies') — list all device control policies.
      2. webapp_get_dc_policy(policy_id) — get full policy + POLICY_HASH.
      3. Modify the DATA fields (USB rules, Bluetooth permissions, etc.).
      4. Call this tool with POLICY_HASH + modified DATA.

    IMPORTANT: The POLICY_HASH prevents overwriting concurrent changes.
    Always get a fresh policy first before updating.

    Args:
        ctx: FastMCP context.
        policy_hash: Policy version hash from get_dc_policy.
        policy_data: Modified policy DATA as JSON string.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.

    Returns:
        JSON with update result.
    """
    try:
        data = json.loads(policy_data) if isinstance(policy_data, str) else policy_data
    except json.JSONDecodeError as e:
        return create_response(data={"error": f"policy_data is not valid JSON: {e}"}, is_error=True)

    url = f"{_WEBAPP_BASE}/device_control/update_policy"
    payload = {"update_data": {"DATA": data, "POLICY_HASH": policy_hash}}
    try:
        result = await _post(url, payload, cookies, csrf_token, xsrf_token,
                             referer="/device-control/policies")
        return create_response(data=result)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_update_dc_policy error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_get_dc_policy_profiles(
    ctx: Context,
    policy_id: Annotated[str, Field(description="Device control policy ID")],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
) -> str:
    """
    Returns the device control profiles linked to a device control policy.

    Args:
        ctx: FastMCP context.
        policy_id: Device control policy ID.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.

    Returns:
        JSON with list of device control profiles assigned to the policy.
    """
    url = f"{_WEBAPP_BASE}/device_control/policy/get_profiles_details"
    try:
        data = await _post(url, {"policy_id": policy_id}, cookies, csrf_token, xsrf_token,
                           referer="/device-control/policies")
        return create_response(data=data)
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_get_dc_policy_profiles error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


async def webapp_get_table_schema(
    ctx: Context,
    table_name: Annotated[str, Field(description=(
        "Table name shortcut or raw TABLE_NAME constant. "
        "Same shortcuts as webapp_list_table: agent_policies, agent_profiles, "
        "global_exceptions, dc_policies, dc_profiles, dc_permanent_exceptions, "
        "dc_temp_exceptions, dc_device_management."
    ))],
    cookies: Annotated[str, Field(description="Full Cookie header from DevTools")],
    csrf_token: Annotated[str, Field(description="x-csrf-token from DevTools")],
    xsrf_token: Annotated[str, Field(description="x-xsrf-token from DevTools")],
) -> str:
    """
    Returns the column definitions and schema for a policy/profile table.

    Call this before updating a policy to understand what fields exist,
    their types, allowed values, and display names. Useful for building
    the correct DATA payload for webapp_update_agent_policy or webapp_update_dc_policy.

    Args:
        ctx: FastMCP context.
        table_name: Table shortcut or raw TABLE_NAME constant.
        cookies/csrf_token/xsrf_token: Session credentials from DevTools.

    Returns:
        JSON with column definitions, types, and metadata.
    """
    resolved = _TABLE_SHORTCUTS.get(table_name.lower(), table_name.upper())
    url = f"{_WEBAPP_BASE}/get_view_def?table_name={resolved}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=_headers(cookies, csrf_token, xsrf_token))
            r.raise_for_status()
            return create_response(data={"table_name": resolved, "schema": r.json() if r.text else {}})
    except httpx.HTTPStatusError as e:
        return create_response(data={"error": f"HTTP {e.response.status_code}: {e.response.text[:500]}"}, is_error=True)
    except Exception as e:
        logger.exception("webapp_get_table_schema error: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


class WebappPolicyModule(BaseModule):
    """
    Webapp API tools for Cortex XDR policy/profile management.

    Uses /api/webapp/ endpoints requiring browser session credentials
    (cookies + csrf/xsrf tokens from DevTools).

    Tools:
        - webapp_list_table: List any policy/profile/device table by shortcut or raw name.
        - webapp_get_table_schema: Column definitions + field types for any table.
        - webapp_get_agent_policy: Full agent policy config by ID.
        - webapp_update_agent_policy: Update agent policy via webapp (create+update).
        - webapp_get_agent_policy_profiles: Profiles assigned to an agent policy.
        - webapp_get_dc_policy: Full device control policy by ID.
        - webapp_update_dc_policy: Update device control policy via webapp.
        - webapp_get_dc_policy_profiles: Profiles assigned to a DC policy.

    Table shortcuts: agent_policies, agent_profiles, global_exceptions,
                     dc_policies, dc_profiles, dc_permanent_exceptions,
                     dc_temp_exceptions, dc_device_management.
    """

    def register_tools(self):
        self._add_tool(webapp_list_table)
        self._add_tool(webapp_get_table_schema)
        self._add_tool(webapp_get_agent_policy)
        self._add_tool(webapp_update_agent_policy)
        self._add_tool(webapp_get_agent_policy_profiles)
        self._add_tool(webapp_get_dc_policy)
        self._add_tool(webapp_update_dc_policy)
        self._add_tool(webapp_get_dc_policy_profiles)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
