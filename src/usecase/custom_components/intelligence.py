"""
intelligence.py — Tools ported from Brad-Edwards/Cortex-XDR-MCP.
Adds risk intelligence, RBAC, device control, exception rules,
prevention overrides, agent packages, syslog, XQL datasets,
lookup datasets, authentication settings, and endpoint tags.
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


# ── Risk Intelligence ─────────────────────────────────────────────────────────

async def list_risky_entities(
    ctx: Context,
    entity_type: Annotated[str, Field(description="'hosts' or 'users'", default="hosts")] = "hosts",
    limit: Annotated[int, Field(description="Max results (1-200)", default=25, ge=1, le=200)] = 25,
) -> str:
    """
    Returns the riskiest hosts or users in the tenant ranked by risk score.
    Useful for prioritizing investigations.

    Args:
        ctx: FastMCP context.
        entity_type: 'hosts' or 'users'.
        limit: Maximum number of results to return.

    Returns:
        JSON list of risky entities with risk score and reasons.
    """
    if entity_type not in ("hosts", "users"):
        return create_response(data={"error": "entity_type must be 'hosts' or 'users'"}, is_error=True)
    path = "get_risky_hosts" if entity_type == "hosts" else "get_risky_users"
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request(path, data={})
        reply = response_data.get("reply", response_data)
        items = reply if isinstance(reply, list) else []
        return create_response(data={"items": items[:limit], "count": min(len(items), limit), "truncated": len(items) > limit})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing risky entities: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list risky entities: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_entity_risk(
    ctx: Context,
    entity_id: Annotated[str, Field(description="Endpoint name, endpoint ID, or username to look up the risk score for")],
) -> str:
    """
    Returns the risk score and risk reasons for a specific host or user.

    Args:
        ctx: FastMCP context.
        entity_id: Endpoint name, endpoint ID, or username.

    Returns:
        JSON with risk score and contributing reasons.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("get_risk_score", data={"request_data": {"id": entity_id}})
        return create_response(data={"entity_id": entity_id, "risk": response_data.get("reply", response_data)})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting entity risk: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get entity risk: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_incident_casefile(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident/case ID to retrieve full details for (e.g. '3215')")],
    include_event_summaries: Annotated[bool, Field(description="Include per-alert event summaries from multi-events endpoint", default=True)] = True,
) -> str:
    """
    Retrieves a comprehensive incident dossier including the incident, all alerts,
    network artifacts, file artifacts, and optionally per-alert event summaries.
    More detailed than get_incident_details.

    Args:
        ctx: FastMCP context.
        incident_id: The incident/case ID.
        include_event_summaries: Whether to fetch per-alert event summaries.

    Returns:
        JSON with full incident context: incident metadata, alerts, artifacts, event summaries.
    """
    try:
        fetcher = await get_fetcher(ctx)
        extra = await fetcher.send_request(
            "incidents/get_incident_extra_data",
            data={"request_data": {"incident_id": incident_id}},
        )
        reply = extra.get("reply", {})
        incident = reply.get("incident", {})
        alerts_obj = reply.get("alerts", {})
        alerts = alerts_obj.get("data", [])
        alert_ids = [int(a["alert_id"]) for a in alerts if str(a.get("alert_id", "")).isdigit()]

        event_summaries = []
        if include_event_summaries and alert_ids:
            try:
                multi = await fetcher.send_request(
                    "alerts/get_alerts_multi_events",
                    data={"request_data": {"filters": [{"field": "alert_id_list", "operator": "in", "value": alert_ids}]}},
                    omit_papi_prefix=False,
                )
                # Use v2 endpoint path
                multi_alerts = multi.get("reply", {}).get("alerts", [])
                for a in multi_alerts:
                    event_summaries.append({
                        "alert_id": a.get("alert_id"),
                        "name": a.get("name"),
                        "events": a.get("events", [])[:5],  # limit events per alert
                    })
            except Exception as e:
                logger.warning(f"Could not fetch event summaries: {e}")

        result = {
            "incident": incident,
            "alerts": alerts,
            "artifacts": {
                "network": reply.get("network_artifacts", {}).get("data", []),
                "files": reply.get("file_artifacts", {}).get("data", []),
            },
            "alert_event_summaries": event_summaries,
        }
        return create_response(data=result)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting incident casefile: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get incident casefile: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_endpoint_context(
    ctx: Context,
    endpoint_id: Annotated[Optional[str], Field(description="Endpoint ID (provide this OR hostname, not both)", default=None)] = None,
    hostname: Annotated[Optional[str], Field(description="Endpoint hostname (provide this OR endpoint_id, not both)", default=None)] = None,
) -> str:
    """
    Returns enriched endpoint context including endpoint details plus risk score.
    Provide either endpoint_id or hostname (not both).

    Args:
        ctx: FastMCP context.
        endpoint_id: The endpoint ID.
        hostname: The endpoint hostname.

    Returns:
        JSON with endpoint details enriched with risk score.
    """
    if bool(endpoint_id) == bool(hostname):
        return create_response(data={"error": "Provide exactly one of endpoint_id or hostname"}, is_error=True)
    try:
        fetcher = await get_fetcher(ctx)
        filters = []
        if endpoint_id:
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]})
        else:
            filters.append({"field": "hostname", "operator": "in", "value": [hostname]})

        response = await fetcher.send_request(
            "endpoints/get_endpoint",
            data={"request_data": {"search_from": 0, "search_to": 2, "filters": filters}},
        )
        endpoints = response.get("reply", {}).get("endpoints", [])
        if not endpoints:
            return create_response(data={"error": "No endpoint matched"}, is_error=True)
        endpoint = endpoints[0]

        risk = None
        risk_target = endpoint.get("endpoint_name") or endpoint.get("endpoint_id")
        if risk_target:
            try:
                risk_raw = await fetcher.send_request("get_risk_score", data={"request_data": {"id": risk_target}})
                risk = risk_raw.get("reply")
            except Exception as e:
                logger.warning(f"Risk enrichment failed: {e}")

        endpoint["risk"] = risk
        return create_response(data={"endpoint": endpoint})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting endpoint context: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get endpoint context: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Device Control ────────────────────────────────────────────────────────────

async def list_device_control_violations(
    ctx: Context,
    endpoint_ids: Annotated[Optional[list[str]], Field(description="Filter by endpoint IDs", default=None)] = None,
    usernames: Annotated[Optional[list[str]], Field(description="Filter by usernames", default=None)] = None,
    limit: Annotated[int, Field(description="Max results (1-100)", default=25, ge=1, le=100)] = 25,
) -> str:
    """
    Lists device control violations (USB, peripheral, etc.) filtered by endpoint or user.

    Args:
        ctx: FastMCP context.
        endpoint_ids: Optional list of endpoint IDs to filter by.
        usernames: Optional list of usernames to filter by.
        limit: Maximum number of results.

    Returns:
        JSON list of device control violations.
    """
    filters = []
    if endpoint_ids:
        filters.append({"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids})
    if usernames:
        filters.append({"field": "username", "operator": "in", "value": usernames})
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request(
            "device_control/get_violations",
            data={"request_data": {"search_from": 0, "search_to": limit, "filters": filters, "sort": {"field": "timestamp", "keyword": "desc"}}},
        )
        reply = response_data.get("reply", {})
        items = reply.get("violations", [])
        return create_response(data={"items": items, "count": len(items), "total_count": reply.get("total_count")})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing device control violations: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list device control violations: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Exception Rules ───────────────────────────────────────────────────────────

async def manage_exception_rule(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'list', 'list_modules', 'create', 'update', 'delete'")],
    rule: Annotated[Optional[dict], Field(description="Rule object for create/update. Fields: name, platform, module_id, status, scope, conditions, description", default=None)] = None,
    exception_id: Annotated[Optional[str], Field(description="Exception rule ID (required for update)", default=None)] = None,
    exception_ids: Annotated[Optional[list[str]], Field(description="List of exception IDs to delete", default=None)] = None,
    limit: Annotated[int, Field(description="Max results for list (1-100)", default=25, ge=1, le=100)] = 25,
) -> str:
    """
    Manages legacy exception rules in Cortex XDR.
    Actions: list (show rules), list_modules (show available modules),
    create (add new rule), update (modify rule), delete (remove rules).

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        rule: Rule definition for create/update.
        exception_id: ID of rule to update.
        exception_ids: IDs of rules to delete.
        limit: Max results for list.

    Returns:
        JSON with exception rules or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            response_data = await fetcher.send_request(
                "legacy_exceptions/fetch",
                data={"request_data": {"search_from": 0, "search_to": limit}},
            )
            reply = response_data.get("reply", {})
            items = reply.get("data") or reply.get("DATA") or []
            return create_response(data={"items": items, "count": len(items), "total_count": reply.get("total_count", reply.get("TOTAL_COUNT", len(items)))})
        elif action == "list_modules":
            response_data = await fetcher.send_request("legacy_exceptions/get_modules", data={})
            return create_response(data={"modules": response_data.get("reply", response_data)})
        elif action == "create":
            if not rule:
                return create_response(data={"error": "rule is required for create"}, is_error=True)
            payload = {"request_data": {
                "name": rule.get("name"),
                "platform": rule.get("platform"),
                "module": rule.get("module_id"),
                "profile_ids": rule.get("profile_ids", []),
                "status": rule.get("status"),
                "scope": rule.get("scope"),
                "conditions": rule.get("conditions"),
                "description": rule.get("description"),
            }}
            response_data = await fetcher.send_request("legacy_exceptions/add", data=payload)
            return create_response(data=response_data)
        elif action == "update":
            if not exception_id or not rule:
                return create_response(data={"error": "exception_id and rule are required for update"}, is_error=True)
            update = dict(rule)
            if "module_id" in update and "module" not in update:
                update["module"] = update.pop("module_id")
            payload = {"request_data": {"exception_id": exception_id, "update_data": update}}
            response_data = await fetcher.send_request("legacy_exceptions/edit", data=payload)
            return create_response(data=response_data)
        elif action == "delete":
            if not exception_ids:
                return create_response(data={"error": "exception_ids is required for delete"}, is_error=True)
            payload = {"request_data": {"exception_ids": exception_ids}}
            response_data = await fetcher.send_request("legacy_exceptions/delete", data=payload)
            return create_response(data=response_data)
        else:
            return create_response(data={"error": "action must be one of: list, list_modules, create, update, delete"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing exception rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage exception rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Prevention Overrides ──────────────────────────────────────────────────────

async def manage_prevention_override(
    ctx: Context,
    override_type: Annotated[str, Field(description="'disable_prevention' or 'disable_injection'")],
    action: Annotated[str, Field(description="Action: 'list', 'create', 'update' (prevention only), 'delete' (prevention) / 'disable' (injection)")],
    rule: Annotated[Optional[dict], Field(description="Rule definition for create/update", default=None)] = None,
    rule_ids: Annotated[Optional[list[str]], Field(description="Rule IDs for delete/disable", default=None)] = None,
) -> str:
    """
    Manages prevention override rules (disable prevention or disable injection prevention).

    Args:
        ctx: FastMCP context.
        override_type: 'disable_prevention' or 'disable_injection'.
        action: 'list', 'create', 'update', 'delete' (prevention) or 'disable' (injection).
        rule: Rule definition for create/update.
        rule_ids: Rule IDs for delete/disable.

    Returns:
        JSON with override rules or operation result.
    """
    if override_type not in ("disable_prevention", "disable_injection"):
        return create_response(data={"error": "override_type must be 'disable_prevention' or 'disable_injection'"}, is_error=True)
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            path = "disable_prevention/fetch" if override_type == "disable_prevention" else "disable_injection_prevention_rules/fetch"
            response_data = await fetcher.send_request(path, data={"request_data": {}})
            reply = response_data.get("reply", response_data)
            items = reply.get("data", []) if isinstance(reply, dict) else reply
            return create_response(data={"override_type": override_type, "items": items if isinstance(items, list) else [], "count": len(items) if isinstance(items, list) else 0})
        elif action == "create":
            path = "disable_prevention/add" if override_type == "disable_prevention" else "disable_injection_prevention_rules/add"
            response_data = await fetcher.send_request(path, data={"request_data": rule or {}})
            return create_response(data=response_data)
        elif action == "update" and override_type == "disable_prevention":
            response_data = await fetcher.send_request("disable_prevention/edit", data={"request_data": rule or {}})
            return create_response(data=response_data)
        elif action == "delete" and override_type == "disable_prevention":
            if not rule_ids:
                return create_response(data={"error": "rule_ids is required for delete"}, is_error=True)
            response_data = await fetcher.send_request("disable_prevention/delete", data={"request_data": {"rule_ids": rule_ids}})
            return create_response(data=response_data)
        elif action == "disable" and override_type == "disable_injection":
            if not rule_ids:
                return create_response(data={"error": "rule_ids is required for disable"}, is_error=True)
            response_data = await fetcher.send_request("disable_injection_prevention_rules/disable", data={"request_data": {"rule_ids": rule_ids}})
            return create_response(data=response_data)
        else:
            return create_response(data={"error": f"Invalid action '{action}' for override_type '{override_type}'"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing prevention override: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage prevention override: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── RBAC ──────────────────────────────────────────────────────────────────────

async def list_rbac_users(
    ctx: Context,
) -> str:
    """
    Lists all RBAC users in the Cortex XDR tenant.

    Args:
        ctx: FastMCP context.

    Returns:
        JSON list of users with their roles and details.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("rbac/get_users", data={"request_data": {}})
        items = response_data.get("reply", [])
        if not isinstance(items, list):
            items = [items] if items else []
        return create_response(data={"items": items, "count": len(items)})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing RBAC users: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list RBAC users: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def list_rbac_roles(
    ctx: Context,
    role_names: Annotated[Optional[list[str]], Field(description="Optional list of role names to filter by. Leave empty to get all roles.", default=None)] = None,
) -> str:
    """
    Gets details of specific RBAC roles by name.
    NOTE: The Cortex XDR API requires at least one role name - it does not support listing
    all roles without filtering. Use list_rbac_users first to discover role names, then
    query specific roles here.

    Args:
        ctx: FastMCP context.
        role_names: List of role names to retrieve details for (required by the API).

    Returns:
        JSON list of role details.
    """
    try:
        fetcher = await get_fetcher(ctx)
        # API requires role_names param; pass empty list to get all roles
        payload = {"request_data": {"role_names": role_names or []}}
        response_data = await fetcher.send_request("rbac/get_roles", data=payload)
        reply = response_data.get("reply", [])
        items = reply if isinstance(reply, list) else [reply] if reply else []
        return create_response(data={"items": items, "count": len(items)})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing RBAC roles: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list RBAC roles: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def list_user_groups(
    ctx: Context,
) -> str:
    """
    Lists all user groups in the Cortex XDR tenant.

    Args:
        ctx: FastMCP context.

    Returns:
        JSON list of user groups.
    """
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("rbac/get_user_group", data={"request_data": {}})
        reply = response_data.get("reply", [])
        items = reply if isinstance(reply, list) else [reply] if reply else []
        return create_response(data={"items": items, "count": len(items)})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing user groups: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list user groups: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def set_user_role(
    ctx: Context,
    user_email: Annotated[str, Field(description="Email address of the user to assign a role to")],
    role_name: Annotated[str, Field(description="Name of the RBAC role to assign")],
) -> str:
    """
    Assigns an RBAC role to a user in Cortex XDR.

    Args:
        ctx: FastMCP context.
        user_email: Email of the user.
        role_name: Name of the role to assign.

    Returns:
        JSON confirming the role assignment.
    """
    try:
        fetcher = await get_fetcher(ctx)
        payload = {"request_data": {"user_emails": [user_email], "role_name": role_name}}
        response_data = await fetcher.send_request("rbac/set_user_role", data=payload)
        return create_response(data={"user_email": user_email, "role_name": role_name, "result": response_data})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error setting user role: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to set user role: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Agent Packages ────────────────────────────────────────────────────────────

async def manage_agent_packages(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'list', 'status', 'download_url', 'create', 'delete'")],
    distribution_id: Annotated[Optional[str], Field(description="Distribution/package ID (for status, download_url)", default=None)] = None,
    distribution_ids: Annotated[Optional[list[str]], Field(description="List of distribution IDs to delete", default=None)] = None,
    package_type: Annotated[Optional[str], Field(description="Package type for download_url (e.g. 'sh', 'rpm', 'deb', 'pkg', 'msi', 'exe')", default=None)] = None,
    package: Annotated[Optional[dict], Field(description="Package definition for create action", default=None)] = None,
) -> str:
    """
    Manages Cortex XDR agent distribution packages.
    Actions: list (all packages), status (check build status),
    download_url (get download link), create (build new package), delete (remove packages).

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        distribution_id: Package ID for status/download.
        distribution_ids: Package IDs to delete.
        package_type: Package format for download URL.
        package: Package definition dict for create.

    Returns:
        JSON with package data or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            response_data = await fetcher.send_request(
                "distributions/get_distributions",
                data={"request_data": {"search_from": 0, "search_to": 100}},
            )
            reply = response_data.get("reply", {})
            items = reply.get("data", [])
            return create_response(data={"items": items, "count": len(items)})
        elif action == "status":
            if not distribution_id:
                return create_response(data={"error": "distribution_id is required for status"}, is_error=True)
            response_data = await fetcher.send_request("distributions/get_status", data={"request_data": {"distribution_id": distribution_id}})
            return create_response(data={"distribution_id": distribution_id, "status": response_data.get("reply", {}).get("status")})
        elif action == "download_url":
            if not distribution_id or not package_type:
                return create_response(data={"error": "distribution_id and package_type are required"}, is_error=True)
            response_data = await fetcher.send_request(
                "distributions/get_dist_url",
                data={"request_data": {"distribution_id": distribution_id, "package_type": package_type}},
            )
            return create_response(data={"distribution_id": distribution_id, "download": response_data.get("reply", response_data)})
        elif action == "create":
            if not package:
                return create_response(data={"error": "package is required for create"}, is_error=True)
            response_data = await fetcher.send_request("distributions/create", data={"request_data": package})
            return create_response(data=response_data)
        elif action == "delete":
            if not distribution_ids:
                return create_response(data={"error": "distribution_ids is required for delete"}, is_error=True)
            results = []
            for did in distribution_ids:
                r = await fetcher.send_request("distributions/delete", data={"request_data": {"distribution_id": did}})
                results.append({"distribution_id": did, "result": r})
            return create_response(data={"results": results})
        else:
            return create_response(data={"error": "action must be one of: list, status, download_url, create, delete"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing agent packages: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage agent packages: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Endpoint Tags ─────────────────────────────────────────────────────────────

async def manage_endpoint_tags(
    ctx: Context,
    action: Annotated[str, Field(description="'assign' or 'remove'")],
    endpoint_ids: Annotated[list[str], Field(description="List of endpoint IDs to tag/untag")],
    tag: Annotated[str, Field(description="The tag name to assign or remove")],
) -> str:
    """
    Assigns or removes a tag from one or more endpoints.

    Args:
        ctx: FastMCP context.
        action: 'assign' to add the tag, 'remove' to remove it.
        endpoint_ids: List of endpoint IDs.
        tag: The tag name.

    Returns:
        JSON confirming the tag operation.
    """
    if action not in ("assign", "remove"):
        return create_response(data={"error": "action must be 'assign' or 'remove'"}, is_error=True)
    try:
        fetcher = await get_fetcher(ctx)
        path = "tags/agents/assign" if action == "assign" else "tags/agents/remove"
        payload = {
            "request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}],
                "tag": tag,
            }
        }
        response_data = await fetcher.send_request(path, data=payload)
        return create_response(data={"action": action, "tag": tag, "endpoint_ids": endpoint_ids, "result": response_data})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing endpoint tags: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage endpoint tags: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Syslog Integration ────────────────────────────────────────────────────────

async def manage_syslog_integration(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'list', 'create', 'update', 'delete', 'test'")],
    integration: Annotated[Optional[dict], Field(description="Integration config for create/update", default=None)] = None,
    selection: Annotated[Optional[dict], Field(description="Selection criteria for delete/test", default=None)] = None,
) -> str:
    """
    Manages syslog integrations in Cortex XDR.
    Actions: list (all integrations), create, update, delete, test.

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        integration: Integration configuration object for create/update.
        selection: Selection criteria (integration ID) for delete/test.

    Returns:
        JSON with integration data or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            all_items = []
            for status in ("ACTIVE", "INACTIVE", "ERROR", "DISABLED"):
                try:
                    r = await fetcher.send_request(
                        "integrations/syslog/get",
                        data={"request_data": {"filters": [{"field": "status", "operator": "eq", "value": status}]}},
                    )
                    page_items = r.get("objects", [])
                    if isinstance(page_items, list):
                        all_items.extend(page_items)
                except Exception:
                    pass
            return create_response(data={"items": all_items, "count": len(all_items)})
        elif action == "create":
            if not integration:
                return create_response(data={"error": "integration is required for create"}, is_error=True)
            response_data = await fetcher.send_request("integrations/syslog/create", data={"request_data": integration})
            return create_response(data=response_data)
        elif action == "update":
            if not integration:
                return create_response(data={"error": "integration is required for update"}, is_error=True)
            response_data = await fetcher.send_request("integrations/syslog/update", data={"request_data": integration})
            return create_response(data=response_data)
        elif action == "delete":
            response_data = await fetcher.send_request("integrations/syslog/delete", data={"request_data": selection or {}})
            return create_response(data=response_data)
        elif action == "test":
            response_data = await fetcher.send_request("integrations/syslog/test", data={"request_data": selection or {}})
            return create_response(data=response_data)
        else:
            return create_response(data={"error": "action must be one of: list, create, update, delete, test"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing syslog integration: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage syslog integration: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── XQL Datasets ──────────────────────────────────────────────────────────────

async def manage_xql_dataset(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'list', 'create', 'delete'")],
    dataset: Annotated[Optional[dict], Field(description="Dataset definition for create/delete", default=None)] = None,
) -> str:
    """
    Manages XQL datasets in Cortex XDR.
    Actions: list (all datasets), create (new dataset), delete (remove dataset).

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        dataset: Dataset definition object for create/delete.

    Returns:
        JSON with dataset data or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            response_data = await fetcher.send_request("xql/get_datasets", data={"request_data": {}})
            return create_response(data={"items": response_data.get("reply", response_data)})
        elif action == "create":
            if not dataset:
                return create_response(data={"error": "dataset is required for create"}, is_error=True)
            response_data = await fetcher.send_request("xql/add_dataset", data={"request_data": dataset})
            return create_response(data=response_data)
        elif action == "delete":
            if not dataset:
                return create_response(data={"error": "dataset is required for delete"}, is_error=True)
            response_data = await fetcher.send_request("xql/delete_dataset", data={"request_data": dataset})
            return create_response(data=response_data)
        else:
            return create_response(data={"error": "action must be one of: list, create, delete"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing XQL dataset: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage XQL dataset: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Lookup Datasets ───────────────────────────────────────────────────────────

async def manage_lookup_dataset(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'get', 'add', 'remove'")],
    lookup: Annotated[Optional[dict], Field(description="Lookup request data. For get: can be empty. For add/remove: include dataset_name and data/filters.", default=None)] = None,
) -> str:
    """
    Manages lookup dataset data in Cortex XDR.
    Actions: get (retrieve lookup data), add (insert rows), remove (delete rows by filter).

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        lookup: Lookup request data object.

    Returns:
        JSON with lookup data or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        request_data = lookup or {}
        if action == "get":
            response_data = await fetcher.send_request("xql/lookups/get_data", data={"request_data": request_data})
            reply = response_data.get("reply", response_data)
            items = reply.get("data", []) if isinstance(reply, dict) else reply
            return create_response(data={"items": items if isinstance(items, list) else [], "count": len(items) if isinstance(items, list) else 0})
        elif action == "add":
            response_data = await fetcher.send_request("xql/lookups/add_data", data={"request_data": request_data})
            return create_response(data=response_data)
        elif action == "remove":
            filters = request_data.get("filters")
            if isinstance(filters, dict):
                request_data = dict(request_data)
                request_data["filters"] = [filters]
            response_data = await fetcher.send_request("xql/lookups/remove_data", data={"request_data": request_data})
            return create_response(data=response_data)
        else:
            return create_response(data={"error": "action must be one of: get, add, remove"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing lookup dataset: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage lookup dataset: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Authentication Settings ───────────────────────────────────────────────────

async def manage_authentication_settings(
    ctx: Context,
    action: Annotated[str, Field(description="Action: 'list', 'metadata', 'create', 'update', 'delete'")],
    settings: Annotated[Optional[dict], Field(description="Settings object for create/update", default=None)] = None,
    selection: Annotated[Optional[dict], Field(description="Selection criteria for delete", default=None)] = None,
) -> str:
    """
    Manages authentication (IdP/SSO) settings in Cortex XDR.
    Actions: list (current settings), metadata (available IdP metadata),
    create, update, delete.

    Args:
        ctx: FastMCP context.
        action: The action to perform.
        settings: Settings definition for create/update.
        selection: Selection criteria for delete.

    Returns:
        JSON with authentication settings or operation result.
    """
    try:
        fetcher = await get_fetcher(ctx)
        if action == "list":
            response_data = await fetcher.send_request("authentication-settings/get/settings", data={"request_data": {}})
            return create_response(data={"items": response_data.get("reply", response_data)})
        elif action == "metadata":
            response_data = await fetcher.send_request("authentication-settings/get/metadata", data={"request_data": {}})
            return create_response(data={"items": response_data.get("reply", response_data)})
        elif action == "create":
            if not settings:
                return create_response(data={"error": "settings is required for create"}, is_error=True)
            response_data = await fetcher.send_request("authentication-settings/create", data={"request_data": settings})
            return create_response(data=response_data)
        elif action == "update":
            if not settings:
                return create_response(data={"error": "settings is required for update"}, is_error=True)
            response_data = await fetcher.send_request("authentication-settings/update", data={"request_data": settings})
            return create_response(data=response_data)
        elif action == "delete":
            response_data = await fetcher.send_request("authentication-settings/delete", data={"request_data": selection or {}})
            return create_response(data=response_data)
        else:
            return create_response(data={"error": "action must be one of: list, metadata, create, update, delete"}, is_error=True)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error managing authentication settings: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to manage authentication settings: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


# ── Module Registration ───────────────────────────────────────────────────────

class IntelligenceModule(BaseModule):
    """
    Intelligence & administration module ported from Brad-Edwards/Cortex-XDR-MCP.

    Tools:
        Risk Intelligence:
        - list_risky_entities: Ranked list of riskiest hosts or users.
        - get_entity_risk: Risk score and reasons for a specific host/user.
        - get_incident_casefile: Comprehensive incident dossier with artifacts.
        - get_endpoint_context: Enriched endpoint details including risk score.

        Device Control:
        - list_device_control_violations: USB/peripheral violations by endpoint or user.

        Exception & Override Rules:
        - manage_exception_rule: CRUD for legacy exception rules.
        - manage_prevention_override: Manage disable-prevention and disable-injection rules.

        RBAC:
        - list_rbac_users: All tenant users.
        - list_rbac_roles: All RBAC roles.
        - list_user_groups: All user groups.
        - set_user_role: Assign role to user.

        Agent Packages:
        - manage_agent_packages: Create/list/download/delete agent distributions.

        Endpoint Tags:
        - manage_endpoint_tags: Assign or remove tags from endpoints.

        Integrations:
        - manage_syslog_integration: CRUD for syslog integrations.
        - manage_xql_dataset: CRUD for XQL datasets.
        - manage_lookup_dataset: CRUD for lookup dataset data.
        - manage_authentication_settings: CRUD for IdP/SSO authentication settings.
    """

    def register_tools(self):
        self._add_tool(list_risky_entities)
        self._add_tool(get_entity_risk)
        self._add_tool(get_incident_casefile)
        self._add_tool(get_endpoint_context)
        self._add_tool(list_device_control_violations)
        self._add_tool(manage_exception_rule)
        self._add_tool(manage_prevention_override)
        self._add_tool(list_rbac_users)
        self._add_tool(list_rbac_roles)
        self._add_tool(list_user_groups)
        self._add_tool(set_user_role)
        self._add_tool(manage_agent_packages)
        self._add_tool(manage_endpoint_tags)
        self._add_tool(manage_syslog_integration)
        self._add_tool(manage_xql_dataset)
        self._add_tool(manage_lookup_dataset)
        self._add_tool(manage_authentication_settings)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
