import logging
from datetime import datetime, timezone
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

_NOW_MS = lambda: int(datetime.now(tz=timezone.utc).timestamp() * 1000)


async def get_coverage_gaps(
    ctx: Context,
    stale_days: Annotated[int, Field(description="Days without communication to flag endpoint as stale (default 7)", default=7)] = 7,
    search_to: Annotated[int, Field(description="Max endpoints to evaluate (default 500)", default=500)] = 500,
) -> str:
    """
    Identifies endpoint coverage gaps in the Cortex XDR sensor fleet.

    Returns a breakdown of:
    - Stale endpoints (no communication for N days)
    - Isolated endpoints currently in network isolation
    - Endpoints with no active agent (disconnected status)
    - Summary statistics for the overall fleet health

    Use this for a weekly sensor health review or before an incident investigation
    to know which endpoints you cannot trust have current data.

    Args:
        ctx: FastMCP context.
        stale_days: Days since last communication to flag as stale.
        search_to: Max number of endpoints to pull.

    Returns:
        JSON with fleet summary, stale endpoints, isolated endpoints, and disconnected endpoints.
    """
    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": min(search_to, 1000),
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/get_endpoints/", data=payload)
        reply = response_data.get("reply", response_data) if isinstance(response_data, dict) else {}
        endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []

        if not endpoints:
            return create_response(data={"error": "No endpoints returned", "raw": reply}, is_error=True)

        now_ms = _NOW_MS()
        stale_cutoff_ms = stale_days * 24 * 60 * 60 * 1000

        stale = []
        isolated = []
        disconnected = []
        no_policy = []

        for ep in endpoints:
            last_seen = ep.get("last_seen") or 0
            status = (ep.get("endpoint_status") or "").lower()
            isolation = ep.get("is_isolated") or False
            policy = ep.get("policy_name") or ""

            ep_summary = {
                "endpoint_id": ep.get("endpoint_id"),
                "hostname": ep.get("endpoint_name") or ep.get("hostname"),
                "os": ep.get("os_type"),
                "agent_version": ep.get("agent_version"),
                "last_seen_ts": last_seen,
                "last_seen_iso": (
                    datetime.fromtimestamp(last_seen / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    if last_seen else "never"
                ),
                "status": status,
                "policy": policy or "none",
            }

            if last_seen and (now_ms - last_seen) > stale_cutoff_ms:
                days_silent = round((now_ms - last_seen) / (24 * 60 * 60 * 1000))
                stale.append({**ep_summary, "days_since_seen": days_silent})

            if isolation:
                isolated.append(ep_summary)

            if status in ("disconnected", "lost_connection", "offline"):
                disconnected.append(ep_summary)

            if not policy:
                no_policy.append(ep_summary)

        total = len(endpoints)
        result = {
            "fleet_summary": {
                "total_endpoints_evaluated": total,
                "stale_count": len(stale),
                "isolated_count": len(isolated),
                "disconnected_count": len(disconnected),
                "no_policy_count": len(no_policy),
                "coverage_score": round(((total - len(stale) - len(disconnected)) / total * 100), 1) if total else 0,
                "stale_threshold_days": stale_days,
            },
            "stale_endpoints": stale,
            "isolated_endpoints": isolated,
            "disconnected_endpoints": disconnected,
            "endpoints_without_policy": no_policy,
        }
        return create_response(data=result)

    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error getting coverage gaps: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get coverage gaps: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_agent_version_stats(
    ctx: Context,
    search_to: Annotated[int, Field(description="Max endpoints to evaluate (default 500)", default=500)] = 500,
) -> str:
    """
    Returns agent version distribution across the endpoint fleet.

    Shows which agent versions are in use, how many endpoints run each version,
    and which endpoints are running the oldest versions (bottom 20%).

    Use this to identify outdated agent versions that may lack recent
    detection capabilities or have known vulnerabilities.

    Args:
        ctx: FastMCP context.
        search_to: Max endpoints to evaluate.

    Returns:
        JSON with version distribution and list of oldest-version endpoints.
    """
    payload = {
        "request_data": {
            "search_from": 0,
            "search_to": min(search_to, 1000),
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/get_endpoints/", data=payload)
        reply = response_data.get("reply", response_data) if isinstance(response_data, dict) else {}
        endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []

        version_map: dict[str, list[str]] = {}
        for ep in endpoints:
            version = ep.get("agent_version") or "unknown"
            hostname = ep.get("endpoint_name") or ep.get("hostname") or ep.get("endpoint_id") or "unknown"
            version_map.setdefault(version, []).append(hostname)

        sorted_versions = sorted(version_map.keys(), reverse=True)
        distribution = [
            {"version": v, "count": len(version_map[v]), "endpoints": version_map[v][:10]}
            for v in sorted_versions
        ]

        oldest_cutoff = max(1, len(sorted_versions) // 5)
        oldest_versions = sorted_versions[-oldest_cutoff:] if sorted_versions else []
        outdated_endpoints = [
            {"hostname": h, "version": v}
            for v in oldest_versions
            for h in version_map[v]
        ]

        return create_response(data={
            "total_endpoints": len(endpoints),
            "unique_versions": len(sorted_versions),
            "version_distribution": distribution,
            "outdated_endpoints": outdated_endpoints,
            "outdated_count": len(outdated_endpoints),
        })

    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error getting agent version stats: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get agent version stats: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class SensorHealthModule(BaseModule):
    """
    Module for Cortex XDR sensor fleet health monitoring.

    Tools:
        - get_coverage_gaps: Find stale, isolated, disconnected, and unprotected endpoints.
        - get_agent_version_stats: Agent version distribution and oldest-version endpoints.
    """

    def register_tools(self):
        self._add_tool(get_coverage_gaps)
        self._add_tool(get_agent_version_stats)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
