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


async def get_audit_management_logs(
    ctx: Context,
    search_from: Annotated[int, Field(description="Pagination start", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100", default=50)] = 50,
    email: Annotated[Optional[str], Field(description="Filter by user email who performed the action")] = None,
    from_timestamp: Annotated[Optional[int], Field(description="Start time filter in epoch milliseconds")] = None,
    to_timestamp: Annotated[Optional[int], Field(description="End time filter in epoch milliseconds")] = None,
) -> str:
    """
    Retrieves the management audit log — actions performed by users in the Cortex console
    (policy changes, user management, configuration changes, etc.).

    Args:
        ctx: FastMCP context.
        search_from: Pagination start.
        search_to: Pagination end.
        email: Filter by user who performed the action.
        from_timestamp: Start time in epoch ms.
        to_timestamp: End time in epoch ms.

    Returns:
        JSON with audit log entries.
    """
    filters = []
    if email:
        filters.append({"field": "email", "operator": "eq", "value": email})
    if from_timestamp:
        filters.append({"field": "TIMESTAMP", "operator": "gte", "value": from_timestamp})
    if to_timestamp:
        filters.append({"field": "TIMESTAMP", "operator": "lte", "value": to_timestamp})

    payload: dict = {
        "request_data": {
            "search_from": search_from,
            "search_to": min(search_to, 100),
            "sort": {"field": "TIMESTAMP", "keyword": "desc"},
        }
    }
    if filters:
        payload["request_data"]["filters"] = filters

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("audits/management_logs/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting management audit logs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get management audit logs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_audit_agent_logs(
    ctx: Context,
    endpoint_ids: Annotated[Optional[list[str]], Field(description="Filter by specific endpoint IDs")] = None,
    endpoint_name: Annotated[Optional[str], Field(description="Filter by partial endpoint name")] = None,
    search_from: Annotated[int, Field(description="Pagination start", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100", default=50)] = 50,
) -> str:
    """
    Retrieves agent audit logs — events reported by the XDR agent on endpoints
    (agent upgrades, policy updates, scan results, etc.).

    Args:
        ctx: FastMCP context.
        endpoint_ids: Filter by specific endpoint IDs.
        endpoint_name: Filter by partial endpoint hostname.
        search_from: Pagination start.
        search_to: Pagination end.

    Returns:
        JSON with agent audit log entries.
    """
    filters = []
    if endpoint_ids:
        filters.append({"field": "endpoint_id", "operator": "in", "value": endpoint_ids})
    if endpoint_name:
        filters.append({"field": "endpoint_name", "operator": "contains", "value": endpoint_name})

    payload: dict = {
        "request_data": {
            "search_from": search_from,
            "search_to": min(search_to, 100),
        }
    }
    if filters:
        payload["request_data"]["filters"] = filters

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("audits/agents_reports/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting agent audit logs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get agent audit logs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class AuditModule(BaseModule):
    """
    Custom module for Cortex XDR audit log retrieval.

    Tools:
        - get_audit_management_logs: Console actions by users (config changes, policy updates).
        - get_audit_agent_logs: Agent events on endpoints (upgrades, scans, policy apply).
    """

    def register_tools(self):
        self._add_tool(get_audit_management_logs)
        self._add_tool(get_audit_agent_logs)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
