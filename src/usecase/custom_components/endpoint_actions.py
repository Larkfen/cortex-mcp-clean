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


async def isolate_endpoint(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="ID of the endpoint to isolate (blocks all network except Cortex communication)")],
) -> str:
    """
    Isolates an endpoint from the network. All traffic is blocked except communication with Cortex.
    Use this for active threat containment.

    Args:
        ctx: FastMCP context.
        endpoint_id: The endpoint ID to isolate.

    Returns:
        JSON with action ID and status.
    """
    payload = {"request_data": {"endpoint_id": endpoint_id}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/isolate/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error isolating endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to isolate endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def unisolate_endpoint(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="ID of the endpoint to remove from isolation")],
) -> str:
    """
    Removes an endpoint from isolation, restoring normal network access.

    Args:
        ctx: FastMCP context.
        endpoint_id: The endpoint ID to unisolate.

    Returns:
        JSON with action ID and status.
    """
    payload = {"request_data": {"endpoint_id": endpoint_id}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/unisolate/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error unisolating endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to unisolate endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def scan_endpoint(
    ctx: Context,
    endpoint_id_list: Annotated[list[str], Field(description="List of endpoint IDs to scan for malware")],
) -> str:
    """
    Initiates a malware scan on one or more endpoints.

    Args:
        ctx: FastMCP context.
        endpoint_id_list: List of endpoint IDs to scan.

    Returns:
        JSON with action ID and status.
    """
    payload = {"request_data": {"endpoint_id_list": endpoint_id_list}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/scan/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error scanning endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to scan endpoint: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_endpoint_details(
    ctx: Context,
    endpoint_id_list: Annotated[Optional[list[str]], Field(description="List of endpoint IDs to retrieve. Leave empty to get all.")] = None,
    endpoint_name: Annotated[Optional[str], Field(description="Filter by partial endpoint hostname")] = None,
    ip_list: Annotated[Optional[list[str]], Field(description="Filter by IP address list")] = None,
    search_from: Annotated[int, Field(description="Pagination start", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100", default=30)] = 30,
) -> str:
    """
    Retrieves detailed information about endpoints including OS, agent version, isolation status, and last seen.

    Args:
        ctx: FastMCP context.
        endpoint_id_list: Specific endpoint IDs to retrieve.
        endpoint_name: Partial hostname filter.
        ip_list: IP address filter list.
        search_from: Pagination start.
        search_to: Pagination end.

    Returns:
        JSON with endpoint details.
    """
    filters = []
    if endpoint_id_list:
        filters.append({"field": "endpoint_id_list", "operator": "in", "value": endpoint_id_list})
    if endpoint_name:
        filters.append({"field": "endpoint_name", "operator": "contains", "value": endpoint_name})
    if ip_list:
        filters.append({"field": "ip_list", "operator": "in", "value": ip_list})

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
        response_data = await fetcher.send_request("endpoints/get_endpoint/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting endpoint details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get endpoint details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_action_status(
    ctx: Context,
    action_id: Annotated[str, Field(description="Action ID returned by isolate, scan, script, or other endpoint actions")],
) -> str:
    """
    Gets the status of a previously triggered endpoint action (isolate, scan, script, etc.).

    Args:
        ctx: FastMCP context.
        action_id: The action ID to check.

    Returns:
        JSON with action status and result per endpoint.
    """
    payload = {"request_data": {"group_action_id": action_id}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("actions/get_action_status/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting action status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get action status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class EndpointActionsModule(BaseModule):
    """
    Custom module for Cortex XDR endpoint response actions.

    Tools:
        - isolate_endpoint: Isolate endpoint from the network.
        - unisolate_endpoint: Remove endpoint isolation.
        - scan_endpoint: Trigger malware scan.
        - get_endpoint_details: Get full endpoint info.
        - get_action_status: Check status of any endpoint action.
    """

    def register_tools(self):
        self._add_tool(isolate_endpoint)
        self._add_tool(unisolate_endpoint)
        self._add_tool(scan_endpoint)
        self._add_tool(get_endpoint_details)
        self._add_tool(get_action_status)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
