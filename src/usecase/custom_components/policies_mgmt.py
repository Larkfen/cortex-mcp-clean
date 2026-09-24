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


async def get_policy(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="Endpoint ID to retrieve the assigned policy for")],
) -> str:
    """
    Retrieves the security policy currently assigned to an endpoint.

    Args:
        ctx: FastMCP context.
        endpoint_id: The endpoint ID.

    Returns:
        JSON with policy name and configuration.
    """
    payload = {"request_data": {"endpoint_id": endpoint_id}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/get_policy/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting policy: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get policy: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_policy_rules(
    ctx: Context,
    policy_name: Annotated[Optional[str], Field(description="Filter by specific policy name")] = None,
) -> str:
    """
    Retrieves endpoint policy rules from Cortex XDR.

    Args:
        ctx: FastMCP context.
        policy_name: Optional policy name filter.

    Returns:
        JSON with policy rules list.
    """
    filters = []
    if policy_name:
        filters.append({"field": "policy_name", "operator": "eq", "value": policy_name})

    payload: dict = {"request_data": {}}
    if filters:
        payload["request_data"]["filters"] = filters

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/get_rules/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting policy rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get policy rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def assign_policy(
    ctx: Context,
    endpoint_ids: Annotated[list[str], Field(description="List of endpoint IDs to assign the policy to")],
    policy_name: Annotated[str, Field(description="Name of the policy to assign")],
) -> str:
    """
    Assigns a security policy to one or more endpoints.

    Args:
        ctx: FastMCP context.
        endpoint_ids: List of target endpoint IDs.
        policy_name: Name of the policy to assign.

    Returns:
        JSON confirming the policy assignment.
    """
    payload = {
        "request_data": {
            "endpoint_ids": endpoint_ids,
            "policy_name": policy_name,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/assign_policy/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error assigning policy: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to assign policy: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_endpoint_violations(
    ctx: Context,
    endpoint_ids: Annotated[Optional[list[str]], Field(description="Filter by specific endpoint IDs")] = None,
    violation_type: Annotated[Optional[str], Field(description="Filter by violation type: disk_encryption | firewall | os_version | password | unmanaged_device")] = None,
    search_from: Annotated[int, Field(description="Pagination start", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100", default=30)] = 30,
) -> str:
    """
    Retrieves policy violations on endpoints (disk encryption, firewall, OS version, etc.).

    Args:
        ctx: FastMCP context.
        endpoint_ids: Filter by specific endpoints.
        violation_type: Filter by violation type.
        search_from: Pagination start.
        search_to: Pagination end.

    Returns:
        JSON with policy violations list.
    """
    filters = []
    if endpoint_ids:
        filters.append({"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids})
    if violation_type:
        filters.append({"field": "type", "operator": "eq", "value": violation_type})

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
        response_data = await fetcher.send_request("device_control/get_violations/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting violations: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get violations: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class PoliciesMgmtModule(BaseModule):
    """
    Custom module for Cortex XDR policy management.

    Tools:
        - get_policy: Get policy assigned to an endpoint.
        - get_policy_rules: List policy rules.
        - assign_policy: Assign a policy to endpoints.
        - get_endpoint_violations: Get policy violations on endpoints.
    """

    def register_tools(self):
        self._add_tool(get_policy)
        self._add_tool(get_policy_rules)
        self._add_tool(assign_policy)
        self._add_tool(get_endpoint_violations)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
