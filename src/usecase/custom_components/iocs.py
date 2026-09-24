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


async def add_iocs(
    ctx: Context,
    iocs: Annotated[list[dict], Field(description=(
        "List of IOC dicts. Each IOC must have: "
        "'indicator' (the value), 'type' (HASH|DOMAIN_NAME|IP|URL), "
        "'severity' (INFO|LOW|MEDIUM|HIGH|CRITICAL), 'reputation' (GOOD|SUSPICIOUS|BAD), "
        "optional: 'comment', 'expiration_date' (epoch ms). "
        "Example: [{\"indicator\": \"1.2.3.4\", \"type\": \"IP\", \"severity\": \"HIGH\", \"reputation\": \"BAD\", \"comment\": \"C2 server\"}]"
    ))],
) -> str:
    """
    Adds one or more Indicators of Compromise (IOCs) to Cortex XDR.
    Supported types: IP addresses, domains, URLs, and file hashes.

    Args:
        ctx: FastMCP context.
        iocs: List of IOC dicts with indicator, type, severity, and reputation.

    Returns:
        JSON confirming how many IOCs were added.
    """
    payload = {"request_data": iocs, "validate": True}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("indicators/tim_insert_jsons/", data=payload, headers={"x-iocs-source": "xsoar"})
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error adding IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to add IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


_IOC_EPOCH_DEFAULT = 1577836800000  # 2020-01-01 00:00:00 UTC — effectively "get all"


async def get_iocs(
    ctx: Context,
    last_update_ts: Annotated[int, Field(description="Epoch milliseconds. Returns IOCs modified since this timestamp. Defaults to 2020-01-01 to retrieve all IOCs.", default=_IOC_EPOCH_DEFAULT)] = _IOC_EPOCH_DEFAULT,
) -> str:
    """
    Retrieves IOCs from Cortex XDR modified since a given timestamp.

    Args:
        ctx: FastMCP context.
        last_update_ts: Epoch milliseconds. IOCs modified after this time are returned.
                        Defaults to 2020-01-01 to retrieve all existing IOCs.

    Returns:
        JSON with IOC list.
    """
    payload = {"request_data": {"last_update_ts": last_update_ts}}

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("indicators/get_changes", data=payload, headers={"x-iocs-source": "xsoar"})
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def delete_iocs(
    ctx: Context,
    indicator_list: Annotated[list[str], Field(description="List of indicator values to delete (e.g. ['1.2.3.4', 'evil.com'])")],
) -> str:
    """
    Deletes IOCs from Cortex XDR by indicator value.

    Args:
        ctx: FastMCP context.
        indicator_list: List of indicator values to remove.

    Returns:
        JSON confirming deletion.
    """
    payload = {"request_data": indicator_list}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("indicators/disable_iocs", data=payload, headers={"x-iocs-source": "xsoar"})
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error deleting IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to delete IOCs: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IOCsModule(BaseModule):
    """
    Custom module for Cortex XDR IOC management.

    Tools:
        - add_iocs: Add IP, domain, URL, or hash IOCs.
        - get_iocs: Search and filter existing IOCs.
        - delete_iocs: Remove IOCs by indicator value.
    """

    def register_tools(self):
        self._add_tool(add_iocs)
        self._add_tool(get_iocs)
        self._add_tool(delete_iocs)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
