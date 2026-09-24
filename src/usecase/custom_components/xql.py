import asyncio
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


async def run_xql_query(
    ctx: Context,
    query: Annotated[str, Field(description=(
        "XQL query to execute. Example: "
        "dataset=xdr_data | filter event_type = ENUM.PROCESS | fields actor_process_image_name, action_process_image_name | limit 20"
    ))],
    timeframe_minutes: Annotated[int, Field(description="Lookback window in minutes (default 1440 = 24h, max 10080 = 7 days)", default=1440)] = 1440,
    max_wait_seconds: Annotated[int, Field(description="Max seconds to wait for results (default 60)", default=60)] = 60,
) -> str:
    """
    Executes an XQL (Cortex Query Language) query for threat hunting and investigation.
    Automatically polls for results until complete or timeout is reached.

    Useful for:
    - Threat hunting across endpoint, network, and cloud data
    - Investigating specific processes, files, IPs, or users
    - Correlating events across multiple data sources

    Args:
        ctx: FastMCP context.
        query: XQL query string.
        timeframe_minutes: Lookback window in minutes.
        max_wait_seconds: Maximum seconds to wait for results.

    Returns:
        JSON with query results or error.
    """
    payload = {
        "request_data": {
            "query": query,
            "timeframe": {"relativeTime": timeframe_minutes * 60 * 1000},
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        start_resp = await fetcher.send_request("xql/start_xql_query/", data=payload)
        execution_id = start_resp.get("reply", {}).get("execution_id") if isinstance(start_resp.get("reply"), dict) else start_resp.get("reply")
        if not execution_id:
            return create_response(data={"error": "No execution_id returned", "raw": start_resp}, is_error=True)

        poll_payload = {"request_data": {"query_id": execution_id, "expected_result_type": "JSON"}}
        waited = 0
        while waited < max_wait_seconds:
            await asyncio.sleep(2)
            waited += 2
            poll_resp = await fetcher.send_request("xql/get_query_results/", data=poll_payload)
            reply = poll_resp.get("reply", {})
            status = reply.get("status")
            if status == "SUCCESS":
                return create_response(data=reply.get("results", reply))
            if status in ("FAILED", "CANCELED"):
                return create_response(data={"error": f"Query {status}", "detail": reply}, is_error=True)

        return create_response(data={"error": f"Timeout after {max_wait_seconds}s", "execution_id": execution_id}, is_error=True)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error running XQL: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to run XQL query: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_xql_query_results(
    ctx: Context,
    execution_id: Annotated[str, Field(description="Execution ID returned by a previous XQL query")],
) -> str:
    """
    Retrieves results of a previously started XQL query by execution ID.
    Use this if run_xql_query timed out but you want to check results later.

    Args:
        ctx: FastMCP context.
        execution_id: The execution ID from a previous run_xql_query call.

    Returns:
        JSON with query status and results.
    """
    payload = {"request_data": {"query_id": execution_id, "expected_result_type": "JSON"}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("xql/get_query_results/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting XQL results: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get XQL results: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class XQLModule(BaseModule):
    """
    Custom module for XQL (Cortex Query Language) threat hunting.

    Tools:
        - run_xql_query: Execute an XQL query and wait for results.
        - get_xql_query_results: Retrieve results of a previously started query.
    """

    def register_tools(self):
        self._add_tool(run_xql_query)
        self._add_tool(get_xql_query_results)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
