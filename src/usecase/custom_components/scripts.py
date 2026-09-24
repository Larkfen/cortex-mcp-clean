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


async def list_scripts(
    ctx: Context,
    script_name: Annotated[Optional[str], Field(description="Filter by partial script name")] = None,
) -> str:
    """
    Lists available scripts in the Cortex XDR script library.

    Args:
        ctx: FastMCP context.
        script_name: Optional partial name filter.

    Returns:
        JSON with script list including name, description, and supported OS.
    """
    filters = []
    if script_name:
        filters.append({"field": "name", "operator": "contains", "value": script_name})

    payload: dict = {"request_data": {}}
    if filters:
        payload["request_data"]["filters"] = filters

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("scripts/get_scripts/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing scripts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list scripts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def run_script(
    ctx: Context,
    endpoint_ids: Annotated[list[str], Field(description="List of endpoint IDs to run the script on")],
    script_uid: Annotated[str, Field(description="UID of the script from the Cortex script library (use list_scripts to find the script_uid)")],
    parameters: Annotated[Optional[dict], Field(description="Script parameters as key-value pairs. Example: {\"file_path\": \"C:\\\\temp\\\\test.txt\"}")] = None,
    timeout: Annotated[int, Field(description="Script execution timeout in seconds (default 600)", default=600)] = 600,
) -> str:
    """
    Runs a script from the Cortex library on one or more endpoints.
    Use list_scripts first to find the script_uid field.

    Args:
        ctx: FastMCP context.
        endpoint_ids: Target endpoint ID list.
        script_uid: Script UID from list_scripts.
        parameters: Script parameter dict.
        timeout: Execution timeout in seconds.

    Returns:
        JSON with action ID to track execution status.
    """
    payload = {
        "request_data": {
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}],
            "script_uid": script_uid,
            "parameters_values": parameters or {},
            "timeout": timeout,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("scripts/run_script/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error running script: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to run script: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_script_execution_status(
    ctx: Context,
    action_id: Annotated[str, Field(description="Action ID returned by run_script")],
) -> str:
    """
    Gets the execution status of a script run on endpoints.

    Args:
        ctx: FastMCP context.
        action_id: Action ID from run_script.

    Returns:
        JSON with status per endpoint (pending, in_progress, completed, failed).
    """
    payload = {"request_data": {"action_id": action_id}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("scripts/get_script_execution_status/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting script status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get script status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_script_execution_results(
    ctx: Context,
    action_id: Annotated[str, Field(description="Action ID from run_script")],
    endpoint_id: Annotated[Optional[str], Field(description="Endpoint ID to get results for (optional, filters results to specific endpoint)")] = None,
) -> str:
    """
    Retrieves the output/results of a completed script execution.

    Args:
        ctx: FastMCP context.
        action_id: Action ID from run_script.
        endpoint_id: Optional endpoint ID to filter results.

    Returns:
        JSON with script stdout, stderr, and exit code.
    """
    request_data: dict = {"action_id": action_id}
    if endpoint_id:
        request_data["endpoint_id"] = endpoint_id
    payload = {"request_data": request_data}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("scripts/get_script_execution_results/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting script results: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get script results: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def run_snippet_code(
    ctx: Context,
    endpoint_ids: Annotated[list[str], Field(description="List of endpoint IDs to run the code on")],
    code: Annotated[str, Field(description="Python code snippet to execute on the endpoint")],
    timeout: Annotated[int, Field(description="Execution timeout in seconds (default 600)", default=600)] = 600,
) -> str:
    """
    Executes a custom Python code snippet on one or more endpoints via the Cortex agent.

    Args:
        ctx: FastMCP context.
        endpoint_ids: Target endpoint ID list.
        code: Python code to execute.
        timeout: Execution timeout in seconds.

    Returns:
        JSON with action ID to track execution.
    """
    payload = {
        "request_data": {
            "endpoint_ids": endpoint_ids,
            "snippet_code": code,
            "timeout": timeout,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("scripts/run_snippet_code/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error running snippet: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to run snippet: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ScriptsModule(BaseModule):
    """
    Custom module for Cortex XDR remote script execution.

    Tools:
        - list_scripts: List available scripts in the library.
        - run_script: Execute a library script on endpoints.
        - get_script_execution_status: Check script execution status.
        - get_script_execution_results: Get script output and results.
        - run_snippet_code: Execute custom Python code on endpoints.
    """

    def register_tools(self):
        self._add_tool(list_scripts)
        self._add_tool(run_script)
        self._add_tool(get_script_execution_status)
        self._add_tool(get_script_execution_results)
        self._add_tool(run_snippet_code)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
