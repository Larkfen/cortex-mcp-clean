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


async def blocklist_files(
    ctx: Context,
    hash_list: Annotated[list[str], Field(description="List of SHA256 hashes to block execution of")],
    comment: Annotated[str, Field(description="Reason or comment for blocking these hashes", default="")] = "",
) -> str:
    """
    Adds SHA256 file hashes to the blocklist, preventing execution on all protected endpoints.

    Args:
        ctx: FastMCP context.
        hash_list: List of SHA256 hashes to block.
        comment: Optional reason/comment.

    Returns:
        JSON confirming the operation.
    """
    payload = {"request_data": {"hash_list": hash_list, "comment": comment}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("hash_exceptions/blocklist/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error blocklisting files: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to blocklist files: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def allowlist_files(
    ctx: Context,
    hash_list: Annotated[list[str], Field(description="List of SHA256 hashes to allow (whitelist)")],
    comment: Annotated[str, Field(description="Reason or comment for allowing these hashes", default="")] = "",
) -> str:
    """
    Adds SHA256 file hashes to the allowlist, preventing false positive detections.

    Args:
        ctx: FastMCP context.
        hash_list: List of SHA256 hashes to allow.
        comment: Optional reason/comment.

    Returns:
        JSON confirming the operation.
    """
    payload = {"request_data": {"hash_list": hash_list, "comment": comment}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("hash_exceptions/allowlist/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error allowlisting files: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to allowlist files: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def retrieve_file(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="ID of the endpoint to retrieve the file from")],
    file_path: Annotated[str, Field(description="Full path of the file on the endpoint. Example: C:\\Users\\user\\Downloads\\suspicious.exe")],
    os_type: Annotated[str, Field(description="OS type of the endpoint: windows | linux | macos", default="windows")] = "windows",
) -> str:
    """
    Retrieves a file from an endpoint for forensic analysis. The file is uploaded to Cortex.

    Args:
        ctx: FastMCP context.
        endpoint_id: Source endpoint ID.
        file_path: Full file path on the endpoint.
        os_type: OS type of the endpoint (windows, linux, or macos).

    Returns:
        JSON with action ID to track the retrieval.
    """
    files_by_os: dict = {"windows": [], "linux": [], "macos": []}
    os_key = os_type.lower() if os_type.lower() in files_by_os else "windows"
    files_by_os[os_key] = [file_path]
    payload = {
        "request_data": {
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}],
            "files": files_by_os,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/file_retrieval/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error retrieving file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to retrieve file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def quarantine_file(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="ID of the endpoint containing the file")],
    file_path: Annotated[str, Field(description="Full path of the file to quarantine on the endpoint")],
    file_hash: Annotated[str, Field(description="SHA256 hash of the file to quarantine")],
) -> str:
    """
    Quarantines a specific file on an endpoint, preventing its execution.

    Args:
        ctx: FastMCP context.
        endpoint_id: Target endpoint ID.
        file_path: Full path to the file.
        file_hash: SHA256 hash of the file.

    Returns:
        JSON with action ID and status.
    """
    payload = {
        "request_data": {
            "endpoint_id": endpoint_id,
            "file_path": file_path,
            "file_hash": file_hash,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/quarantine/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error quarantining file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to quarantine file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_quarantine_status(
    ctx: Context,
    files: Annotated[list[dict], Field(description=(
        "List of file objects to check quarantine status. "
        "Each object must have: 'endpoint_id' (string), 'file_path' (string), 'file_hash' (SHA256 string). "
        "Example: [{\"endpoint_id\": \"ep1\", \"file_path\": \"C:\\\\temp\\\\mal.exe\", \"file_hash\": \"abc123...\"}]"
    ))],
) -> str:
    """
    Checks the quarantine status of files on endpoints.

    Args:
        ctx: FastMCP context.
        files: List of file objects with endpoint_id, file_path, and file_hash.

    Returns:
        JSON with quarantine status per file per endpoint.
    """
    payload = {"request_data": {"files": files}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("quarantine/status/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting quarantine status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get quarantine status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class FilesHashesModule(BaseModule):
    """
    Custom module for Cortex XDR file and hash management.

    Tools:
        - blocklist_files: Block SHA256 hashes across all endpoints.
        - allowlist_files: Allow SHA256 hashes (whitelist).
        - retrieve_file: Pull a file from an endpoint for analysis.
        - quarantine_file: Quarantine a specific file on an endpoint.
        - get_quarantine_status: Check quarantine status of files.
    """

    def register_tools(self):
        self._add_tool(blocklist_files)
        self._add_tool(allowlist_files)
        self._add_tool(retrieve_file)
        self._add_tool(quarantine_file)
        self._add_tool(get_quarantine_status)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
