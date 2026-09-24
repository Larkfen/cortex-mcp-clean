import logging
from typing import Annotated

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

# WildFire verdict codes
_VERDICT_MAP = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    -100: "pending (not yet analyzed)",
    -101: "error",
    -102: "unknown",
    -103: "invalid hash",
}


async def get_wildfire_verdict(
    ctx: Context,
    hashes: Annotated[
        list[str],
        Field(description=(
            "List of SHA256 file hashes to query WildFire for. "
            "Example: ['d41d8cd98f00b204e9800998ecf8427e', 'a1b2c3...']"
        ))
    ],
) -> str:
    """
    Queries WildFire for verdicts on one or more SHA256 file hashes.
    Returns verdict per hash: benign, malware, grayware, phishing, or pending.

    Use this to validate IOCs, check suspicious files from endpoint alerts,
    or confirm whether a hash is known-malicious before blocking.

    Args:
        ctx: FastMCP context.
        hashes: List of SHA256 hashes to check.

    Returns:
        JSON with verdict per hash and human-readable label.
    """
    payload = {"request_data": {"hash_list": hashes}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("wildfire/get_verdict/", data=payload)
        reply = response_data.get("reply", response_data)

        # Enrich raw verdict codes with human-readable labels
        if isinstance(reply, dict) and "verdict_list" in reply:
            for item in reply["verdict_list"]:
                code = item.get("verdict")
                item["verdict_label"] = _VERDICT_MAP.get(code, f"unknown ({code})")

        return create_response(data=reply if isinstance(reply, dict) else {"raw": reply})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error querying WildFire verdict: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get WildFire verdict: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_wildfire_report(
    ctx: Context,
    hash_value: Annotated[str, Field(description="SHA256 hash to retrieve the full WildFire analysis report for")],
) -> str:
    """
    Retrieves the full WildFire analysis report for a single SHA256 hash.
    Includes behavior summary, network activity, registry changes, and dropped files
    observed during sandbox detonation.

    Use this after get_wildfire_verdict confirms a hash is malicious or grayware
    and you need the full behavioral breakdown for your incident report.

    Args:
        ctx: FastMCP context.
        hash_value: SHA256 hash to analyze.

    Returns:
        JSON with full WildFire behavioral report.
    """
    payload = {"request_data": {"hash": hash_value}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("wildfire/get_report/", data=payload)
        return create_response(data=response_data.get("reply", response_data) if isinstance(response_data, dict) else {"raw": response_data})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting WildFire report: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get WildFire report: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class WildFireModule(BaseModule):
    """
    Module for WildFire threat intelligence integration.

    Tools:
        - get_wildfire_verdict: Get verdict (malicious/benign/grayware) for SHA256 hashes.
        - get_wildfire_report: Full behavioral sandbox report for a hash.
    """

    def register_tools(self):
        self._add_tool(get_wildfire_verdict)
        self._add_tool(get_wildfire_report)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
