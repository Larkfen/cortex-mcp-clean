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

_PAPI_ERRORS = (
    PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
    PAPIClientRequestError, PAPIResponseError, PAPIClientError,
)


async def _safe_request(fetcher, endpoint: str, payload: dict) -> Optional[dict]:
    try:
        return await fetcher.send_request(endpoint, data=payload)
    except Exception as e:
        logger.warning(f"Non-fatal error querying {endpoint}: {e}")
        return None


async def correlate_ioc(
    ctx: Context,
    indicator: Annotated[str, Field(description=(
        "The IOC value to correlate. Supports: IP address, domain, URL, SHA256 hash. "
        "Example: '185.220.101.5', 'evil.example.com', 'd41d8cd98f00b204e9800998ecf8427e'"
    ))],
    indicator_type: Annotated[
        str,
        Field(description="IOC type: IP | DOMAIN_NAME | URL | HASH (SHA256). Required to route the right queries.")
    ],
    timeframe_hours: Annotated[int, Field(description="Lookback window in hours for alert and XQL searches (default 168 = 7 days)", default=168)] = 168,
) -> str:
    """
    Performs cross-source correlation for a single IOC across Cortex XDR data.

    Searches in parallel across:
    - Existing IOC database (registered indicators)
    - Alerts (filtered by the indicator value)
    - XQL datasets (endpoint telemetry for the indicator)

    Returns a consolidated view: where the IOC appears, which alerts reference it,
    associated endpoints, and risk context. Replaces 4-5 manual queries.

    Args:
        ctx: FastMCP context.
        indicator: The IOC value to search.
        indicator_type: One of IP, DOMAIN_NAME, URL, HASH.
        timeframe_hours: Hours of lookback for alert and XQL searches.

    Returns:
        JSON with correlated findings across all sources.
    """
    fetcher = await get_fetcher(ctx)
    timeframe_ms = timeframe_hours * 60 * 60 * 1000

    # --- Build parallel tasks ---

    # 1. Check IOC database
    ioc_payload = {"request_data": {"last_update_ts": 1577836800000}}

    # 2. Alert search — filter depends on IOC type
    alert_filters: list[dict] = []
    if indicator_type == "IP":
        alert_filters = [{"field": "action_remote_ip", "operator": "contains", "value": indicator}]
    elif indicator_type == "DOMAIN_NAME":
        alert_filters = [{"field": "dns_query_name", "operator": "contains", "value": indicator}]
    elif indicator_type == "HASH":
        alert_filters = [{"field": "actor_process_image_sha256", "operator": "eq", "value": indicator}]
    elif indicator_type == "URL":
        alert_filters = [{"field": "action_remote_url", "operator": "contains", "value": indicator}]

    alert_payload = {
        "request_data": {
            "filters": alert_filters,
            "search_from": 0,
            "search_to": 50,
            "sort": {"field": "detection_timestamp", "keyword": "desc"},
        }
    }

    # 3. XQL search — universal hunt across endpoint telemetry
    xql_query_map = {
        "IP": (
            f"dataset=xdr_data "
            f"| filter action_remote_ip = \"{indicator}\" or action_local_ip = \"{indicator}\" "
            f"| fields event_timestamp, host_name, actor_process_image_name, action_remote_ip, action_remote_port "
            f"| limit 30"
        ),
        "DOMAIN_NAME": (
            f"dataset=xdr_data "
            f"| filter dns_query_name contains \"{indicator}\" "
            f"| fields event_timestamp, host_name, actor_process_image_name, dns_query_name "
            f"| limit 30"
        ),
        "HASH": (
            f"dataset=xdr_data "
            f"| filter actor_process_image_sha256 = \"{indicator}\" or action_file_sha256 = \"{indicator}\" "
            f"| fields event_timestamp, host_name, actor_process_image_name, actor_process_image_sha256 "
            f"| limit 30"
        ),
        "URL": (
            f"dataset=xdr_data "
            f"| filter action_remote_url contains \"{indicator}\" "
            f"| fields event_timestamp, host_name, actor_process_image_name, action_remote_url "
            f"| limit 30"
        ),
    }
    xql_query = xql_query_map.get(indicator_type, "")
    xql_payload = {
        "request_data": {
            "query": xql_query,
            "timeframe": {"relativeTime": timeframe_ms},
        }
    }

    try:
        # Fire IOC DB check and alert search in parallel
        ioc_task = asyncio.create_task(_safe_request(fetcher, "indicators/get_changes", {
            "request_data": {"last_update_ts": 1577836800000}
        }))
        alert_task = asyncio.create_task(_safe_request(fetcher, "alerts/get_alerts_by_filter_data/", alert_payload))

        # Start XQL query
        xql_resp = await _safe_request(fetcher, "xql/start_xql_query/", xql_payload)
        execution_id = None
        if xql_resp:
            reply = xql_resp.get("reply", {})
            execution_id = reply.get("execution_id") if isinstance(reply, dict) else reply

        # Wait for parallel tasks
        ioc_resp, alert_resp = await asyncio.gather(ioc_task, alert_task)

        # Poll XQL results
        xql_results = None
        if execution_id:
            poll_payload = {"request_data": {"query_id": execution_id, "expected_result_type": "JSON"}}
            for _ in range(15):
                await asyncio.sleep(2)
                poll = await _safe_request(fetcher, "xql/get_query_results/", poll_payload)
                if poll:
                    status = poll.get("reply", {}).get("status") if isinstance(poll.get("reply"), dict) else None
                    if status == "SUCCESS":
                        xql_results = poll.get("reply", {}).get("results")
                        break
                    if status in ("FAILED", "CANCELED"):
                        break

        # --- Extract and correlate ---
        # IOC: filter to the specific indicator
        ioc_match = None
        if ioc_resp:
            ioc_list = ioc_resp.get("reply", []) if isinstance(ioc_resp, dict) else []
            if isinstance(ioc_list, list):
                ioc_match = next((i for i in ioc_list if i.get("indicator") == indicator), None)

        # Alerts
        alerts_found = []
        if alert_resp:
            alert_data = alert_resp.get("reply", {})
            alerts_found = alert_data.get("alerts", []) if isinstance(alert_data, dict) else []

        # Unique hosts from XQL
        xql_hosts: set[str] = set()
        xql_rows = []
        if xql_results and isinstance(xql_results, dict):
            for row in (xql_results.get("data") or []):
                xql_rows.append(row)
                if row.get("host_name"):
                    xql_hosts.add(row["host_name"])

        result = {
            "indicator": indicator,
            "type": indicator_type,
            "timeframe_hours": timeframe_hours,
            "ioc_registered": ioc_match is not None,
            "ioc_details": ioc_match,
            "alert_count": len(alerts_found),
            "alerts": [
                {
                    "alert_id": a.get("alert_id"),
                    "name": a.get("name") or a.get("alert_name"),
                    "severity": a.get("severity"),
                    "host": a.get("host_name") or a.get("hostname"),
                    "timestamp": a.get("detection_timestamp"),
                }
                for a in alerts_found[:20]
            ],
            "endpoint_hits": list(xql_hosts),
            "telemetry_rows": xql_rows[:20],
            "risk_summary": (
                "HIGH — Active in alerts and endpoint telemetry" if alerts_found and xql_rows
                else "MEDIUM — Found in telemetry only" if xql_rows
                else "LOW — No active hits found in this timeframe"
            ),
        }

        return create_response(data=result)

    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error correlating IOC {indicator}: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to correlate IOC {indicator}: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IOCCorrelationModule(BaseModule):
    """
    Module for cross-source IOC correlation in Cortex XDR.

    Tools:
        - correlate_ioc: Given an IOC (IP/domain/hash/URL), search in parallel across
          the IOC database, alerts, and XQL endpoint telemetry — returns a consolidated
          risk summary in one call.
    """

    def register_tools(self):
        self._add_tool(correlate_ioc)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
