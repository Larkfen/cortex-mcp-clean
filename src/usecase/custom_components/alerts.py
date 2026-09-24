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


async def get_alerts(
    ctx: Context,
    filters: Annotated[list[dict], Field(description=(
        "Filter list. Allowed fields: "
        "'alert_id' (list of str), 'severity' (low|medium|high|critical), "
        "'status' (new|under_investigation|resolved_true_positive|resolved_false_positive|resolved_other), "
        "'source' (XDR Analytics|XDR Analytics BIOC|Correlation|...), "
        "'host_name' (str), 'user_name' (str), "
        "'creation_time' with operator gte/lte (epoch ms). "
        "Example: [{\"field\": \"severity\", \"operator\": \"in\", \"value\": [\"high\", \"critical\"]}]"
    ))] = [],
    search_from: Annotated[int, Field(description="Pagination start (default 0)", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100 (default 25)", default=25)] = 25,
    sort: Annotated[Optional[dict], Field(description="Sort: {\"field\": \"creation_time\", \"keyword\": \"desc\"}")] = None,
) -> str:
    """
    Retrieves alerts from Cortex XDR with optional filtering.
    Alerts are the individual detections that make up incidents.

    Args:
        ctx: FastMCP context.
        filters: List of filter dicts.
        search_from: Pagination start.
        search_to: Pagination end (max 100).
        sort: Sort field and direction.

    Returns:
        JSON with alerts list and total count.
    """
    payload: dict = {
        "request_data": {
            "search_from": search_from,
            "search_to": min(search_to, 100),
        }
    }
    if filters:
        payload["request_data"]["filters"] = filters
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("alerts/get_alerts/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting alerts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get alerts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def update_alert(
    ctx: Context,
    alert_id_list: Annotated[list[str], Field(description="List of alert IDs to update")],
    status: Annotated[Optional[str], Field(description="New status: new | under_investigation | resolved_true_positive | resolved_false_positive | resolved_other")] = None,
    severity: Annotated[Optional[str], Field(description="Override severity: low | medium | high | critical")] = None,
    comment: Annotated[Optional[str], Field(description="Comment to add to the alert")] = None,
) -> str:
    """
    Updates one or more alerts: status, severity, or adds a comment.

    Args:
        ctx: FastMCP context.
        alert_id_list: List of alert ID strings to update.
        status: New status.
        severity: Severity override.
        comment: Comment text.

    Returns:
        JSON confirming the update.
    """
    update_data: dict = {}
    if status:
        update_data["status"] = status
    if severity:
        update_data["severity"] = severity
    if comment:
        update_data["comment"] = comment

    if not update_data:
        return create_response(data={"error": "No update fields provided"}, is_error=True)

    payload = {
        "request_data": {
            "alert_id_list": alert_id_list,
            "update_data": update_data,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        # Path oficial: alerts/update_alerts/ (plural); update_alert/ singular puede devolver 500.
        response_data = await fetcher.send_request("alerts/update_alerts/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error updating alert: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to update alert: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class AlertsModule(BaseModule):
    """
    Custom module for Cortex XDR alert management.

    Tools:
        - get_alerts: Search and filter alerts.
        - update_alert: Update status, severity, or add comments to alerts.
    """

    def register_tools(self):
        self._add_tool(get_alerts)
        self._add_tool(update_alert)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
