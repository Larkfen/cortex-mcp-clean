import logging
from typing import Annotated, Optional

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)


async def get_incidents(
    ctx: Context,
    filters: Annotated[
        list[dict],
        Field(description=(
            "Filters list. Leave empty to get all incidents. "
            "Allowed fields: 'status' (new, under_investigation, resolved_true_positive, resolved_false_positive, resolved_other), "
            "'severity' (low, medium, high, critical), 'incident_id_list' (list of int). "
            "Example: [{\"field\": \"severity\", \"operator\": \"in\", \"value\": [\"medium\", \"high\"]}]"
        ))
    ],
    search_from: Annotated[int, Field(description="Pagination start offset", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end offset, max 100", default=30)] = 30,
    sort: Annotated[
        Optional[dict],
        Field(description="Sort order. Example: {\"field\": \"creation_time\", \"keyword\": \"desc\"}. Allowed fields: creation_time, modification_time, severity.")
    ] = None,
) -> str:
    """
    Retrieves a list of incidents from Cortex XDR.
    Use this tool to search and filter security incidents by status, severity, or ID.
    Useful for security monitoring, triage, and reporting.

    Args:
        ctx: FastMCP context.
        filters: List of filter dicts. Leave empty to get all incidents.
        search_from: Pagination start (default 0).
        search_to: Pagination end (default 30, max 100).
        sort: Sort dict with 'field' and 'keyword' (asc/desc).

    Returns:
        JSON with incidents list and total count.
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
        response_data = await fetcher.send_request("incidents/get_incidents/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting incidents: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get incidents: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_incident_details(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident ID to retrieve full details for (e.g. '3217')")],
    alerts_limit: Annotated[int, Field(description="Max number of alerts to return (default 100)", default=100)] = 100,
) -> str:
    """
    Retrieves full details of a specific incident including alerts, network artifacts, and file artifacts.
    Use this tool when you need to investigate a specific incident in depth.

    Args:
        ctx: FastMCP context.
        incident_id: The incident ID string.
        alerts_limit: Maximum number of associated alerts to return.

    Returns:
        JSON with incident details, alerts, network artifacts, and file artifacts.
    """
    payload = {
        "request_data": {
            "incident_id": incident_id,
            "alerts_limit": alerts_limit,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("incidents/get_incident_extra_data/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting incident details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get incident details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def update_incident(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident ID to update (e.g. '3217')")],
    status: Annotated[
        Optional[str],
        Field(description="New status: new | under_investigation | resolved_true_positive | resolved_false_positive | resolved_other")
    ] = None,
    assigned_user_mail: Annotated[
        Optional[str],
        Field(description="Email of the analyst to assign the incident to (e.g. 'analyst@example.com')")
    ] = None,
    resolve_comment: Annotated[
        Optional[str],
        Field(description="Resolution comment explaining why the incident is being closed")
    ] = None,
    severity: Annotated[
        Optional[str],
        Field(description="Override severity: low | medium | high | critical")
    ] = None,
) -> str:
    """
    Updates an incident in Cortex XDR: status, assignment, resolution comment, or severity.
    Use this tool to close, assign, or add notes to an incident.

    Args:
        ctx: FastMCP context.
        incident_id: The incident ID string.
        status: New status value.
        assigned_user_mail: Email to assign the incident to.
        resolve_comment: Comment when resolving/closing the incident.
        severity: Manual severity override.

    Returns:
        JSON confirming the update (true if successful).
    """
    update_data: dict = {}
    if status:
        update_data["status"] = status
    if assigned_user_mail:
        update_data["assigned_user_mail"] = assigned_user_mail
    if resolve_comment:
        update_data["resolve_comment"] = resolve_comment
    if severity:
        update_data["manual_severity"] = severity

    if not update_data:
        return create_response(data={"error": "No update fields provided"}, is_error=True)

    payload = {
        "request_data": {
            "incident_id": incident_id,
            "update_data": update_data,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("incidents/update_incident/", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while updating incident: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to update incident: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IncidentsModule(BaseModule):
    """
    Custom module for managing Cortex XDR incidents.

    Tools provided:
        - get_incidents: Search and filter incidents with pagination.
        - get_incident_details: Full detail of a specific incident (alerts, artifacts).
        - update_incident: Update status, assignment, resolve comment, or severity.
    """

    def register_tools(self):
        self._add_tool(get_incidents)
        self._add_tool(get_incident_details)
        self._add_tool(update_incident)

    def register_resources(self):
        pass  # No static resources needed

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
