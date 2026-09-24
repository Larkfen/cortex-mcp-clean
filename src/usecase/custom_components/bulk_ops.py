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

_IOC_CHUNK_SIZE = 100  # Cortex API limit per IOC submission call


async def bulk_add_iocs(
    ctx: Context,
    iocs: Annotated[
        list[dict],
        Field(description=(
            "List of IOC dicts. Each must have: "
            "'indicator' (value), 'type' (HASH|DOMAIN_NAME|IP|URL), "
            "'severity' (INFO|LOW|MEDIUM|HIGH|CRITICAL), 'reputation' (GOOD|SUSPICIOUS|BAD). "
            "Optional: 'comment', 'expiration_date' (epoch ms). "
            "Handles lists of any size by chunking automatically."
        ))
    ],
) -> str:
    """
    Adds a large list of IOCs to Cortex XDR, automatically chunking into batches of 100.

    Unlike add_iocs (single-batch), this handles threat intel feeds or investigation exports
    with hundreds of indicators without hitting API limits.

    Args:
        ctx: FastMCP context.
        iocs: Full list of IOC dicts to submit.

    Returns:
        JSON with per-batch results and total success/failure counts.
    """
    fetcher = await get_fetcher(ctx)
    chunks = [iocs[i:i + _IOC_CHUNK_SIZE] for i in range(0, len(iocs), _IOC_CHUNK_SIZE)]

    results = []
    success_count = 0
    error_count = 0

    for idx, chunk in enumerate(chunks):
        payload = {"request_data": chunk, "validate": True}
        try:
            resp = await fetcher.send_request("indicators/tim_insert_jsons/", data=payload, headers={"x-iocs-source": "xsoar"})
            results.append({"batch": idx + 1, "submitted": len(chunk), "response": resp})
            success_count += len(chunk)
        except Exception as e:
            logger.warning(f"Batch {idx + 1} failed: {e}")
            results.append({"batch": idx + 1, "submitted": len(chunk), "error": str(e)})
            error_count += len(chunk)

    return create_response(data={
        "total_submitted": len(iocs),
        "success_count": success_count,
        "error_count": error_count,
        "batch_count": len(chunks),
        "batch_results": results,
    }, is_error=error_count > 0 and success_count == 0)


async def bulk_update_alerts(
    ctx: Context,
    filters: Annotated[
        list[dict],
        Field(description=(
            "Filters to select which alerts to update. "
            "Example: [{\"field\": \"severity\", \"operator\": \"in\", \"value\": [\"low\"]}, "
            "{\"field\": \"alert_source\", \"operator\": \"eq\", \"value\": \"XDR Analytics\"}]. "
            "Allowed fields: severity, status, alert_source, host_name, alert_id."
        ))
    ],
    new_status: Annotated[
        Optional[str],
        Field(description="New status: new | under_investigation | resolved_true_positive | resolved_false_positive | resolved_other")
    ] = None,
    new_severity: Annotated[
        Optional[str],
        Field(description="New severity: low | medium | high | critical")
    ] = None,
    comment: Annotated[
        Optional[str],
        Field(description="Comment to add to all matching alerts (e.g. 'Closed as false positive — known scanner')")
    ] = None,
    dry_run: Annotated[
        bool,
        Field(description="If true, only returns the count of matching alerts without making changes (default false)")
    ] = False,
) -> str:
    """
    Updates all alerts matching a set of filters with the same status, severity, or comment.

    Use this to close bulk false positives, mass-assign alerts after triage,
    or add batch comments during an incident investigation.

    When dry_run=true, returns how many alerts would be affected without making changes.

    Args:
        ctx: FastMCP context.
        filters: Alert filter criteria.
        new_status: Status to set on all matching alerts.
        new_severity: Severity override for all matching alerts.
        comment: Comment to add to all matching alerts.
        dry_run: Preview mode — no changes made.

    Returns:
        JSON with count of affected alerts and per-alert update results.
    """
    if not new_status and not new_severity and not comment and not dry_run:
        return create_response(data={"error": "Provide at least one of: new_status, new_severity, comment, or set dry_run=true"}, is_error=True)

    fetcher = await get_fetcher(ctx)

    # First: fetch matching alerts
    list_payload = {
        "request_data": {
            "filters": filters,
            "search_from": 0,
            "search_to": 200,
            "sort": {"field": "detection_timestamp", "keyword": "desc"},
        }
    }

    try:
        list_resp = await fetcher.send_request("alerts/get_alerts_by_filter_data/", data=list_payload)
        alert_data = list_resp.get("reply", {}) if isinstance(list_resp, dict) else {}
        alerts = alert_data.get("alerts", []) if isinstance(alert_data, dict) else []

        if not alerts:
            return create_response(data={"message": "No alerts matched the filters", "count": 0})

        if dry_run:
            return create_response(data={
                "dry_run": True,
                "matching_count": len(alerts),
                "sample_alert_ids": [a.get("alert_id") for a in alerts[:10]],
                "would_apply": {
                    "status": new_status,
                    "severity": new_severity,
                    "comment": comment,
                },
            })

        # Update each matching alert
        update_results = []
        success_count = 0
        error_count = 0

        for alert in alerts:
            alert_id = alert.get("alert_id")
            if not alert_id:
                continue

            update_payload: dict = {}
            if new_status:
                update_payload["status"] = new_status
            if new_severity:
                update_payload["severity"] = new_severity
            if comment:
                update_payload["comment"] = comment

            upd_payload = {
                "request_data": {
                    "alert_id_list": [alert_id],
                    "update_data": update_payload,
                }
            }
            try:
                resp = await fetcher.send_request("alerts/update_alerts/", data=upd_payload)
                update_results.append({"alert_id": alert_id, "success": True})
                success_count += 1
            except Exception as e:
                update_results.append({"alert_id": alert_id, "success": False, "error": str(e)})
                error_count += 1

        return create_response(data={
            "total_matched": len(alerts),
            "success_count": success_count,
            "error_count": error_count,
            "update_results": update_results,
        }, is_error=error_count > 0 and success_count == 0)

    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error in bulk_update_alerts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed bulk_update_alerts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def bulk_isolate_endpoints(
    ctx: Context,
    hostnames: Annotated[
        list[str],
        Field(description="List of endpoint hostnames to isolate. Example: ['WORKSTATION-01', 'LAPTOP-SALES-03']")
    ],
    reason: Annotated[
        str,
        Field(description="Isolation reason — logged with each action (e.g. 'Suspected ransomware — HSOF-2026-007')")
    ],
    dry_run: Annotated[
        bool,
        Field(description="If true, returns which endpoints would be isolated without taking action (default false)")
    ] = False,
) -> str:
    """
    Isolates multiple endpoints by hostname in sequence.

    Use during active incident response when you need to contain multiple
    compromised machines quickly. Requires explicit reason for audit trail.

    When dry_run=true, confirms which hostnames resolve to endpoint IDs
    without triggering isolation.

    IMPORTANT: This action cuts network access. Confirm scope before use.

    Args:
        ctx: FastMCP context.
        hostnames: List of hostnames to isolate.
        reason: Isolation reason for audit log.
        dry_run: Preview mode — no isolation performed.

    Returns:
        JSON with per-hostname isolation results.
    """
    fetcher = await get_fetcher(ctx)

    # Resolve hostnames to endpoint IDs
    filter_payload = {
        "request_data": {
            "filters": [{"field": "endpoint_name_list", "operator": "in", "value": hostnames}],
            "search_from": 0,
            "search_to": len(hostnames) + 10,
        }
    }

    try:
        filter_resp = await fetcher.send_request("endpoints/get_endpoint/", data=filter_payload)
        reply = filter_resp.get("reply", {}) if isinstance(filter_resp, dict) else {}
        endpoints = reply.get("endpoints", []) if isinstance(reply, dict) else []

        if not endpoints:
            return create_response(data={"error": "No endpoints matched the provided hostnames", "hostnames": hostnames}, is_error=True)

        # Map hostname → endpoint_id
        endpoint_map = {
            (ep.get("endpoint_name") or "").lower(): ep.get("endpoint_id")
            for ep in endpoints
        }
        not_found = [h for h in hostnames if h.lower() not in endpoint_map]

        if dry_run:
            return create_response(data={
                "dry_run": True,
                "found_count": len(endpoints),
                "not_found": not_found,
                "would_isolate": [
                    {"hostname": ep.get("endpoint_name"), "endpoint_id": ep.get("endpoint_id"), "current_status": ep.get("endpoint_status")}
                    for ep in endpoints
                ],
            })

        # Isolate each endpoint
        results = []
        for ep in endpoints:
            ep_id = ep.get("endpoint_id")
            hostname = ep.get("endpoint_name") or ep_id
            isolate_payload = {
                "request_data": {
                    "endpoint_id_list": [ep_id],
                    "incident_id": reason,
                }
            }
            try:
                resp = await fetcher.send_request("endpoints/isolate/", data=isolate_payload)
                results.append({"hostname": hostname, "endpoint_id": ep_id, "success": True, "response": resp})
            except Exception as e:
                logger.warning(f"Failed to isolate {hostname}: {e}")
                results.append({"hostname": hostname, "endpoint_id": ep_id, "success": False, "error": str(e)})

        success_count = sum(1 for r in results if r.get("success"))
        return create_response(data={
            "total_requested": len(hostnames),
            "found_count": len(endpoints),
            "not_found": not_found,
            "isolated_count": success_count,
            "error_count": len(results) - success_count,
            "results": results,
        }, is_error=success_count == 0 and len(endpoints) > 0)

    except _PAPI_ERRORS as e:
        logger.exception(f"PAPI error in bulk_isolate_endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed bulk_isolate_endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class BulkOpsModule(BaseModule):
    """
    Module for bulk operations across alerts, IOCs, and endpoints.

    Tools:
        - bulk_add_iocs: Submit large IOC lists with automatic chunking.
        - bulk_update_alerts: Mass-update alerts matching filter criteria (with dry_run option).
        - bulk_isolate_endpoints: Isolate multiple endpoints by hostname list (with dry_run option).
    """

    def register_tools(self):
        self._add_tool(bulk_add_iocs)
        self._add_tool(bulk_update_alerts)
        self._add_tool(bulk_isolate_endpoints)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
