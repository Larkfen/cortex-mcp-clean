import json
import logging
from datetime import datetime, timezone
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

# MITRE tactic display names
_TACTIC_MAP = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _ts_to_iso(ts_ms: Optional[int]) -> str:
    if not ts_ms:
        return "unknown"
    try:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts_ms)


def _severity_icon(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "informational": "⚪",
    }.get((severity or "").lower(), "⚪")


def _build_obsidian_timeline(incident: dict, alerts: list[dict]) -> str:
    inc_id = incident.get("incident_id", "?")
    inc_name = incident.get("incident_name", "Unknown Incident")
    severity = incident.get("severity", "unknown")
    status = incident.get("status", "unknown")
    hosts = ", ".join(incident.get("hosts", []) or [])
    users = ", ".join(incident.get("users", []) or [])
    created = _ts_to_iso(incident.get("creation_time"))
    modified = _ts_to_iso(incident.get("modification_time"))

    # Collect unique MITRE techniques
    mitre_tags = set()
    for a in alerts:
        for t in (a.get("mitre_tactic_id_and_name") or []):
            if t:
                tac_id = t.split(" - ")[0] if " - " in t else t
                mitre_tags.add(tac_id)
        for t in (a.get("mitre_technique_id_and_name") or []):
            if t:
                tech_id = t.split(" - ")[0] if " - " in t else t
                mitre_tags.add(tech_id)

    tag_line = " ".join(f"[[{t}]]" for t in sorted(mitre_tags)) if mitre_tags else "none identified"

    lines = [
        f"---",
        f"case_id: auto",
        f"source_incident: {inc_id}",
        f"title: {inc_name}",
        f"severity: {severity}",
        f"status: {status}",
        f"created: {created}",
        f"last_modified: {modified}",
        f"hosts: {hosts or 'none'}",
        f"users: {users or 'none'}",
        f"analyst: analyst@example.com",
        f"tags: [cortex-xdr, timeline]",
        f"---",
        f"",
        f"# Timeline — Incident {inc_id}",
        f"",
        f"> [!info] **{inc_name}**",
        f"> Severity: **{severity.upper()}** | Status: {status} | Hosts: {hosts or 'N/A'} | Users: {users or 'N/A'}",
        f"",
        f"## MITRE ATT&CK",
        f"> {tag_line}",
        f"",
        f"## Alert Timeline",
        f"",
    ]

    # Sort alerts by detection timestamp
    sorted_alerts = sorted(alerts, key=lambda a: a.get("detection_timestamp") or a.get("alert_id_list", [0])[0] if a.get("alert_id_list") else 0)

    for i, alert in enumerate(sorted_alerts, 1):
        ts = _ts_to_iso(alert.get("detection_timestamp"))
        name = alert.get("name") or alert.get("alert_name") or "Unknown Alert"
        sev = alert.get("severity") or "unknown"
        icon = _severity_icon(sev)
        host = alert.get("host_name") or alert.get("hostname") or "unknown host"
        user = alert.get("user_name") or "unknown user"
        desc = alert.get("description") or ""
        actor = alert.get("actor_process_image_name") or ""
        action = alert.get("action_process_image_name") or ""
        source = alert.get("source") or ""

        mitre_tech = ""
        tech_list = alert.get("mitre_technique_id_and_name") or []
        if tech_list:
            mitre_tech = " · ".join(t for t in tech_list if t)

        lines.append(f"### {i}. {icon} `{ts}` — {name}")
        lines.append(f"- **Severity:** {sev.upper()} | **Host:** {host} | **User:** {user}")
        if source:
            lines.append(f"- **Source:** {source}")
        if actor:
            lines.append(f"- **Actor process:** `{actor}`")
        if action:
            lines.append(f"- **Action process:** `{action}`")
        if mitre_tech:
            lines.append(f"- **MITRE:** {mitre_tech}")
        if desc:
            short_desc = desc[:200] + "..." if len(desc) > 200 else desc
            lines.append(f"- **Description:** {short_desc}")
        lines.append("")

    lines += [
        "## Network Artifacts",
        "",
        "## File Artifacts",
        "",
        "## Open Questions",
        "",
        "> [!question] What is still missing from this investigation?",
        "- [ ] TBD",
        "",
    ]

    return "\n".join(lines)


async def build_incident_timeline(
    ctx: Context,
    incident_id: Annotated[str, Field(description="Cortex XDR incident ID to build a timeline for (e.g. '3217')")],
    alerts_limit: Annotated[int, Field(description="Max alerts to include in the timeline (default 50)", default=50)] = 50,
    output_format: Annotated[
        str,
        Field(description="Output format: 'obsidian' for ready-to-paste Obsidian note, 'json' for raw structured data (default: obsidian)")
    ] = "obsidian",
) -> str:
    """
    Builds a complete attack timeline for a Cortex XDR incident.

    Retrieves all alerts sorted chronologically, extracts key forensic details
    (processes, users, hosts, MITRE techniques), and formats the result as
    either an Obsidian-ready note or structured JSON.

    Use this to generate the timeline section of an HSOF incident report
    or to quickly understand the sequence of events in an attack.

    Args:
        ctx: FastMCP context.
        incident_id: The incident ID to build a timeline for.
        alerts_limit: Maximum alerts to include (default 50).
        output_format: 'obsidian' or 'json'.

    Returns:
        Formatted timeline as Obsidian Markdown or JSON.
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
        reply = response_data.get("reply", response_data)

        incident = reply.get("incident", {}) if isinstance(reply, dict) else {}
        alerts_raw = reply.get("alerts", {}) if isinstance(reply, dict) else {}
        alerts = alerts_raw.get("data", []) if isinstance(alerts_raw, dict) else []

        if not incident:
            return create_response(data={"error": f"Incident {incident_id} not found or no data returned", "raw": reply}, is_error=True)

        if output_format == "json":
            structured = {
                "incident_id": incident_id,
                "incident_name": incident.get("incident_name"),
                "severity": incident.get("severity"),
                "status": incident.get("status"),
                "hosts": incident.get("hosts", []),
                "users": incident.get("users", []),
                "creation_time_iso": _ts_to_iso(incident.get("creation_time")),
                "modification_time_iso": _ts_to_iso(incident.get("modification_time")),
                "alert_count": len(alerts),
                "alerts": [
                    {
                        "alert_id": a.get("alert_id"),
                        "timestamp_iso": _ts_to_iso(a.get("detection_timestamp")),
                        "name": a.get("name") or a.get("alert_name"),
                        "severity": a.get("severity"),
                        "host": a.get("host_name") or a.get("hostname"),
                        "user": a.get("user_name"),
                        "actor_process": a.get("actor_process_image_name"),
                        "action_process": a.get("action_process_image_name"),
                        "mitre_tactics": a.get("mitre_tactic_id_and_name", []),
                        "mitre_techniques": a.get("mitre_technique_id_and_name", []),
                        "description": a.get("description", "")[:300],
                    }
                    for a in sorted(alerts, key=lambda x: x.get("detection_timestamp") or 0)
                ],
            }
            return create_response(data=structured)

        # Default: Obsidian format
        obsidian_note = _build_obsidian_timeline(incident, alerts)
        return create_response(data={"obsidian_note": obsidian_note, "alert_count": len(alerts), "incident_id": incident_id})

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error building timeline for incident {incident_id}: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to build incident timeline: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class TimelineBuilderModule(BaseModule):
    """
    Module for building attack timelines from Cortex XDR incidents.

    Tools:
        - build_incident_timeline: Chronological timeline of alerts with MITRE mapping,
          output as Obsidian note or structured JSON.
    """

    def register_tools(self):
        self._add_tool(build_incident_timeline)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
