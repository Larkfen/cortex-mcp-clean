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

# HSOF Risk Score: (Impact × 0.4) + (Likelihood × 0.35) + (Exposure × 0.25)
_SEVERITY_TO_IMPACT = {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 1}
_SEVERITY_TO_LIKELIHOOD = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1}

_STATUS_LABELS = {
    "new": "🔴 New",
    "under_investigation": "🟡 Under Investigation",
    "resolved_true_positive": "🟢 Resolved — True Positive",
    "resolved_false_positive": "✅ Resolved — False Positive",
    "resolved_other": "⚪ Resolved — Other",
}


def _calc_risk_score(impact: int, likelihood: int, exposure: int) -> int:
    return round((impact * 0.4) + (likelihood * 0.35) + (exposure * 0.25) * 10)


def _risk_level(score: int) -> tuple[str, str]:
    if score >= 80:
        return "Critical", "🔴"
    if score >= 60:
        return "High", "🟠"
    if score >= 40:
        return "Medium", "🟡"
    if score >= 20:
        return "Low", "🔵"
    return "Info", "⚪"


def _ts_to_iso(ts_ms: Optional[int]) -> str:
    if not ts_ms:
        return "unknown"
    try:
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts_ms)


def _build_hsof_note(
    incident: dict,
    alerts: list[dict],
    case_number: str,
    exposure_override: Optional[int],
) -> dict:
    sev = (incident.get("severity") or "medium").lower()
    impact = _SEVERITY_TO_IMPACT.get(sev, 5)
    likelihood = _SEVERITY_TO_LIKELIHOOD.get(sev, 5)

    # Exposure: higher if more hosts/users affected, internet-facing, or critical asset
    exposure = exposure_override if exposure_override is not None else min(10, max(1, len(incident.get("hosts") or []) + len(incident.get("users") or [])))

    # Scale impact/likelihood to 1-10 range before formula
    risk_raw = (impact * 0.4) + (likelihood * 0.35) + (exposure * 0.25)
    risk_score = round(risk_raw * 10)
    risk_level, risk_icon = _risk_level(risk_score)

    inc_id = incident.get("incident_id", "?")
    inc_name = incident.get("incident_name") or f"Cortex Incident {inc_id}"
    status = incident.get("status", "new")
    status_label = _STATUS_LABELS.get(status, status)
    hosts = incident.get("hosts") or []
    users = incident.get("users") or []
    alert_count = len(alerts)
    created = _ts_to_iso(incident.get("creation_time"))

    # MITRE techniques from alerts
    mitre_techniques: set[str] = set()
    for a in alerts:
        for t in (a.get("mitre_technique_id_and_name") or []):
            if t:
                mitre_techniques.add(t.strip())

    # Open questions (auto-generated based on what's missing)
    open_questions = []
    if not hosts:
        open_questions.append("Identify affected endpoints")
    if not users:
        open_questions.append("Identify affected user accounts")
    if not mitre_techniques:
        open_questions.append("Map MITRE ATT&CK techniques manually")
    if alert_count == 0:
        open_questions.append("Retrieve and review associated alerts")
    if status in ("new", "under_investigation"):
        open_questions.append("Determine root cause and attack vector")
        open_questions.append("Confirm true positive / false positive")
    if not open_questions:
        open_questions.append("Review and confirm resolution steps")

    mitre_tag_list = "\n".join(f"- {t}" for t in sorted(mitre_techniques)) if mitre_techniques else "- None identified — map manually"

    yaml_tags = "[cortex-xdr, incident-response]"
    obsidian_note = f"""---
case_id: {case_number}
source_incident: {inc_id}
title: "{inc_name}"
date: {datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")}
analyst: analyst@example.com
severity: {sev}
risk_score: {risk_score}
risk_level: {risk_level}
status: open
incident_status: {status}
hosts: {hosts or ["none"]}
users: {users or ["none"]}
alert_count: {alert_count}
tags: {yaml_tags}
---

# {case_number} — {inc_name}

## Executive Summary

> [!{('danger' if risk_score >= 80 else 'warning' if risk_score >= 60 else 'caution' if risk_score >= 40 else 'info')}] {risk_icon} Risk Score: **{risk_score}/100** — {risk_level}
> Cortex XDR incident **{inc_id}** detected on {created}. Severity: **{sev.upper()}**.
> Affected hosts: {', '.join(hosts) or 'unknown'}. Affected users: {', '.join(users) or 'unknown'}.
> Status: {status_label}. **{alert_count} alert(s)** associated.

Incident "{inc_name}" was detected through Cortex XDR on {created}. The event triggered {alert_count} alert(s) with a severity of {sev.upper()}. Initial triage is {'complete' if status not in ('new',) else 'pending'}. This case requires {'immediate attention' if risk_score >= 60 else 'scheduled remediation'}.

## Risk Assessment

| Factor | Score | Weight | Contribution |
|--------|-------|--------|-------------|
| Impact | {impact}/10 | 40% | {impact * 0.4:.1f} |
| Likelihood | {likelihood}/10 | 35% | {likelihood * 0.35:.1f} |
| Exposure | {exposure}/10 | 25% | {exposure * 0.25:.1f} |
| **TOTAL** | | | **{risk_raw:.1f} × 10 = {risk_score}** |

**Formula:** `Risk = (Impact × 0.4) + (Likelihood × 0.35) + (Exposure × 0.25)`

## Technical Findings

> [!note] Source: Cortex XDR Incident {inc_id}

- **Incident ID:** {inc_id}
- **Detection time:** {created}
- **Affected hosts:** {', '.join(hosts) or 'TBD'}
- **Affected users:** {', '.join(users) or 'TBD'}
- **Alert count:** {alert_count}
- **Cortex status:** {status_label}

## MITRE ATT&CK Mapping

{mitre_tag_list}

## Recommended Actions

### P0 — Immediate
- [ ] Confirm scope: are all affected hosts identified?
- [ ] {'Isolate endpoint(s) if active threat confirmed' if risk_score >= 60 else 'Review alerts and confirm true/false positive'}

### P1 — Within 24–48h
- [ ] Collect forensic evidence from affected endpoints
- [ ] Review audit logs for privilege escalation or persistence

### P2 — Within 1 week
- [ ] Document root cause and attack vector
- [ ] Update detection rules to prevent recurrence

## Open Questions

> [!question] Missing evidence — do not close case until resolved
""" + "\n".join(f"- [ ] {q}" for q in open_questions) + f"""

## Decision Record

- Link: `DR-{datetime.now(tz=timezone.utc).strftime("%Y")}-TBD`

---
*Generated by HSOF Integration Tool from Cortex XDR incident {inc_id}*
"""

    return {
        "case_number": case_number,
        "incident_id": inc_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "impact": impact,
        "likelihood": likelihood,
        "exposure": exposure,
        "obsidian_note": obsidian_note,
    }


async def create_hsof_case(
    ctx: Context,
    incident_id: Annotated[str, Field(description="Cortex XDR incident ID to convert into an HSOF case (e.g. '3217')")],
    case_number: Annotated[str, Field(description="HSOF case number in format HSOF-YYYY-NNN (e.g. 'HSOF-2026-007')")],
    exposure_override: Annotated[
        Optional[int],
        Field(description="Manual exposure score 1-10 (optional). If omitted, auto-calculated from host/user count. Use to reflect asset criticality (e.g. 10 for internet-facing production system).")
    ] = None,
    alerts_limit: Annotated[int, Field(description="Max alerts to include (default 30)", default=30)] = 30,
) -> str:
    """
    Converts a Cortex XDR incident into a complete HSOF case.

    Fetches incident data, calculates the HSOF risk score using the formula
    (Impact × 0.4) + (Likelihood × 0.35) + (Exposure × 0.25), maps MITRE techniques,
    generates open questions, and returns an Obsidian-ready note with YAML frontmatter.

    Use this as the first step when opening a new HSOF case from a Cortex alert.

    Args:
        ctx: FastMCP context.
        incident_id: The Cortex incident ID.
        case_number: HSOF case ID (e.g. HSOF-2026-007).
        exposure_override: Optional manual exposure score 1-10.
        alerts_limit: How many alerts to pull for MITRE mapping.

    Returns:
        JSON with risk_score, risk_level, and complete Obsidian note ready to paste.
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
        reply = response_data.get("reply", response_data) if isinstance(response_data, dict) else {}

        incident = reply.get("incident", {}) if isinstance(reply, dict) else {}
        alerts_raw = reply.get("alerts", {}) if isinstance(reply, dict) else {}
        alerts = alerts_raw.get("data", []) if isinstance(alerts_raw, dict) else []

        if not incident:
            return create_response(data={"error": f"Incident {incident_id} not found"}, is_error=True)

        result = _build_hsof_note(incident, alerts, case_number, exposure_override)
        return create_response(data=result)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error creating HSOF case for incident {incident_id}: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to create HSOF case: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def calculate_hsof_risk_score(
    ctx: Context,
    impact: Annotated[int, Field(description="Impact score 1-10: business/operational damage if the threat materializes", ge=1, le=10)],
    likelihood: Annotated[int, Field(description="Likelihood score 1-10: probability the threat is real and active", ge=1, le=10)],
    exposure: Annotated[int, Field(description="Exposure score 1-10: attack surface (internet-facing, critical asset, lateral spread risk)", ge=1, le=10)],
) -> str:
    """
    Calculates the HSOF risk score using the standard formula.

    Formula: Risk = (Impact × 0.4) + (Likelihood × 0.35) + (Exposure × 0.25)
    Scale: 0-100 mapped to Critical / High / Medium / Low / Info.

    Use this standalone to calculate a risk score for any finding without
    needing a Cortex incident (e.g. manual threat assessment, vendor report).

    Args:
        ctx: FastMCP context (required by MCP protocol, not used here).
        impact: Business impact score 1-10.
        likelihood: Probability score 1-10.
        exposure: Attack surface score 1-10.

    Returns:
        JSON with score, level, color, and recommended action timeline.
    """
    raw = (impact * 0.4) + (likelihood * 0.35) + (exposure * 0.25)
    score = round(raw * 10)
    level, icon = _risk_level(score)

    action_map = {
        "Critical": "Immediate action required",
        "High": "Action within 24–48h",
        "Medium": "Action within 1 week",
        "Low": "Monitor / backlog",
        "Info": "Document only",
    }

    return create_response(data={
        "risk_score": score,
        "risk_level": level,
        "icon": icon,
        "action": action_map[level],
        "breakdown": {
            "impact_contribution": round(impact * 0.4, 2),
            "likelihood_contribution": round(likelihood * 0.35, 2),
            "exposure_contribution": round(exposure * 0.25, 2),
            "raw_sum": round(raw, 2),
        },
    })


class HSOFIntegrationModule(BaseModule):
    """
    Module for HSOF (Hybrid Security Operations Framework) integration.

    Tools:
        - create_hsof_case: Convert a Cortex XDR incident into a full HSOF case with
          risk score, MITRE mapping, and Obsidian-ready note.
        - calculate_hsof_risk_score: Standalone risk score calculator using the
          HSOF formula (Impact × 0.4) + (Likelihood × 0.35) + (Exposure × 0.25).
    """

    def register_tools(self):
        self._add_tool(create_hsof_case)
        self._add_tool(calculate_hsof_risk_score)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
