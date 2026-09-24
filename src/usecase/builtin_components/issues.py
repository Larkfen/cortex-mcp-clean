import json
import logging
import re
from collections import Counter
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
from entities.llm_config import LLM_FORMATTING_BASE_INSTRUCTIONS
from pkg.util import create_response, read_resource
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d+)\b", re.IGNORECASE)


def _extract_cve(issue: dict) -> str | None:
    name = (issue.get("name") or "") or (issue.get("description") or "")
    m = _CVE_RE.search(name)
    return m.group(1).upper() if m else None


async def get_top_vulnerabilities_by_occurrence(
    ctx: Context,
    top_n: Annotated[int, Field(description="Número de vulnerabilidades (CVE) a devolver", ge=1, le=50)] = 10,
    max_issues: Annotated[int, Field(description="Máximo de issues a consultar (paginas de 100). Cortex limita 100 por request.", ge=100, le=5000)] = 500,
) -> str:
    """
    Obtiene las N vulnerabilidades (CVE) que más se repiten en equipos según los issues de Cortex.
    Usa el mismo endpoint issue/search que get_issues, pagina automáticamente y agrega por CVE.
    """
    page_size = 100
    cve_counts: Counter[str] = Counter()
    search_from = 0

    try:
        fetcher = await get_fetcher(ctx)
        while search_from < max_issues:
            payload = {
                "request_data": {
                    "search_from": search_from,
                    "search_to": search_from + page_size,
                }
            }
            response_data = await fetcher.send_request("issue/search", data=payload)
            reply = response_data.get("reply") or response_data
            issues = reply.get("DATA") or []
            for issue in issues:
                cve = _extract_cve(issue)
                if cve:
                    cve_counts[cve] += 1
            if not issues:
                break
            search_from += len(issues)
            if len(issues) < page_size:
                break

        top = cve_counts.most_common(top_n)
        result = {
            "top_vulnerabilities": [{"cve": cve, "occurrences": count} for cve, count in top],
            "total_issues_with_cve": sum(cve_counts.values()),
            "issues_queried": search_from,
        }
        return create_response(data=result)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in get_top_vulnerabilities_by_occurrence: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed get_top_vulnerabilities_by_occurrence: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_issues_response() -> str:
    try:
        issues_json = read_resource("issues_response.json")
        return create_response(data={"response": json.loads(issues_json)})
    except FileNotFoundError as e:
        logger.exception(f"Issues response file not found: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in issues response file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to read issues responses: {e}")
        return create_response(data={"error": str(e)}, is_error=True)

async def get_issues(ctx: Context,
                    filters: Annotated[list[dict], Field(description="Filters list to get the issues by. Leave empty go get all issues")],
                    search_from: Annotated[int, Field(description="Marker for pagination starting point", default=0)] = 0,
                    search_to: Annotated[int, Field(description="Marker for pagination ending point", default=30)] = 30,
                    sort: Annotated[Optional[dict], Field(description="Dictionary of field and keyword to sort by. By default the sort is defined as observation time, desc")] = None,
                    ) -> str:
    """
    Retrieves a list of issues or alerts from the Cortex platform.
    Use this tool to fetch all issues, or a filtered subset of issues, or one issue, based on various criteria such as time range, severity, status, or specific alert IDs.
    This is highly valuable for security monitoring, threat hunting, and reporting on detected security events.

    Args:
        ctx: The FastMCP context.
        filters: Filters list to get the issues by. Examples -
            [{
                        "field": "id",
                        "operator": "in",
                        "value": [123]
            }],
            [{
                        "field": "status",
                        "operator": "in",
                        "value": ["new", "under_investigation"]
            }]
            Leave empty go get all issues.
            Allowed values:"id","external_id","detection_method","issue_domain","severity","_insert_time","status"
        search_from: Marker for pagination starting point.
        search_to: Marker for pagination ending point.
        sort: Field to sort by. Example -
            {
                    "field": "observation_time",
                    "keyword": "desc"
            }
            Allowed fields are "id","observation_time","severity".
    Returns:
        JSON response containing issue data.
      """

    payload = {
        "request_data": {
            "search_from": search_from,
            "search_to": search_to,
        }
    }
    if filters:
        for f in filters:
            if f.get("field") == "id" and f.get("value"):
                f["value"] = [int(v) for v in f["value"]]
        payload["request_data"]["filters"] = filters
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("issue/search", data=payload)
        response_data["_metadata"] = {
            "formatting_instructions": LLM_FORMATTING_BASE_INSTRUCTIONS,
        }

        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IssuesModule(BaseModule):
    """
       Module for managing and retrieving security issues and alerts from the Cortex platform.

       This module provides tools and resources for interacting with the Cortex platform's issue/alert system,
       enabling users to search, filter, and paginate through security issues. It supports various filtering
       criteria such as status, severity, time range, and custom search parameters.

       The module registers:
       - Tools: get_issues - for retrieving filtered and paginated issue data
       - Resources: issues_response.json - example API response for reference

       This module is essential for security monitoring, threat hunting, incident response,
       and generating reports on detected security events within the Cortex platform.
       """

    def register_tools(self):
        self._add_tool(get_issues)
        self._add_tool(get_top_vulnerabilities_by_occurrence)

    def register_resources(self):
        self._add_resource(get_issues_response, uri="resources://issues_response.json",
    name="issues_response.json",
    description="Example response from the issues API",
    mime_type="application/json",)

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)

