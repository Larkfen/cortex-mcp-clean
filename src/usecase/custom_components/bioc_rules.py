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


async def list_bioc_rules(
    ctx: Context,
    rule_name: Annotated[Optional[str], Field(description="Filter by partial rule name")] = None,
    enabled: Annotated[Optional[bool], Field(description="Filter by enabled status: true=enabled, false=disabled")] = None,
    search_from: Annotated[int, Field(description="Pagination start", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end, max 100", default=50)] = 50,
) -> str:
    """
    Lists BIOC (Behavioral Indicator of Compromise) rules in Cortex XDR.
    BIOC rules define behavioral patterns that trigger alerts.

    Args:
        ctx: FastMCP context.
        rule_name: Optional partial name filter.
        enabled: Filter by enabled/disabled status.
        search_from: Pagination start.
        search_to: Pagination end.

    Returns:
        JSON with BIOC rules list.
    """
    filters = []
    if rule_name:
        filters.append({"field": "name", "operator": "contains", "value": rule_name})
    if enabled is not None:
        filters.append({"field": "enabled", "operator": "eq", "value": enabled})

    payload: dict = {
        "request_data": {
            "search_from": search_from,
            "search_to": min(search_to, 100),
        }
    }
    if filters:
        payload["request_data"]["filters"] = filters

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("bioc/get", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error listing BIOC rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to list BIOC rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def create_bioc_rule(
    ctx: Context,
    name: Annotated[str, Field(description="Unique name for the BIOC rule")],
    rule: Annotated[str, Field(description="XQL-based rule definition string")],
    severity: Annotated[str, Field(description="Alert severity: low | medium | high | critical")],
    description: Annotated[str, Field(description="Description of what the rule detects", default="")] = "",
) -> str:
    """
    Creates a new BIOC (Behavioral Indicator of Compromise) rule.
    BIOC rules use XQL syntax to define behavioral patterns that trigger alerts.

    Args:
        ctx: FastMCP context.
        name: Unique rule name.
        rule: XQL rule body.
        severity: Alert severity level.
        description: Human-readable description.

    Returns:
        JSON with the new rule ID.
    """
    payload = {
        "request_data": {
            "name": name,
            "rule": rule,
            "severity": severity,
            "description": description,
        }
    }
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("bioc/insert", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error creating BIOC rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to create BIOC rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def update_bioc_rule(
    ctx: Context,
    rule_id: Annotated[str, Field(description="ID of the BIOC rule to update")],
    name: Annotated[Optional[str], Field(description="New name for the rule")] = None,
    rule: Annotated[Optional[str], Field(description="Updated XQL rule definition")] = None,
    severity: Annotated[Optional[str], Field(description="Updated severity: low | medium | high | critical")] = None,
    enabled: Annotated[Optional[bool], Field(description="Enable or disable the rule")] = None,
    description: Annotated[Optional[str], Field(description="Updated description")] = None,
) -> str:
    """
    Updates an existing BIOC rule. Only provided fields are updated.

    Args:
        ctx: FastMCP context.
        rule_id: ID of the rule to update.
        name: New name.
        rule: Updated XQL rule body.
        severity: Updated severity.
        enabled: Enable/disable toggle.
        description: Updated description.

    Returns:
        JSON confirming the update.
    """
    update_data: dict = {}
    if name is not None:
        update_data["name"] = name
    if rule is not None:
        update_data["rule"] = rule
    if severity is not None:
        update_data["severity"] = severity
    if enabled is not None:
        update_data["enabled"] = enabled
    if description is not None:
        update_data["description"] = description

    if not update_data:
        return create_response(data={"error": "No update fields provided"}, is_error=True)

    payload = {"request_data": {"rule_id": rule_id, **update_data}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("bioc/insert", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error updating BIOC rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to update BIOC rule: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def delete_bioc_rule(
    ctx: Context,
    rule_id_list: Annotated[list[str], Field(description="List of BIOC rule IDs to delete")],
) -> str:
    """
    Deletes one or more BIOC rules by ID.

    Args:
        ctx: FastMCP context.
        rule_id_list: List of rule IDs to delete.

    Returns:
        JSON confirming deletion.
    """
    payload = {"request_data": {"rule_id_list": rule_id_list}}
    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("bioc/delete", data=payload)
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error deleting BIOC rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to delete BIOC rules: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class BIOCRulesModule(BaseModule):
    """
    Custom module for Cortex XDR BIOC (Behavioral Indicator of Compromise) rule management.

    Tools:
        - list_bioc_rules: List and filter BIOC rules.
        - create_bioc_rule: Create a new behavioral detection rule.
        - update_bioc_rule: Update an existing rule.
        - delete_bioc_rule: Delete rules by ID.
    """

    def register_tools(self):
        self._add_tool(list_bioc_rules)
        self._add_tool(create_bioc_rule)
        self._add_tool(update_bioc_rule)
        self._add_tool(delete_bioc_rule)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
