"""MCP server exposing a read-only slice of the Action1 API via ``action1_client``.

Configure via environment variables:
    ACTION1_CLIENT_ID     e.g. api-key-xxxx@action1.com
    ACTION1_CLIENT_SECRET
    ACTION1_REGION        north_america | europe | australia (default: north_america)
"""

from __future__ import annotations

import functools
import os

from action1_client import Action1Client, Action1Error
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

INSTRUCTIONS = """Action1 RMM. Start with list_organizations to get org_id.

To build a custom report (e.g. a compliance check against a benchmark such as CIS):
1. Write a PowerShell script that runs on each Windows endpoint and ends with ONE bare
   [PSCustomObject] - each property becomes a column. The object MUST also have
   'A1_Key' = 'none' (Action1's row key; one row per endpoint) - don't list A1_Key in columns.
   Data sources run only on Windows agents. Wrap each check in try/catch so one
   failure doesn't blank the row. Look at existing scripts with list_data_sources/get_data_source.
2. publish_check(name, script, columns, report_name). columns = the object's property names
   exactly, plus "Endpoint Name" (the agent adds that one itself).
3. requery_report(org_id, report_id) to ask agents to collect now. Agents report back
   asynchronously - offline endpoints won't appear; online ones usually within a few minutes.
4. list_report_data(org_id, report_id) for rows, list_report_errors for script failures.
   Fix the script and call publish_check again with data_source_id to update in place.
"""

# Client method name -> tool description.
# ponytail: endpoint/user/org deletes, update approvals etc. left out; add when needed.
TOOLS = {
    "list_organizations": "List all organizations. Call this first to get the org_id other tools need.",
    "search": "Full-text search across endpoints, software, etc. in an organization.",
    "list_endpoints": "List all managed endpoints (computers) in an organization.",
    "get_endpoint": "Get full details of one endpoint.",
    "get_endpoint_status": "Connected/disconnected/pending endpoint counts for an organization.",
    "get_endpoint_missing_updates": "List updates missing on one endpoint.",
    "list_endpoint_installed_software": "List software installed on one endpoint.",
    "list_endpoint_groups": "List endpoint groups in an organization.",
    "list_endpoint_group_members": "List endpoints in an endpoint group.",
    "list_missing_updates": "List missing OS/third-party updates across an organization.",
    "list_update_missing_endpoints": "List endpoints missing a specific update package version.",
    "list_vulnerabilities": "List vulnerabilities (CVEs) detected in an organization.",
    "get_vulnerability": "Get details of one CVE in an organization.",
    "list_vulnerability_endpoints": "List endpoints affected by a CVE.",
    "list_automation_schedules": "List automation schedules in an organization.",
    "list_automation_instances": "List automation runs (instances) in an organization.",
    "list_automation_instance_endpoint_results": "Per-endpoint results of one automation run.",
    "list_reports": "List available reports and report categories.",
    "list_report_data": "Get the rows of a report for an organization.",
    "list_users": "List console users.",
    "list_roles": "List roles.",
    "get_enterprise_usage": "Enterprise-wide license/endpoint usage.",
    "get_report_or_category": "Get a report (or category) definition by id.",
    "list_report_errors": "Endpoints where a report's data source script failed, with the error.",
    "list_data_sources": "List data sources (PowerShell scripts agents run to feed reports).",
    "get_data_source": "Get a data source including its script_text and columns.",
}

# Change things in the tenant; MCP clients ask the user before calling these.
WRITE_TOOLS = {
    "requery_report": "Ask agents to re-run the report's data source script now.",
    "delete_custom_report": "Delete a custom report.",
    "delete_data_source": "Delete a data source (delete reports that use it first).",
}


def _expose_errors(fn):
    """mcp hides the text of unexpected exceptions; re-raise ours as ToolError so the model
    sees *why* a call failed (403, not found, bad id) instead of a bare "Error executing tool"."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (Action1Error, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


def build_server(client: Action1Client) -> MCPServer:
    mcp = MCPServer("action1", instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(readOnlyHint=True)
    writes = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
    for name, description in TOOLS.items():
        mcp.add_tool(_expose_errors(getattr(client, name)), name=name, description=description, annotations=read_only)
    for name, description in WRITE_TOOLS.items():
        mcp.add_tool(_expose_errors(getattr(client, name)), name=name, description=description, annotations=writes)

    @_expose_errors
    def publish_check(
        name: str,
        script: str,
        columns: list[str],
        report_name: str = "",
        data_source_id: str = "",
    ) -> dict:
        """Publish a PowerShell script as an Action1 data source and (if report_name is given)
        a custom report showing its columns. Pass data_source_id to update an existing data
        source in place - reports built on it pick up new columns automatically."""
        ds = client.publish_data_source(name, script, columns, data_source_id=data_source_id or None)
        result = {"data_source_id": ds["id"], "columns": ds.get("columns")}
        if report_name:
            result["report_id"] = client.create_simple_report(report_name, ds, columns)["id"]
        return result

    mcp.add_tool(publish_check, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False))
    return mcp


def main() -> None:
    client = Action1Client(
        client_id=os.environ["ACTION1_CLIENT_ID"],
        client_secret=os.environ["ACTION1_CLIENT_SECRET"],
        region=os.environ.get("ACTION1_REGION", "north_america"),
    )
    with client:
        build_server(client).run()


if __name__ == "__main__":
    main()
