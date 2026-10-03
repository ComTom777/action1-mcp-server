"""MCP server for the Action1 API via ``action1_client``: read tools, custom reports, run scripts.

Configure via environment variables:
    ACTION1_CLIENT_ID     e.g. api-key-xxxx@action1.com
    ACTION1_CLIENT_SECRET
    ACTION1_REGION        north_america | europe | australia (default: north_america)
"""

from __future__ import annotations

import functools
import inspect
import os
import time

from action1_client import Action1Client, Action1Error
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

INSTRUCTIONS = """Action1 RMM. Start with list_organizations to get org_id.

To build a custom report (e.g. a compliance check against a benchmark such as CIS):
1. Write a PowerShell script that runs on each Windows endpoint and ends with ONE bare
   [PSCustomObject] - each property becomes a column. The object MUST also have
   'A1_Key' = 'none' (Action1's row key; one row per endpoint) - don't list A1_Key in columns.
   Max 30 columns (more = rows silently dropped, no error). Values are truncated at 255 chars.
   Data sources run only on Windows agents. Wrap each check in try/catch so one
   failure doesn't blank the row. Look at existing scripts with list_data_sources/get_data_source.
2. publish_check(name, script, columns, report_name). columns = the object's property names
   exactly, plus "Endpoint Name" (the agent adds that one itself).
3. requery_report(org_id, report_id) to ask agents to collect now. Agents report back
   asynchronously - offline endpoints won't appear; online ones usually within a few minutes.
4. list_report_data(org_id, report_id) for rows, list_report_errors for script failures.
   Fix the script and call publish_check again with data_source_id to update in place.
   Long details belong in a file the data source writes on the endpoint; read it with run_script.

run_script(org_id, endpoint_ids, script) runs PowerShell as SYSTEM on online endpoints right now
and returns each endpoint's output (capped at ~10,000 chars - summarize in the script if needed).
Use it for one-off diagnostics or to fetch files; use a data source for recurring reports.
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


class _OnePage:
    """Stands in for the client while one list method runs: ``paginate`` fetches a single page
    (with Action1's server-side ``filter``) instead of walking every page. A tenant can have
    thousands of CVEs - 63 requests, ~75 s and 3 MB of JSON for the full list."""

    def __init__(self, client: Action1Client, contains: str, offset: int, limit: int):
        self._client = client
        self._params = {"from": offset, "limit": limit, **({"filter": contains} if contains else {})}
        self.total: int | None = None
        self.has_more = False

    def __getattr__(self, name):
        return getattr(self._client, name)

    def paginate(self, path, *, params=None):
        page = self._client.get(path, params={**(params or {}), **self._params})
        page = page if isinstance(page, dict) else {}
        items = page.get("items", [])
        if page.get("total_items") is not None:
            self.total = int(page["total_items"])
        self.has_more = bool(page.get("next_page")) or (
            self.total is not None and self._params["from"] + len(items) < self.total
        )
        return iter(items)


def _paged(client: Action1Client, name: str):
    """Expose a list-returning client method as one page: adds ``contains``/``offset``/``limit``
    and returns ``{total, offset, has_more, items}``."""
    method = getattr(type(client), name)
    sig = inspect.signature(getattr(client, name), eval_str=True)

    @functools.wraps(method)
    def wrapper(*args, contains: str = "", offset: int = 0, limit: int = 20, **kwargs):
        proxy = _OnePage(client, contains, max(offset, 0), min(max(limit, 1), 200))
        items = method(proxy, *args, **kwargs)
        return {"total": proxy.total, "offset": offset, "has_more": proxy.has_more, "items": items}

    extra = [
        inspect.Parameter("contains", inspect.Parameter.KEYWORD_ONLY, default="", annotation=str),
        inspect.Parameter("offset", inspect.Parameter.KEYWORD_ONLY, default=0, annotation=int),
        inspect.Parameter("limit", inspect.Parameter.KEYWORD_ONLY, default=20, annotation=int),
    ]
    wrapper.__signature__ = sig.replace(parameters=[*sig.parameters.values(), *extra], return_annotation=dict)
    return wrapper


_PAGING_NOTE = (
    " Returns one page {total, offset, has_more, items} (limit default 20, max 200). `contains` is"
    " Action1's server-side text filter on the items' own fields (e.g. CVE id or product name for"
    " vulnerabilities) - check `total` before paging through everything."
)


def build_server(client: Action1Client) -> MCPServer:
    mcp = MCPServer("action1", instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(readOnlyHint=True)
    writes = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
    for name, description in TOOLS.items():
        fn = getattr(client, name)
        sig = inspect.signature(fn, eval_str=True)
        if sig.return_annotation == list[dict] and "limit" not in sig.parameters:
            fn, description = _paged(client, name), description + _PAGING_NOTE
        mcp.add_tool(_expose_errors(fn), name=name, description=description, annotations=read_only)
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

    @_expose_errors
    def run_script(org_id: str, endpoint_ids: list[str], script: str, wait_seconds: int = 120) -> dict:
        """Run a PowerShell script now, as SYSTEM, on the given endpoints (ids from list_endpoints)
        and wait up to wait_seconds for results. Returns each endpoint's status and output
        (stdout, capped at ~10,000 chars by Action1). Never reboots. Offline endpoints stay
        pending - check later with list_automation_instance_endpoint_results(instance_id)."""
        instance_id = client.run_script(org_id, endpoint_ids, script, name="MCP run_script")["id"]
        deadline = time.monotonic() + max(0, min(wait_seconds, 600))
        while True:
            results = client.list_automation_instance_endpoint_results(org_id, instance_id)
            done = len(results) >= len(endpoint_ids) and all(
                r.get("status") not in ("Pending", "Running", "Waiting") for r in results
            )
            if done or time.monotonic() >= deadline:
                break
            time.sleep(5)
        return {
            "instance_id": instance_id,
            "finished": done,
            "results": [
                {"endpoint_id": r.get("id"), "endpoint_name": r.get("endpoint_name"),
                 "status": r.get("status"), "output": r.get("description")}
                for r in results
            ],
        }

    mcp.add_tool(run_script, annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
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
