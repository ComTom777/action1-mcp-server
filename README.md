# action1-mcp-server

**Unofficial**: not affiliated with, endorsed by, or supported by Action1 Corporation.
An [MCP](https://modelcontextprotocol.io) server for the [Action1](https://www.action1.com/) RMM API,
built on [action1-python-client](https://github.com/ComTom777/action1-python-client).

**What it can do:**

- **Read**: organizations, endpoints, groups, missing updates, vulnerabilities, automations,
  reports, users, roles, data sources (`TOOLS` in `src/action1_mcp/server.py`).
- **Build custom reports**: the model writes a PowerShell check, calls `publish_check` to create
  the Action1 data source + custom report, `requery_report` to have agents collect now, then
  `list_report_data` to read results, e.g. "check my Windows servers against CIS Level 1 and
  summarize what fails". The workflow is described to the model in the server's instructions.
- **Run scripts**: `run_script` runs PowerShell as SYSTEM on chosen endpoints right now and returns
  each one's output (capped at ~10,000 chars by Action1; never reboots). Good for one-off
  diagnostics or fetching files a data source wrote, e.g. the full CIS v8 details JSON.
- **Change** only report-related things (`WRITE_TOOLS`): requery, delete a custom report or data
  source. No endpoint/user/org deletes. MCP clients ask before calling non-read-only tools.

Data sources run on online **Windows** agents only (Action1 data sources are PowerShell-only);
results arrive asynchronously, typically minutes after `requery_report`.

## Install

```bash
pip install git+https://github.com/ComTom777/action1-mcp-server.git
```

or use it without installing, via [uv](https://docs.astral.sh/uv/):
`uvx --from git+https://github.com/ComTom777/action1-mcp-server.git action1-mcp`

## Configure

Create an API key in the Action1 console (Configuration → API Credentials), then add the server
to your MCP client.

**Claude Code:**

```bash
claude mcp add action1 \
  -e ACTION1_CLIENT_ID=api-key-xxxx@action1.com \
  -e ACTION1_CLIENT_SECRET=... \
  -e ACTION1_REGION=europe \
  -- uvx --from git+https://github.com/ComTom777/action1-mcp-server.git action1-mcp
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "action1": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/ComTom777/action1-mcp-server.git", "action1-mcp"],
      "env": {
        "ACTION1_CLIENT_ID": "api-key-xxxx@action1.com",
        "ACTION1_CLIENT_SECRET": "...",
        "ACTION1_REGION": "europe"
      }
    }
  }
}
```

`ACTION1_REGION` is `north_america` (default), `europe`, or `australia`.

## Adding a tool

Add `"client_method_name": "description"` to `TOOLS` in `server.py`. The tool's parameters
come from the client method's signature.

## Development

```bash
python -m venv .venv
.venv\Scripts\activate      # Windows
pip install -e ".[dev]"
pytest
```
