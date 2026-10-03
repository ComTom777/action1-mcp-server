import asyncio

import httpx
import respx
from action1_client import Action1Client

from action1_mcp.server import TOOLS, WRITE_TOOLS, build_server

BASE = "https://app.action1.com/api/3.0"


def test_all_tools_registered():
    tools = asyncio.run(build_server(Action1Client("id", "secret")).list_tools())
    assert {t.name for t in tools} == set(TOOLS) | set(WRITE_TOOLS) | {"publish_check"}


@respx.mock
def test_tool_call_hits_api():
    respx.post(f"{BASE}/oauth2/token").respond(json={"access_token": "t", "expires_in": 3600})
    respx.get(f"{BASE}/endpoints/managed/org1").respond(
        json={"items": [{"id": "e1", "name": "pc"}], "next_page": ""}
    )
    server = build_server(Action1Client("id", "secret"))
    result = asyncio.run(server.call_tool("list_endpoints", {"org_id": "org1"}))
    assert "pc" in str(result)


@respx.mock
def test_api_error_reaches_model():
    respx.post(f"{BASE}/oauth2/token").respond(json={"access_token": "t", "expires_in": 3600})
    respx.get(f"{BASE}/organizations").respond(403, json={"user_message": "Access denied"})
    server = build_server(Action1Client("id", "secret"))
    try:
        asyncio.run(server.call_tool("list_organizations", {}))
    except Exception as exc:
        assert "Access denied" in str(exc)
    else:
        raise AssertionError("expected a tool error")
