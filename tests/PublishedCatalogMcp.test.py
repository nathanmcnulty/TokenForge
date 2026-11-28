"""Walk a fresh stdio MCP connection and compare it with the native CLI."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

FIXTURE = Path(__file__).with_name("fixtures") / "a2-catalog-mcp.json"
FILES = ("applications.json", "applications.non-verified.json", "applications.verified-evidence.json")
FILTER_OPTIONS = {"appId": "--id", "name": "--name", "resourceId": "--resource",
                  "tenancyEvidence": "--tenancy-evidence"}


class Client:
    def __init__(self, process):
        self.process = process
        self.request_id = 0

    def send(self, method, params=None, *, notification=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notification:
            self.request_id += 1
            message["id"] = self.request_id
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        if notification:
            return
        line = self.process.stdout.readline()
        assert line, f"Server closed stdout during {method}"
        response = json.loads(line)
        assert response["jsonrpc"] == "2.0" and response["id"] == self.request_id, response
        return response

    def call(self, name, arguments):
        return self.send("tools/call", {"name": name, "arguments": arguments})

    def result(self, name, arguments):
        response = self.call(name, arguments)
        assert "result" in response, response
        result = response["result"]
        assert not result.get("isError"), result
        data = result["structuredContent"]
        assert result["content"][0]["type"] == "text"
        assert json.loads(result["content"][0]["text"]) == data
        return data


def cli(command, operation, arguments):
    options = []
    for key, value in arguments.items():
        if key == "scopes":
            for scope in value:
                options.extend(["--scope", scope])
        elif key == "includeNonVerified":
            if value:
                options.append("--include-non-verified")
        else:
            options.extend([FILTER_OPTIONS[key], value])
    return json.loads(subprocess.check_output(command(operation) + options))


def check(command, client, fixture):
    initialize = client.send("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "tokenforge-walkthrough", "version": "1"},
    })["result"]
    assert initialize["protocolVersion"] == "2025-11-25"
    assert "tools" in initialize["capabilities"]
    client.send("notifications/initialized", notification=True)
    tools = client.send("tools/list")["result"]["tools"]
    assert {tool["name"] for tool in tools} == {"search_applications", "get_application"}
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)
    print("tools/list: search_applications, get_application")

    for case in fixture["searches"]:
        arguments = case["arguments"]
        expected = cli(command, "search", arguments)
        assert expected["CatalogRevision"] == fixture["revision"]
        assert expected["Count"] == case["count"]
        page_size = 100
        rows = []
        offset = pages = 0
        while offset is not None:
            request = dict(arguments, pageSize=page_size, offset=offset)
            page = client.result("search_applications", request)
            for key in ("SchemaVersion", "CatalogRevision", "Count"):
                assert page[key] == expected[key], (case["label"], key, page[key])
            assert page["Offset"] == offset and page["PageSize"] == page_size
            assert len(page["Applications"]) == min(page_size, expected["Count"] - offset)
            if offset == 0:
                assert page == client.result("search_applications", request)
            rows.extend(page["Applications"])
            next_offset = offset + len(page["Applications"])
            assert page["NextOffset"] == (next_offset if next_offset < expected["Count"] else None)
            offset = page["NextOffset"]
            pages += 1
        assert rows == expected["Applications"], case["label"]
        ids = [row["AppId"] for row in rows]
        assert ids == sorted(set(ids))
        print(f'{case["label"]}: {len(rows)} matches, {pages} pages, full CLI/MCP evidence parity')

    for case in fixture["details"]:
        arguments = case["arguments"]
        detail = client.result("get_application", arguments)
        assert detail == cli(command, "get", arguments)
        assert detail["CatalogRevision"] == fixture["revision"] and detail["Count"] == case["count"]
        if case["count"]:
            assert detail["Applications"][0]["AppId"] == arguments["appId"].lower()
        print(f'exact detail {arguments["appId"]} (includeNonVerified={arguments.get("includeNonVerified", False)}): {case["count"]} matches')

    for arguments in ({"name": ""}, {"name": "  \t"}, {"name": None}, {"scopes": [""]},
                      {"scopes": ["User.Read", "  "]}, {"scopes": [None]}, {"scopes": "Read"},
                      {"pageSize": 0}, {"pageSize": 101}, {"pageSize": 1.5}, {"offset": -1},
                      {"offset": 2147483648}, {"tenancyEvidence": "invalid"}, {"typo": True}):
        assert client.call("search_applications", arguments)["error"]["code"] == -32602, arguments
    for arguments in ({}, {"appId": "00000001"}, {"appId": "0000000100000000c000000000000000"},
                      {"appId": "00000001-0000-0000-c000-000000000000", "name": "unexpected"}):
        assert client.call("get_application", arguments)["error"]["code"] == -32602, arguments
    first = client.result("search_applications", {})
    assert first["PageSize"] == 25 and first["NextOffset"] == len(first["Applications"]) == 25
    empty = client.result("search_applications", {"offset": 2147483647})
    assert empty["Count"] == 2066 and empty["NextOffset"] is None and empty["Applications"] == []
    print("18 invalid calls rejected; default and past-end pagination passed")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python3 tests/PublishedCatalogMcp.test.py <tokenforge command...>")
    fixture = json.loads(FIXTURE.read_bytes())
    revision = fixture["revision"]
    git_env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="")
    with tempfile.TemporaryDirectory() as directory:
        for filename in FILES:
            data = subprocess.check_output(
                ["git", "--no-replace-objects", "show", f"{revision}:{filename}"], env=git_env)
            (Path(directory) / filename).write_bytes(data)

        def command(operation):
            return [*sys.argv[1:], "catalog", operation, "--snapshot", directory, "--revision", revision]

        with subprocess.Popen(command("mcp"), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, encoding="utf-8") as process:
            try:
                check(command, Client(process), fixture)
                process.stdin.close()
                assert process.wait(timeout=5) == 0
            finally:
                if process.poll() is None:
                    process.kill()
    print(f"A2 passed at {revision}")


if __name__ == "__main__":
    main()
