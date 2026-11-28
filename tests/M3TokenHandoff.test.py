"""Drive MCP planning over stdio, then run the returned handoff with offline identity mocks."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

a2 = runpy.run_path(str(Path(__file__).with_name("PublishedCatalogMcp.test.py")))
CLIENT = "22222222-2222-2222-2222-222222222222"
RESOURCE = "00000003-0000-0000-c000-000000000000"


def main():
    pwsh, *command = sys.argv[1:]
    revision = json.loads(a2["FIXTURE"].read_bytes())["revision"]
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory)
        for filename in a2["FILES"]:
            (snapshot / filename).write_bytes(subprocess.check_output(
                ["git", "--no-replace-objects", "show", f"{revision}:{filename}"],
                env=dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="")))
        server = command + ["catalog", "mcp", "--snapshot", directory, "--revision", revision]
        arguments = {"resourceId": RESOURCE, "scopes": ["User.Read", "User.Read"]}
        for configured in (False, True):
            options = ["--authorized-client-id", CLIENT] if configured else []
            with subprocess.Popen(server + options, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8") as process:
                rpc = a2["Client"](process)
                rpc.send("initialize", {"protocolVersion": "2025-11-25"})
                rpc.send("notifications/initialized", notification=True)
                names = {tool["name"] for tool in rpc.send("tools/list")["result"]["tools"]}
                expected = {"search_applications", "get_application"}
                if configured:
                    expected.add("plan_token_request")
                assert names == expected
                if configured:
                    plan = rpc.result("plan_token_request", arguments)
                    assert plan == {
                        "SchemaVersion": 1, "CatalogRevision": revision,
                        "Script": "./scripts/Invoke-TokenForge.ps1",
                        "Parameters": {"Action": "Token", "ClientId": CLIENT,
                                       "ResourceId": RESOURCE, "Scope": ["User.Read"]},
                        "RequiredLocalParameters": ["StatePath"],
                    }
                    for invalid in ({}, dict(arguments, clientId=CLIENT),
                                    dict(arguments, resourceId="00000000-0000-0000-0000-000000000000"),
                                    dict(arguments, scopes=[]), dict(arguments, scopes=[None]),
                                    dict(arguments, scopes=["User.Read"] * 65),
                                    dict(arguments, scopes=[".default"]), dict(arguments, scopes=["offline_access"]),
                                    dict(arguments, scopes=["User.Read; echo secret"]),
                                    dict(arguments, accessToken="mock-access-secret"),
                                    dict(arguments, refreshToken="mock-refresh-secret")):
                        response = rpc.call("plan_token_request", invalid)
                        assert response["error"]["code"] == -32602
                        assert "mock-access-secret" not in str(response)
                        assert "mock-refresh-secret" not in str(response)
                else:
                    assert rpc.call("plan_token_request", arguments)["error"]["code"] == -32602
                # MCP exits before the operator acquires any credentials. There is no return channel.
                stdout, stderr = process.communicate(timeout=5)
                assert process.returncode == 0 and not stdout and not stderr
        print("M3 MCP: opt-in tool, exact credential-free handoff, 11 invalid calls rejected")
        handoff = snapshot / "handoff.json"
        handoff.write_text(json.dumps(plan), encoding="utf-8")
        subprocess.run(
            [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             "Invoke-Pester -Path ./tests/M3TokenHandoff.Tests.ps1 -Output Detailed -CI"],
            env=dict(os.environ, TOKENFORGE_M3_HANDOFF=str(handoff)), check=True)


if __name__ == "__main__":
    main()
