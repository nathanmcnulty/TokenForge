# M3 scoped-token CLI handoff and receipt

[Tracking issue #171](https://github.com/nathanmcnulty/TokenForge/issues/171)

Start the [A2 catalog MCP server](a2-catalog-mcp.md) with the additional
arguments `--authorized-client-id <GUID>`. The operator supplies the GUID
of a client they are authorized to use in their tenant. This opt-in
enables `plan_token_request`. Catalog lookup and search use the same
offline snapshot with or without the option.

Call `plan_token_request` with a non-empty resource AppId and 1–64 explicit
API scope names. For example, use `{"resourceId":"00000003-0000-0000-c000-000000000000","scopes":["User.Read"]}`.
The server returns the script path, the PowerShell parameters
`Action`, `ClientId`, `ResourceId`, and `Scope`, and lists `StatePath` as
required local input. The catalog revision identifies the server snapshot.
The configured GUID records the operator's client choice. Authorization
and issuance still depend on the tenant, account, and session.

From a local TokenForge checkout in PowerShell 7.6+, use the plan values
and supply private state and authentication settings locally. For example,
for a plan configured with the synthetic GUID below, the handoff takes
this form:

```powershell
$token = ./scripts/Invoke-TokenForge.ps1 -Action Token -StatePath $privateState `
    -ClientId '22222222-2222-2222-2222-222222222222' `
    -ResourceId '00000003-0000-0000-c000-000000000000' -Scope User.Read -Browser
try {
    $token | Select-Object ClientId, ResourceId, RequestedScopes, GrantedScopes
} finally {
    $token.AccessToken.Dispose()
    if ($token.RefreshToken) { $token.RefreshToken.Dispose() }
}
```

The [scoped-token workflow](scope-token-workflow.md) confirms the observer
with its existing Graph bootstrap, which has a separate `BootstrapClientId`
setting. It requires enabled ownership-verified inventory entries and
fresh matching coverage for the configured client. It requests explicit
scopes silently and checks the issued token's tenant, principal, client,
audience and delegated scopes. The credential result stays in the local
PowerShell process. MCP has only the planning inputs and output. Keep
the local credential result out of the MCP client.

## Linux x64 validation receipt

Source baseline `03d6246516e688644c2ead101755f94d0b52991c` (A2 merge,
PR #170), plus the M3 implementation in this commit. The catalog fixture
pins `ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62`. The host reported
`Linux x86_64`. Validation used the existing .NET SDK 10.0.401,
PowerShell 7.6.6 and Pester 6.2.0. Run from the repository root.

```bash
export DOTNET_CLI_HOME=/tmp/tokenforge-a1-dotnet DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
flags=(-p:RuntimeIdentifiers=linux-x64 -p:SelfContained=false -p:PublishSingleFile=false -p:EnableRuntimePackDownload=false -p:UseSharedCompilation=false -p:NuGetLockFilePath=obj/linux-x64.packages.lock.json -m:1 -nr:false)
unshare -Urn -- "$sdk" restore native/TokenForge.Cli -r linux-x64 --source "$DOTNET_CLI_HOME/.nuget/packages" "${flags[@]}" &&
unshare -Urn -- "$sdk" build native/TokenForge.Cli -c Release -r linux-x64 --no-restore "${flags[@]}"
```

The framework-dependent build used the local package cache and completed
with zero warnings and errors.

```bash
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
cli=native/TokenForge.Cli/bin/Release/net10.0/linux-x64/tokenforge.dll
scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_CLI_HOME="$scratch" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_EnableDiagnostics=0 PSModulePath=/home/paseo/.local/share/powershell/Modules timeout 120s python3 -u tests/M3TokenHandoff.test.py /home/paseo/.local/bin/pwsh "$sdk" "$cli"

scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_CLI_HOME="$scratch" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_EnableDiagnostics=0 timeout 120s python3 -u tests/PublishedCatalogMcp.test.py "$sdk" "$cli"

scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" PSModulePath=/home/paseo/.local/share/powershell/Modules timeout 120s /home/paseo/.local/bin/pwsh -NoLogo -NoProfile -NonInteractive -Command 'Invoke-Pester -Path ./tests/ScopedToken.Tests.ps1 -Output Detailed -CI'

git diff --cached --check
```

- M3 MCP stdio returned exactly the documented metadata in both result
  representations. Eleven invalid inputs were rejected, including client
  overrides, access and refresh token fields, and implicit scopes. With
  no configured client, the tool was absent and calls were rejected. The
  MCP process exited before the local CLI acquired credentials.
- M3 mocked four identity cases through the returned parameters and the
  real CLI. Success returned matching access and refresh SecureStrings
  inside the local process. A missing delegated claim scope and a wrong
  audience each yielded zero token objects. `interaction_required`
  yielded zero token objects, retained only the numeric AADSTS50076 code,
  and stopped without redeeming a final token. Each case used
  `prompt=none` and the configured final client despite another eligible
  client in the fixture.
- A2 passed with full CLI/MCP evidence parity for 2,066 verified and 5,500
  total records, exact detail lookups, pagination, and 18 invalid calls.
  The existing scoped-token suite passed 29 tests. The staged diff check passed.

Remaining unknowns include live consent and issuance for any tenant or
client, real browser/passkey execution through this handoff, API
acceptance, and behavior on other platforms. Validation used synthetic
identity responses in isolated network namespaces, and the published
catalog was replayed from local Git objects.
