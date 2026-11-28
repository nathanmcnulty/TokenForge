# A2 published catalog MCP walkthrough and receipt

[A2 tracking issue #168](https://github.com/nathanmcnulty/TokenForge/issues/168)

## Connect a local MCP client

Use a native TokenForge executable built from this source. Stage
`applications.json`, `applications.non-verified.json`, and
`applications.verified-evidence.json` from the same catalog revision in one
directory. For the walkthrough below, the client stages the three files
directly from local Git objects.

Configure a stdio server with this command and argument array, using absolute
paths to the executable and snapshot directory.

```json
{
  "command": "/path/to/tokenforge",
  "args": ["catalog", "mcp", "--snapshot", "/path/to/snapshot", "--revision", "ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62"]
}
```

The server loads the snapshot once at startup. Restart it to switch snapshots.
The revision identifies the supplied files and is echoed in every result.
For a framework-dependent build, use the absolute path to `dotnet` as the
command and prepend the absolute path to `tokenforge.dll` to the arguments.

- `search_applications` accepts optional `appId`, `name`, `resourceId`,
  `scopes`, `tenancyEvidence`, and `includeNonVerified` filters. Verified
  records are included by default. `includeNonVerified: true` includes both
  partitions. Names use case-insensitive substring matching and all requested
  scopes must match one resource grant row with case-sensitive scope names.
  Tenancy values are `owner-outside-target-tenant`,
  `owner-not-outside-target-tenant`, and `unknown`.
- Search returns up to `pageSize` applications in ascending AppId order.
  `pageSize` defaults to 25 and accepts 1–100. `offset` defaults to 0.
  Supply the returned `NextOffset` as `offset` with the same filters to
  continue until `NextOffset` is null. `Count` is the total number of
  matches across pages. An offset beyond the last match yields an empty page.
- `get_application` requires a full hyphenated `appId` GUID and accepts
  `includeNonVerified`. It returns the same zero-or-one result as
  `catalog get`. Both tools preserve the A1 result fields, including
  partition, provenance, observation dates, matching claims and grants,
  and unknown fields.

The optional [M3 CLI handoff](m3-cli-handoff.md) uses a client AppId configured
at server startup.

## Local validation receipt

The source baseline was `c0c0380a515e85bcb2aefba8b434fddaa6687d33`
(PR #167). The host reported Linux x86_64. Validation used .NET 10.0.401
and a framework-dependent Linux x64 build. The commands use an existing
SDK and local NuGet cache under `/tmp`.

```sh
export DOTNET_CLI_HOME=/tmp/tokenforge-a1-dotnet DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
flags=(-p:RuntimeIdentifiers=linux-x64 -p:SelfContained=false -p:PublishSingleFile=false -p:EnableRuntimePackDownload=false -p:UseSharedCompilation=false -p:NuGetLockFilePath=obj/linux-x64.packages.lock.json -m:1 -nr:false)
unshare -Urn -- "$sdk" restore native/TokenForge.Cli -r linux-x64 --source "$DOTNET_CLI_HOME/.nuget/packages" "${flags[@]}" &&
unshare -Urn -- "$sdk" build native/TokenForge.Cli -c Release -r linux-x64 --no-restore "${flags[@]}"
```

Restore used the local cache. Build succeeded with zero warnings and zero
errors.

The shared fixture in `tests/fixtures/a2-catalog-mcp.json` drives the same
searches and exact detail lookups through both interfaces. The walkthrough
and A1 regression check ran in isolated network namespaces with an empty
credential home and a cleared environment.

```sh
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
cli=native/TokenForge.Cli/bin/Release/net10.0/linux-x64/tokenforge.dll
scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_CLI_HOME="$scratch" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_EnableDiagnostics=0 timeout 120s python3 -u tests/PublishedCatalogMcp.test.py "$sdk" "$cli"
```

```text
tools/list: search_applications, get_application
verified: 2066 matches, 21 pages, full CLI/MCP evidence parity
both partitions: 5500 matches, 55 pages, full CLI/MCP evidence parity
name, resource, scopes and tenancy: 1 matches, 1 pages, full CLI/MCP evidence parity
case-sensitive scope miss: 0 matches, 1 pages, full CLI/MCP evidence parity
exact detail 0000000C-0000-0000-C000-000000000000 (includeNonVerified=False): 1 matches
exact detail 00000000-0000-0000-0000-000000000001 (includeNonVerified=False): 0 matches
exact detail 00000000-0000-0000-0000-000000000001 (includeNonVerified=True): 1 matches
exact detail ffffffff-ffff-ffff-ffff-ffffffffffff (includeNonVerified=False): 0 matches
18 invalid calls rejected; default and past-end pagination passed
A2 passed at ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62
```

```sh
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
cli=native/TokenForge.Cli/bin/Release/net10.0/linux-x64/tokenforge.dll
scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_CLI_HOME="$scratch" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_EnableDiagnostics=0 timeout 120s python3 -u tests/PublishedCatalogSearch.test.py "$sdk" "$cli"
```

```text
A1 passed: 2066 verified, 5500 total, 3434 unknown tenancy; exact detail, provenance, explicit false vs. missing/null tenancy, byte-stable JSON round-trip, audience, conflicts, no-match and scope isolation.
```

`git diff --cached --check` passed.
