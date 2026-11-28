# A1 catalog search plan and receipt

Agent A owns the offline native CLI search, exact-ID detail, shared core query,
and acceptance fixture. The source baseline is
`7efe2609828f6ed136f1feebe10e9a6f89268cb2`. The input is discovery-data revision
`ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62` and its two partitions and verified
evidence file. The validation host is Linux x64. MCP, discovery, authentication,
token requests, hosted compute, and additional platforms are outside A1.

## Plan

1. Read the three local snapshot files, aligning verification evidence by exact AppId.
2. Query individual source claims and resource grant rows, preserving provenance
   and conflicts in stable JSON.
3. Build the Linux x64 CLI and run the focused acceptance script using the pinned
   input and a synthetic fixture. Record commands, outcomes, and unknowns here.

## Receipt

[A1 issue #165](https://github.com/nathanmcnulty/TokenForge/issues/165).
Paseo host `paseo-lxc` reported Linux x86_64. Validation used .NET SDK
10.0.401 and a framework-dependent build targeting Linux x64. The SDK and
local NuGet caches were prepared in `/tmp`. The restore used an intermediate
lock file for the Linux-only framework-dependent configuration.

```sh
DOTNET_CLI_HOME=/tmp/tokenforge-a1-dotnet DOTNET_NOLOGO=1 /tmp/tokenforge-a1-sdk.B8p4La/dotnet build native/TokenForge.Cli -c Release -r linux-x64 --no-restore -p:RuntimeIdentifiers=linux-x64 -p:SelfContained=false -p:PublishSingleFile=false -p:EnableRuntimePackDownload=false -p:UseSharedCompilation=false -m:1 -nr:false
python3 tests/PublishedCatalogSearch.test.py /tmp/tokenforge-a1-sdk.B8p4La/dotnet native/TokenForge.Cli/bin/Release/net10.0/linux-x64/tokenforge.dll
git diff --check
```

- Build passed with zero warnings and zero errors. Source scope and fixtures
  were finalized before the build and acceptance run.
- The acceptance script passed with 2,066 verified IDs and 5,500 IDs across
  both partitions, including 3,434 IDs with unknown tenancy evidence. It
  checked exact-ID detail and partition parity, exact verification records,
  byte-stable JSON and parsed round-trip, unknown configured audience,
  conflicting metadata, no match, and grant isolation across claim rows
  and resources.
- The diff whitespace check passed. `paseo usage --json` returned
  `DAEMON_NOT_RUNNING`, so usage was unavailable.
- The framework-dependent CLI was exercised directly. Release-package
  qualification and independent review remain pending. Configured sign-in
  audience and the total Microsoft-owned multitenant population remain
  unknown in the pinned input.
