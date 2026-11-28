# M4 Linux x64 independent reproduction

On 2026-11-28, a clean rebuild of
`5a682d3373da08d2094ed837837934020116770c` reproduced
`TokenForge-0.48.0-5a682d3-linux-x64.tar.gz` byte for byte. The complete
payload digest list and path, type and mode list matched the original.
There were no added, missing, byte-changed or mode-changed paths.
This follows the [original qualification](m4-linux-x64-qualification.md)
from PR #175. [Tracking issue #176](https://github.com/nathanmcnulty/TokenForge/issues/176)

## Inputs and digests

The review branch started at fetched `origin/main`
(`df578d9007a277490bab2231c6a52bc3eea19286`). The package and check
harnesses came from a separate detached worktree at the pinned source
revision. The build used Debian 13.8 x86_64, kernel 7.0.14-17-pve,
.NET SDK 10.0.401, .NET runtime packs 10.0.12, and PowerShell 7.6.6.
Packaging used GNU tar 1.35 and gzip 1.13. Validation used Pester 6.2.0.
The build reused the retained SDK and dependency feed with fresh restore
and build directories. The original package and manifests served as
comparison references.

| Item | SHA-256 |
| --- | --- |
| Archive | `2d6e8da9448ee9c76ca8ae3393da9836dc8affb07d8fcfe13b98b3f7e43fa45c` |
| Complete payload hash list (176 files) | `c725ae1ae6bc83e2da0d5bc3656994f3bcf133a355fd2d2629a10ea819feeea9` |
| Path, type and mode list (187 entries) | `3fab3cca0f8db5d192d89ca653c2830b3290f72517d59bf40adbaea03da864c5` |
| `tokenforge` | `7c565c3af41130454a6873aa3ce1a75e01aa9f86dcdf4a2dc747678d51f3426d` |
| `TokenForge.Credentials.dll` | `9b941032f3f1146057ea1cdc0e6c4ae14dbc05eda895268fac7ef421287552c8` |
| `scripts/Invoke-TokenForge.ps1` | `2794baf90de4037590f1006492bc499eb6d12f2b7d8abe07a1547a7e310c69f7` |
| Projected CLI lock | `ba06b1fcbc51a58fc8067d9eaee4824a09dbd700e7c3b92c2c29725a89e5011f` |
| Projected Core lock | `c7d4283106acae4fe2978f386e606679c01e6a9531c1286ea6016d484f464d64` |
| Projected Credentials lock | `ce45544f1fd90b4415b1def8bd823c56d47b951fe67d74d79e045f7ca4e89b16` |

The layout comprised 11 directories at `0750`, 175 files at `0640`,
and the executable at `0755`. The three retained NuGet packs matched
the 10.0.12 hashes in the original receipt.

The catalog came directly from local Git objects at
`ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62`.

| Catalog input | SHA-256 |
| --- | --- |
| `applications.json` | `93cb678c13bf22906f8544dbdd3bf3795dc705cdb6af07b01225361a653ac0e2` |
| `applications.non-verified.json` | `fb58d4bb0e4647257bdf6945218ed88be89fc4ef59750e0a2c732229c2be516a` |
| `applications.verified-evidence.json` | `21b61c704b95703cce8dbed0922ea7de5bb06491eef99f36b5af225c8ecf33d0` |
| `tests/fixtures/a2-catalog-mcp.json` from the package source revision | `15333593a8cf5f2aab900209a2b6138e4763634150b80d8be6ab91de3fd4969f` |

## Build and comparison commands

The build and validation logs, rebuilt archive, and full manifests are
retained under `/tmp/tokenforge-m4-reproduction.u6aqqj`.

```bash
set -euo pipefail
git fetch origin main
umask 027
git worktree add -b milestone-m4-linux-x64-reproduction .m4-reproduction-worktree origin/main
git worktree add --detach .m4-reproduction-source 5a682d3373da08d2094ed837837934020116770c
cd .m4-reproduction-source

root=$(mktemp -d /tmp/tokenforge-m4-reproduction.XXXXXX)
original=/tmp/tokenforge-m4-build
feed=/tmp/tokenforge-m4-feed
cache=/tmp/tokenforge-a1-dotnet/.nuget/packages
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
pwsh=/home/paseo/.local/bin/pwsh
name=TokenForge-0.48.0-5a682d3-linux-x64.tar.gz
sha256sum -c <<CHECKSUMS
2d6e8da9448ee9c76ca8ae3393da9836dc8affb07d8fcfe13b98b3f7e43fa45c  $original/$name
c725ae1ae6bc83e2da0d5bc3656994f3bcf133a355fd2d2629a10ea819feeea9  $original/payload.sha256
3fab3cca0f8db5d192d89ca653c2830b3290f72517d59bf40adbaea03da864c5  $original/layout.txt
5e3883d280dac567a4bc19a52a75669bf96e24bd41e29ec9ea1baafbd1a6a800  $feed/microsoft.aspnetcore.app.runtime.linux-x64.10.0.12.nupkg
37aa984da51fdc01cc7d57a8647893392f3539cdd5a1d32ce4982be5309bc08b  $feed/microsoft.net.illink.tasks.10.0.12.nupkg
8869e2fb974bc810ffe40b8fb8e18b7ffb1d1a03e52a094c804668c4d793b1ae  $feed/microsoft.netcore.app.runtime.linux-x64.10.0.12.nupkg
CHECKSUMS
mkdir "$root"/{home,dotnet,nuget,tmp}
clean=(unshare -Urn -- env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC
  HOME="$root/home" TMPDIR="$root/tmp" DOTNET_CLI_HOME="$root/dotnet"
  NUGET_PACKAGES="$root/nuget" DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
  DOTNET_EnableDiagnostics=0)
"${clean[@]}" "$sdk" --version
for project in native/TokenForge.{Cli,Core,Credentials}; do
  mkdir -p "$project/obj"
  jq '.dependencies |= with_entries(select(.key == "net10.0" or .key == "net10.0/linux-x64"))' \
    "$project/packages.lock.json" > "$project/obj/m4-linux-x64.packages.lock.json"
done
sha256sum native/TokenForge.{Cli,Core,Credentials}/obj/m4-linux-x64.packages.lock.json
"${clean[@]}" "$sdk" restore native/TokenForge.Cli -r linux-x64 --locked-mode \
  --source "$feed" --source "$cache" -p:RuntimeIdentifiers=linux-x64 \
  -p:SelfContained=true -p:NuGetAudit=false -p:NuGetLockFilePath=obj/m4-linux-x64.packages.lock.json
cat >"$root/dotnet-wrapper" <<'SH'
#!/bin/bash
exec /tmp/tokenforge-a1-sdk.B8p4La/dotnet "$@" -p:UseSharedCompilation=false -m:1 -nr:false
SH
chmod +x "$root/dotnet-wrapper"
"${clean[@]}" "$pwsh" -NoProfile -File scripts/Build-TokenForgeNative.ps1 \
  -Runtime linux-x64 -OutputPath "$root/build" -Dotnet "$root/dotnet-wrapper" -NoRestore
stage="$root/build/linux-x64"
archive="$root/$name"
epoch=$(git show -s --format=%ct HEAD)
(cd "$stage" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "$root/payload.sha256"
(cd "$stage" && find . -printf '%y %m %p\n' | LC_ALL=C sort) > "$root/layout.txt"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - . | gzip -n > "$archive"
sha256sum "$archive" "$root/payload.sha256" "$root/layout.txt" "$stage/tokenforge" \
  "$stage/src/TokenForge/lib/net10.0/TokenForge.Credentials.dll" "$stage/scripts/Invoke-TokenForge.ps1"
for item in "$name" payload.sha256 layout.txt; do
  cmp "$root/$item" "$original/$item"
done
diff -u "$original/payload.sha256" "$root/payload.sha256"
diff -u "$original/layout.txt" "$root/layout.txt"
```

## Installation and capability checks

| Capability | Result |
| --- | --- |
| Clean installation | Pass. The archive digest, all 176 installed file digests and all 187 layout entries matched. The native executable reported 0.48.0 with an empty runtime root. |
| Offline catalog CLI | Pass. 2,066 verified, 5,500 total and 3,434 with unknown tenancy. Exact detail, provenance, byte-stable JSON, tenancy distinctions, unknown audience, conflicting metadata, misses and scope isolation passed. |
| MCP stdio startup | Pass. The packaged server initialized and listed `search_applications` and `get_application`. The M3 planning tool appeared only with the explicitly configured client. |
| CLI/MCP evidence parity | Pass. Full evidence and revision matched over 21 verified pages, 55 combined pages, the filtered match and miss, and four exact lookups. Default and past-end pagination passed. MCP rejected 18 invalid catalog calls. |
| M3 operator handoff | Pass. The handoff used the installed script, module and credential DLL. Pester 6.2.0 passed success, missing scope, wrong audience and required interaction, with zero skips or failures. The configured client was selected despite a second eligible client. |

Both MCP result representations matched the expected plan. The harness
rejected 11 invalid planning calls and checked the responses for the
synthetic access and refresh values. MCP exited before PowerShell ran the
handoff. The success case verified both issued SecureStrings in the local
PowerShell process and disposed them there. No issued token was sent
back to MCP. The three failure cases returned zero token objects and
excluded synthetic token values and private identity messages from
diagnostics. Required interaction retained only the numeric
`AADSTS50076` code from the identity response and stopped before final
redemption. The final authorization request used `prompt=none`.

Run from the same detached source worktree with `root`, `archive` and
`pwsh` set as in the build block.

```bash
set -euo pipefail
umask 077
package="$root/install/0.48.0-5a682d3-linux-x64"
printf '%s  %s\n' 2d6e8da9448ee9c76ca8ae3393da9836dc8affb07d8fcfe13b98b3f7e43fa45c "$archive" | sha256sum -c
mkdir -p "$package"
tar --same-permissions -xzf "$archive" -C "$package"
(cd "$package" && sha256sum -c --quiet "$root/payload.sha256")
(cd "$package" && find . -printf '%y %m %p\n' | LC_ALL=C sort) | cmp "$root/layout.txt" -
wc -l "$root/payload.sha256" "$root/layout.txt"
sha256sum tests/fixtures/a2-catalog-mcp.json
revision=ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62
for name in applications.json applications.non-verified.json applications.verified-evidence.json; do
  git --no-replace-objects show "$revision:$name" | sha256sum | sed "s|-$|$name|"
done
offline() {
  local scratch
  scratch=$(mktemp -d "$root/check.XXXXXX")
  unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_ROOT="$scratch" \
    DOTNET_BUNDLE_EXTRACT_BASE_DIR="$scratch/bundle" DOTNET_EnableDiagnostics=0 \
    timeout 120s "$@"
}
offline "$package/tokenforge" --version
for test in PublishedCatalogSearch PublishedCatalogMcp; do
  offline python3 -u "tests/$test.test.py" "$package/tokenforge"
done
offline env PSModulePath=/home/paseo/.local/share/powershell/Modules TOKENFORGE_M3_PACKAGE="$package" \
  python3 -u tests/M3TokenHandoff.test.py "$pwsh" "$package/tokenforge"
```

## Remaining unknowns

Byte identity was demonstrated on the same Linux x64 host with a fresh
checkout, restore and build, using the retained SDK and offline feeds.
Reproduction on another host or with independently provisioned
toolchain bytes remains untested. This receipt covers local offline
behavior and the mocked handoff. Live sign-in, consent, issuance, API
acceptance, browser and passkey behavior, vault persistence, and
published-archive provenance remain untested. Hosted compute,
publication, tenant activity, discovery and additional platforms were
outside the scope of this check.
