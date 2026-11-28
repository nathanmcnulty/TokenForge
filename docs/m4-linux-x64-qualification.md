# M4 Linux x64 distribution qualification

[Tracking issue #174](https://github.com/nathanmcnulty/TokenForge/issues/174)

## Package and provenance

Local candidate `TokenForge-0.48.0-5a682d3-linux-x64.tar.gz`, built from
`5a682d3373da08d2094ed837837934020116770c` in a fresh worktree based on
`30feccb259de55339931c2841ba7cad7241d239c` (PR #173).
The package includes the M3 operator entry point, its bundled module and
credential assembly, and the A2 and M3 guides. The catalog is a separate
input pinned by the A2 fixture to `ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62`.
The walkthrough reads all three catalog files directly from local Git objects.

Validation on 2026-11-28 used Debian GNU/Linux 13.8 (trixie), kernel
7.0.14-17-pve, x86_64, .NET SDK 10.0.401, .NET runtime packs 10.0.12,
PowerShell 7.6.6 and Pester 6.2.0. The archive and manifests are retained
locally under `/tmp/tokenforge-m4-build`. The hashes identify the locally
built candidate. Independent review of its provenance is pending.

| Item | SHA-256 |
| --- | --- |
| Archive | `2d6e8da9448ee9c76ca8ae3393da9836dc8affb07d8fcfe13b98b3f7e43fa45c` |
| Complete payload hash list | `c725ae1ae6bc83e2da0d5bc3656994f3bcf133a355fd2d2629a10ea819feeea9` |
| Path, type and mode list | `3fab3cca0f8db5d192d89ca653c2830b3290f72517d59bf40adbaea03da864c5` |
| `tokenforge` | `7c565c3af41130454a6873aa3ce1a75e01aa9f86dcdf4a2dc747678d51f3426d` |
| `TokenForge.Credentials.dll` | `9b941032f3f1146057ea1cdc0e6c4ae14dbc05eda895268fac7ef421287552c8` |
| `scripts/Invoke-TokenForge.ps1` | `2794baf90de4037590f1006492bc499eb6d12f2b7d8abe07a1547a7e310c69f7` |

## Results for this package

| Capability | Result |
| --- | --- |
| Installation | Pass. The archive matched its local build receipt. Extraction into a new directory preserved all 176 file hashes, full membership and modes. The installed executable reported 0.48.0 in a clean environment with an empty runtime root. The handoff check also verified that PowerShell loaded the installed credential DLL. |
| Offline catalog CLI | Pass. 2,066 verified and 5,500 total, including 3,434 records with unknown tenancy evidence. Exact detail, provenance, byte-stable JSON, unknown audience, conflicting metadata, misses, and scope isolation passed. |
| MCP stdio startup | Pass. A fresh client initialized the packaged executable and listed `search_applications` and `get_application`. The planning tool appeared only with a configured client. |
| CLI/MCP evidence parity | Pass. The shared A2 fixture matched full result evidence and catalog revision across 21 verified pages and 55 combined pages, filtered matches and misses, and all four exact lookups. Default and past-end pagination passed. MCP rejected 18 invalid calls. |
| Operator-run M3 handoff, mocked identity only | Pass. The returned plan invoked the installed PowerShell script using the installed module. Pester passed all four cases. The authorized-client parameter was honored despite a second eligible client in the fixture. |

For the handoff, run the plan's relative script path from the installed package
root in PowerShell 7.6+, with operator inputs supplied locally as shown in the
[M3 walkthrough](m3-cli-handoff.md). The checks used a synthetic cookie and
mocked identity transport:

- **Success** returned matching access and refresh SecureStrings in the local
  PowerShell process. The test disposed both after checking them.
- **Missing scope** and **wrong audience** each returned zero token objects.
- **Required user interaction** returned zero token objects, reported only
  the numeric `AADSTS50076` code from the identity response, and stopped
  before final redemption. The final request used `prompt=none` in all cases.

Both MCP result representations matched the expected credential-free plan.
Eleven invalid calls were rejected, including access and refresh token fields,
whose synthetic values were absent from the error responses. MCP exited before
the separate local CLI process acquired credentials. The fixture supplied no
vault and sent no credential result back to MCP. Failure diagnostics excluded
the synthetic token and private-message values.

## Commands

Run from the qualification worktree at the package source revision above.
The existing SDK and NuGet dependency cache were reused. Stage the three
SDK-selected packs from NuGet before offline restore:

```bash
mkdir -p /tmp/tokenforge-m4-feed
for id in microsoft.net.illink.tasks microsoft.netcore.app.runtime.linux-x64 microsoft.aspnetcore.app.runtime.linux-x64; do
  curl --fail --silent --show-error --location --retry 2 \
    "https://api.nuget.org/v3-flatcontainer/$id/10.0.12/$id.10.0.12.nupkg" \
    -o "/tmp/tokenforge-m4-feed/$id.10.0.12.nupkg" || exit 1
done
sha256sum /tmp/tokenforge-m4-feed/*.nupkg
```

| Pack | SHA-256 |
| --- | --- |
| `microsoft.aspnetcore.app.runtime.linux-x64` | `5e3883d280dac567a4bc19a52a75669bf96e24bd41e29ec9ea1baafbd1a6a800` |
| `microsoft.net.illink.tasks` | `37aa984da51fdc01cc7d57a8647893392f3539cdd5a1d32ce4982be5309bc08b` |
| `microsoft.netcore.app.runtime.linux-x64` | `8869e2fb974bc810ffe40b8fb8e18b7ffb1d1a03e52a094c804668c4d793b1ae` |

The default builder restore requests packs for every configured runtime.
The local build used a Linux x64 projection of the checked-in lock files,
preserving the selected dependency records and hashes, followed by the native
builder with `-NoRestore`. A wrapper selected single-node MSBuild after the
unwrapped command exited unsuccessfully in the isolated environment.

```bash
set -euo pipefail
export DOTNET_CLI_HOME=/tmp/tokenforge-a1-dotnet DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
sdk=/tmp/tokenforge-a1-sdk.B8p4La/dotnet
for project in native/TokenForge.{Cli,Core,Credentials}; do
  mkdir -p "$project/obj"
  jq '.dependencies |= with_entries(select(.key == "net10.0" or .key == "net10.0/linux-x64"))' \
    "$project/packages.lock.json" > "$project/obj/m4-linux-x64.packages.lock.json"
done
unshare -Urn -- "$sdk" restore native/TokenForge.Cli -r linux-x64 --locked-mode \
  --source /tmp/tokenforge-m4-feed --source "$DOTNET_CLI_HOME/.nuget/packages" \
  -p:RuntimeIdentifiers=linux-x64 -p:SelfContained=true -p:NuGetAudit=false \
  -p:NuGetLockFilePath=obj/m4-linux-x64.packages.lock.json

cat >/tmp/tokenforge-m4-dotnet <<'SH'
#!/bin/bash
exec /tmp/tokenforge-a1-sdk.B8p4La/dotnet "$@" -p:UseSharedCompilation=false -m:1 -nr:false
SH
chmod +x /tmp/tokenforge-m4-dotnet
unshare -Urn -- /home/paseo/.local/bin/pwsh -NoProfile -File scripts/Build-TokenForgeNative.ps1 \
  -Runtime linux-x64 -OutputPath /tmp/tokenforge-m4-build -Dotnet /tmp/tokenforge-m4-dotnet -NoRestore
```

The archive was created from the staged payload. Installation used
`--same-permissions` after the first extraction's private umask narrowed
the archived modes. The final mode-preserving installation was in a new
directory under the private parent.

```bash
set -euo pipefail
umask 077
root=/tmp/tokenforge-m4-build
stage="$root/linux-x64"
archive="$root/TokenForge-0.48.0-5a682d3-linux-x64.tar.gz"
package="$root/install/0.48.0-5a682d3-linux-x64"
epoch=$(git show -s --format=%ct 5a682d3373da08d2094ed837837934020116770c)
(cd "$stage" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "$root/payload.sha256"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$stage" -cf - . | gzip -n > "$archive"
sha256sum "$archive" > "$root/archive.sha256"
sha256sum -c "$root/archive.sha256"
mkdir -p "$(dirname "$package")"
mkdir "$package"
tar --same-permissions -xzf "$archive" -C "$package"
(cd "$package" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | cmp "$root/payload.sha256" -
(cd "$stage" && find . -printf '%y %m %p\n' | LC_ALL=C sort) > "$root/layout.txt"
(cd "$package" && find . -printf '%y %m %p\n' | LC_ALL=C sort) | cmp "$root/layout.txt" -
sha256sum "$root/payload.sha256" "$root/layout.txt" "$package/tokenforge" \
  "$package/src/TokenForge/lib/net10.0/TokenForge.Credentials.dll" "$package/scripts/Invoke-TokenForge.ps1"
wc -l "$root/payload.sha256"
scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_ROOT="$scratch" \
  DOTNET_BUNDLE_EXTRACT_BASE_DIR="$scratch/bundle" "$package/tokenforge" --version
```

All capability checks used the same extracted package, fresh homes and
isolated network namespaces. The A1, A2 and M3 harnesses cover the qualified
interfaces directly.

```bash
package=/tmp/tokenforge-m4-build/install/0.48.0-5a682d3-linux-x64
for test in PublishedCatalogSearch PublishedCatalogMcp; do
  scratch=$(mktemp -d)
  unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_ROOT="$scratch" \
    DOTNET_BUNDLE_EXTRACT_BASE_DIR="$scratch/bundle" DOTNET_EnableDiagnostics=0 \
    timeout 120s python3 -u "tests/$test.test.py" "$package/tokenforge" || exit 1
done

scratch=$(mktemp -d)
unshare -Urn -- env -i PATH=/usr/bin:/bin HOME="$scratch" DOTNET_ROOT="$scratch" \
  DOTNET_BUNDLE_EXTRACT_BASE_DIR="$scratch/bundle" DOTNET_EnableDiagnostics=0 \
  PSModulePath=/home/paseo/.local/share/powershell/Modules TOKENFORGE_M3_PACKAGE="$package" \
  timeout 120s python3 -u tests/M3TokenHandoff.test.py /home/paseo/.local/bin/pwsh "$package/tokenforge"

git diff --cached --check
```

## Remaining unknowns

Live sign-in, consent, issuance, API acceptance, browser and passkey
behavior, and vault persistence are untested for this package. The
qualification covers Debian 13.8 x64 on the tested host. Other Linux
environments, architectures and operating systems remain unqualified.
Published-archive provenance and independent reproduction remain pending.
Discovery and hosted validation were outside this milestone.
