# M4 Windows x64 distribution qualification

[Tracking issue #179](https://github.com/nathanmcnulty/TokenForge/issues/179)

On 2026-11-28 UTC, the local Windows x64 candidate was built from
`fe3937669ec0dc06bd6df203e57e4b645335015a`, fetched from `origin/main`
after the [Linux reproduction](m4-linux-x64-reproduction.md) merged.
The registered local Windows VM reported OS architecture `X64`, process
architecture `AMD64`, and Windows build `10.0.26300.9974` before the build.
Git for Windows 2.56.1 used `core.autocrlf=true` for this checkout.

## Inputs

The build used .NET SDK 10.0.401 and PowerShell 7.7.0. Validation used
Python 3.13.9 x64 and Pester 6.2.0. The
[Microsoft SDK metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json)
lists SHA-512 `24b670ad3d923bfcf47df6c3b034152398b42f6dbc388e10d783aee1cfb5e5817d399fc0ae2a12cfa822a55e61d34830ccb15c50ef6efee437ab874bb7c79430`
for the SDK ZIP. The [Python embed ZIP](https://www.python.org/downloads/release/python-3139/)
had SHA-256 `91d828c2da3a029b41699e918674a0cb379c02cf20dab9c501306885f837402a`.

The catalog came from local Git objects at
`ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62`. Git emitted the catalog files
directly, so Windows checkout newline conversion did not change them.

| Input | SHA-256 |
| --- | --- |
| `applications.json` | `93cb678c13bf22906f8544dbdd3bf3795dc705cdb6af07b01225361a653ac0e2` |
| `applications.non-verified.json` | `fb58d4bb0e4647257bdf6945218ed88be89fc4ef59750e0a2c732229c2be516a` |
| `applications.verified-evidence.json` | `21b61c704b95703cce8dbed0922ea7de5bb06491eef99f36b5af225c8ecf33d0` |
| `tests/fixtures/a2-catalog-mcp.json` (Windows checkout) | `4351c05c6246fa2f19aebf76d883e79d3dc9a9ee22b7fc0ccd40fb62efc93c33` |

The SDK selected .NET 10.0.12 packs. The locked restore used NuGet.org
and a fresh package cache. The projected locks retained only `net10.0`
and `net10.0/win-x64`, with the original dependency records and content
hashes for those targets.

| Restore input | SHA-256 |
| --- | --- |
| Projected CLI lock | `69b9330d558920213f99116918a1d70b0ab31023132cae6d0aa1bba958059146` |
| Projected Core lock | `cac82d7e8a73b7aa12cabf09cf681138ef9edb5ce9331e84a7e3b4ef5de6492e` |
| Projected Credentials lock | `315cf3c6e41a1a09c3d23ed051d460cfcc88c06d92fce353b1145946c3e904b7` |
| `microsoft.aspnetcore.app.runtime.win-x64.10.0.12.nupkg` | `59025d88c8f5178e8569f91c7cbc56ad3ead3d83a777477d17fade3f9cdd8103` |
| `microsoft.data.sqlite.10.0.12.nupkg` | `246679d8c6c83ffcf4c8a480066e3f4fc4e051c96b71bedfd932fe7a5af1f7d4` |
| `microsoft.data.sqlite.core.10.0.12.nupkg` | `5e8ed353006dadf55d5c7f56d237321c20bb10c786262e6b25526756e1036332` |
| `microsoft.net.illink.tasks.10.0.12.nupkg` | `37aa984da51fdc01cc7d57a8647893392f3539cdd5a1d32ce4982be5309bc08b` |
| `microsoft.netcore.app.runtime.win-x64.10.0.12.nupkg` | `0f63dee7ca4383cb16848966f81e439399e2058e1671ebe27e5eaf4b200e8691` |
| `microsoft.windowsdesktop.app.runtime.win-x64.10.0.12.nupkg` | `68bce56d2402969d82ac77fbd2b2a54f55fda86ea060366e6ddb832353dab80a` |
| `sqlitepclraw.bundle_e_sqlite3.2.1.12.nupkg` | `a9a06e6b5a313f6ef3675f91997d012adeffe8aa9e1ffd69ed46a4e685b054e1` |
| `sqlitepclraw.core.2.1.12.nupkg` | `af06904138ffa6dc95a599133d64d254716d6facc7543a6b3b910793dae9dca5` |
| `sqlitepclraw.lib.e_sqlite3.2.1.12.nupkg` | `4a22c02ffcf489792903cf263def9fce27739716883f965f0b5eeff1637430ac` |
| `sqlitepclraw.provider.e_sqlite3.2.1.12.nupkg` | `df2b3271992e5d719186c4671e3cf4f8658097c154cbdc41494ab594c5997595` |

## Installed package

The ZIP and complete payload manifest are retained under
`%LOCALAPPDATA%\TokenForge-M4-fe39376` on the Windows host. A fresh
extraction matched all 176 staged file paths and SHA-256 digests. The
installed executable's PE machine identifier was `0x8664` (AMD64).

| Item | SHA-256 |
| --- | --- |
| `TokenForge-0.48.0-fe39376-win-x64.zip` | `ff80fb05c367321afa71df8cbeeb6ef41acf1ad86d02f1c9773f74cfeaaa94e1` |
| Complete `payload.sha256` file | `616146101a38a8f8f3f4b555774d62c1673f920e91841187762a5f1558c81d46` |
| `tokenforge.exe` | `b1102c5478cd64bccef8e520f279c859173d81d5a9cac0f385d0f9c09cd55b76` |
| `src/TokenForge/lib/net10.0/TokenForge.Credentials.dll` | `cc75fb332d023382aa3a0f7df2255db3808c83609764165e9bc1b36996902524` |
| `scripts/Invoke-TokenForge.ps1` | `2794baf90de4037590f1006492bc499eb6d12f2b7d8abe07a1547a7e310c69f7` |

## Capability results

| Capability | Observed result | Remaining unknowns |
| --- | --- | --- |
| Clean installation | Pass. A new directory matched all 176 payload entries. The installed native CLI reported 0.48.0 with an empty runtime root in 31.11 seconds. | Installer integration, signing, published provenance and independent rebuild identity. |
| Offline catalog CLI | Pass in 47.75 seconds. The fixture returned 2,066 verified IDs, 5,500 combined and 3,434 with unknown tenancy. Exact detail, provenance, explicit false versus absent or null tenancy, stable JSON, audience, conflicts, misses and scope isolation passed. | Other catalog revisions and live refresh behavior. |
| MCP stdio startup | Pass. A fresh client negotiated protocol `2025-11-25` and listed `search_applications` and `get_application`. | Other MCP client implementations and transports. |
| CLI/MCP evidence parity | Pass. The A2 run took 39.81 seconds including startup. Full results and catalog revision matched across 21 verified pages, 55 combined pages, a filtered match and miss, and four exact lookups. Default and past-end pagination passed. MCP rejected all 18 invalid catalog calls. | Catalogs and query shapes outside the fixture. |
| Operator-run M3 handoff | Pass against mocked identity responses. Pester 6.2.0 passed all four cases with zero failures or skips. The retry took 68.24 seconds including MCP. The installed script loaded the installed credential DLL, selected the explicitly configured client despite a second eligible client, and asserted `prompt=none`. | Live sign-in, consent, issuance, API acceptance, browser and passkey flows, and vault persistence. |

- **Success** verified the issued access and refresh `SecureString` values
  inside the local PowerShell process and disposed both there.
- **Missing scopes** and **wrong audience** each produced zero token objects.
- **Required interaction** produced zero token objects, retained only the
  identity response's numeric `AADSTS50076` code, and stopped before final
  redemption.

Both MCP response representations matched the credential-free plan. The
planning tool appeared only with an explicitly configured client. MCP
rejected 11 invalid calls including access and refresh token fields, and
the error responses omitted the synthetic credential values. MCP exited
before the separate PowerShell CLI ran the handoff, so no token result
crossed back into MCP. The handoff used no vault. Failure diagnostics
excluded the synthetic credentials and private identity details.

The capability checks used fresh scratch directories and local Git objects.
The test environment pointed HTTP(S) at a loopback proxy endpoint and verified
the .NET default proxy selection for the identity URL. OS-level network
isolation remains unverified.

The original M3 run reached the MCP plan and then failed all four PowerShell
cases at the module import mock. The fixture accepted only forward slashes.
The test change accompanying this receipt normalizes the path separators in
that filter. The Windows copy of the corrected test had SHA-256
`e4c551cdc23304e45ace317ea8a234eb53cbc5d2c189343c2ab2e53173c7dbdb`.
The retry used the original installed package and catalog inputs.

These results apply to the exact local candidate and tested Windows build.
Other Windows versions, OS/architecture combinations and live authorization
remain outside this receipt. The [release support declaration](native-releases.md)
tracks the Linux x64 release candidate.

## Reproduction commands

Fetch `origin/main` and create a fresh worktree for the receipt.

```sh
git fetch origin main
git worktree add -b milestone-m4-windows .m4-windows-worktree origin/main
```

On the local Windows x64 host, run the following in PowerShell 7.7.0
with Git for Windows and Pester 6.2.0 available. The clone, SDK and Python
downloads, and NuGet restore are the online staging steps.

```powershell
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$true
$r=Join-Path $env:LOCALAPPDATA 'TokenForge-M4-fe39376'
New-Item -ItemType Directory $r | Out-Null
Set-Location $r
git -c credential.helper= clone --no-checkout https://github.com/nathanmcnulty/TokenForge.git source
git -C source worktree add --detach candidate fe3937669ec0dc06bd6df203e57e4b645335015a
curl.exe -fsSL https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.401/dotnet-sdk-10.0.401-win-x64.zip -o sdk.zip
curl.exe -fsSL --max-time 90 https://www.python.org/ftp/python/3.13.9/python-3.13.9-embed-amd64.zip -o python.zip
Expand-Archive python.zip python
(Get-FileHash python.zip).Hash
& "$r/python/python.exe" --version
$sdkHash=(Get-FileHash sdk.zip -Algorithm SHA512).Hash.ToLowerInvariant()
if($sdkHash -ne '24b670ad3d923bfcf47df6c3b034152398b42f6dbc388e10d783aee1cfb5e5817d399fc0ae2a12cfa822a55e61d34830ccb15c50ef6efee437ab874bb7c79430'){throw 'SDK checksum mismatch'}
[IO.Compression.ZipFile]::ExtractToDirectory("$r/sdk.zip","$r/sdk-verified")
$dotnet="$r/sdk-verified/dotnet.exe"
$env:DOTNET_CLI_HOME="$r/dotnet-home"
$env:NUGET_PACKAGES="$r/nuget"
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_NOLOGO='1'
Set-Location "$r/source/candidate"
git --version
git config --get core.autocrlf
git rev-parse HEAD
$catalog='ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62'
foreach($f in 'applications.json','applications.non-verified.json','applications.verified-evidence.json'){
  cmd /c "git --no-replace-objects show ${catalog}:$f > `"$r/$f`""
  Get-FileHash "$r/$f" | Format-List Hash,Path
}
Get-FileHash tests/fixtures/a2-catalog-mcp.json | Format-List Hash,Path
& $dotnet --info
foreach($project in 'Cli','Core','Credentials'){
  $path="native/TokenForge.$project"
  New-Item -ItemType Directory "$path/obj" -Force | Out-Null
  $lock=Get-Content "$path/packages.lock.json" -Raw | ConvertFrom-Json -AsHashtable
  foreach($key in @($lock.dependencies.Keys)){
    if($key -notin 'net10.0','net10.0/win-x64'){ $lock.dependencies.Remove($key) }
  }
  $lock | ConvertTo-Json -Depth 100 | Set-Content "$path/obj/m4-win-x64.packages.lock.json"
  Get-FileHash "$path/obj/m4-win-x64.packages.lock.json" | Format-List Hash,Path
}
& $dotnet restore native/TokenForge.Cli -r win-x64 --locked-mode --source https://api.nuget.org/v3/index.json -p:RuntimeIdentifiers=win-x64 -p:SelfContained=true -p:NuGetAudit=false -p:NuGetLockFilePath=obj/m4-win-x64.packages.lock.json
Get-ChildItem "$r/nuget" -Filter *.nupkg -Recurse | Sort-Object Name |
  ForEach-Object { "$((Get-FileHash $_.FullName).Hash) $($_.Name)" }
& ./scripts/Build-TokenForgeNative.ps1 -Runtime win-x64 -OutputPath "$r/build" -Dotnet $dotnet -NoRestore | Format-List
'DONE-BUILD'
```

Create the local ZIP and verify it before installation into a new directory.

```powershell
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$true
$r=Join-Path $env:LOCALAPPDATA 'TokenForge-M4-fe39376'
Set-Location "$r/source/candidate"
$stage="$r/build/win-x64"
$package="$r/install/0.48.0-fe39376-win-x64"
$archive="$r/TokenForge-0.48.0-fe39376-win-x64.zip"
function Get-Payload($path){
  Get-ChildItem -LiteralPath $path -File -Recurse -Force |
    Sort-Object FullName -CaseSensitive |
    ForEach-Object {
      $name=[IO.Path]::GetRelativePath($path,$_.FullName).Replace('\','/')
      '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant(),$name
    }
}
Get-Payload $stage | Set-Content "$r/payload.sha256"
[IO.Compression.ZipFile]::CreateFromDirectory($stage,$archive)
$archiveHash=(Get-FileHash $archive).Hash
$archiveHash | Set-Content "$r/archive.sha256"
if((Get-FileHash $archive).Hash -ne (Get-Content "$r/archive.sha256")){throw 'archive mismatch'}
if(Test-Path $package){throw 'install destination already exists'}
Expand-Archive $archive $package
$expected=Get-Content "$r/payload.sha256"
$actual=Get-Payload $package
if(($expected -join "`n") -cne ($actual -join "`n")){throw 'payload mismatch'}
"Files: $($actual.Count)"
Get-FileHash $archive,"$r/payload.sha256","$package/tokenforge.exe","$package/src/TokenForge/lib/net10.0/TokenForge.Credentials.dll","$package/scripts/Invoke-TokenForge.ps1" | Format-List Hash,Path
$exe="$package/tokenforge.exe"
$pe=[IO.File]::ReadAllBytes($exe)
$machine=[BitConverter]::ToUInt16($pe,[BitConverter]::ToInt32($pe,60)+4)
if($machine -ne 0x8664){throw "unexpected PE machine $machine"}
'PE machine: 0x{0:x4}' -f $machine
'DONE-INSTALL'
```

Run the capability checks from a fresh PowerShell process.

```powershell
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$true
$r=Join-Path $env:LOCALAPPDATA 'TokenForge-M4-fe39376'
Set-Location "$r/source/candidate"
$package="$r/install/0.48.0-fe39376-win-x64"
$exe="$package/tokenforge.exe"
$python="$r/python/python.exe"
$pwsh=(Get-Command pwsh.exe -CommandType Application | Select-Object -First 1).Source
$pester=Get-Module -ListAvailable Pester | Where-Object Version -eq '6.2.0' | Select-Object -First 1
if(!$pester){throw 'Pester 6.2.0 missing'}
$env:PSModulePath=Split-Path (Split-Path $pester.ModuleBase)
$env:Path="$env:SystemRoot/System32;C:/Program Files/Git/cmd"
$env:DOTNET_EnableDiagnostics='0'
$env:GIT_NO_LAZY_FETCH='1'
$env:GIT_ALLOW_PROTOCOL=''
$env:HTTP_PROXY='http://127.0.0.1:1'
$env:HTTPS_PROXY=$env:HTTP_PROXY
$env:ALL_PROXY=$env:HTTP_PROXY
Remove-Item Env:NO_PROXY -ErrorAction SilentlyContinue
$proxyTarget=[uri]'https://login.microsoftonline.com/'
if([Net.Http.HttpClient]::DefaultProxy.IsBypassed($proxyTarget) -or
   [Net.Http.HttpClient]::DefaultProxy.GetProxy($proxyTarget).AbsoluteUri -ne 'http://127.0.0.1:1/'){
  throw 'Offline proxy unavailable'
}
$env:TOKENFORGE_M3_PACKAGE=$package
Start-Transcript -Path "$r/validation.txt" | Out-Null
try {
  foreach($check in 'version','PublishedCatalogSearch','PublishedCatalogMcp','M3TokenHandoff'){
    $scratch=Join-Path $r ("check-"+[guid]::NewGuid())
    New-Item -ItemType Directory $scratch | Out-Null
    $env:HOME=$env:USERPROFILE=$env:DOTNET_ROOT=$env:TEMP=$env:TMP=$scratch
    $env:DOTNET_BUNDLE_EXTRACT_BASE_DIR="$scratch/bundle"
    $timer=[Diagnostics.Stopwatch]::StartNew()
    switch($check){
      version { & $exe --version }
      M3TokenHandoff { & $python -u "tests/$check.test.py" $pwsh $exe }
      default { & $python -u "tests/$check.test.py" $exe }
    }
    "$check completed in $([math]::Round($timer.Elapsed.TotalSeconds,2)) seconds"
  }
  'DONE-TEST'
} finally { Stop-Transcript | Out-Null }
```

To reproduce the M3 retry from the pinned source, apply the test-only change
before running the validation block with only `'M3TokenHandoff'` in the
`foreach` list and `"$r/validation-m3.txt"` as the transcript path.

```powershell
$ErrorActionPreference='Stop'
$r=Join-Path $env:LOCALAPPDATA 'TokenForge-M4-fe39376'
Set-Location "$r/source/candidate"
$test=Join-Path (Get-Location).Path 'tests/M3TokenHandoff.Tests.ps1'
$before=[IO.File]::ReadAllText($test)
$after=$before.Replace('$Name -like', '($Name -replace ''\\'',''/'') -like')
if($before -ceq $after){throw 'Mock filter did not change'}
[IO.File]::WriteAllText($test,$after)
git diff --check
if($LASTEXITCODE){throw 'git diff check'}
git diff -- tests/M3TokenHandoff.Tests.ps1
Get-FileHash $test | Format-List Hash,Path
```
