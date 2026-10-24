[CmdletBinding()]
param([Parameter(Mandatory)][string]$BasePackagePath,[Parameter(Mandatory)][string]$OutputPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceRevision)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicHealth.ps1)
. (Join-Path $PSScriptRoot Copy-TokenForgePackageSource.ps1)
$base=[IO.Path]::GetFullPath($BasePackagePath)
Initialize-TokenForgeHealthRuntime (Join-Path $base tokenforge)
if((Get-FileHash (Join-Path $base local-package-manifest.json)).Hash.ToLowerInvariant() -cne '8295f2508bc95d67c1ce61904cd3a4bba5a7ccac0f8d30af8ef34066eff383c9'){throw 'Base package manifest is not the accepted receipt.'}
$baseline=Get-Content (Join-Path $base local-package-manifest.json) -Raw|ConvertFrom-Json -AsHashtable
if($baseline.sourceRevision -cne '0a1704d057417e58b92fd5eac8c546541d3f7ec2'){throw 'Unreviewed base package source.'}
$repo=Split-Path $PSScriptRoot -Parent
$head=(& git -C $repo rev-parse HEAD).Trim()
if($LASTEXITCODE -or $SourceRevision -cne $head){throw 'Package source revision must be the owning HEAD.'}
$scriptNames=@('tokenforge.ps1','Invoke-TokenForgePublicHealth.ps1','Sync-TokenForgePublicHealth.ps1','Test-TokenForgePublicContribution.ps1','TokenForgePublicHealth.ps1','TokenForgePublicHealthSync.ps1')
$sourcePaths=@(& git -C $repo ls-files -- src/TokenForge)+@($scriptNames|ForEach-Object {'scripts/'+$_})
if($LASTEXITCODE -or $sourcePaths.Count -lt 7){throw 'Source inventory is unavailable.'}
foreach($relative in $sourcePaths){
    $expected=(& git -C $repo rev-parse ($SourceRevision+':'+$relative)).Trim()
    $actual=(& git -C $repo hash-object --no-filters -- (Join-Path $repo $relative)).Trim()
    if($LASTEXITCODE -or $actual -cne $expected){throw 'Package source differs from the declared Git revision.'}
}
$packagingDriverSha256='475ce7f727c264b021acdcc00baeca1a459be0e2c687fddc2fceeb22be7c94b5'
foreach($entry in $baseline.nativeInputs.GetEnumerator()){
    $actual=(Get-FileHash (Join-Path $repo $entry.Key)).Hash.ToLowerInvariant()
    # This exact reviewed driver delta only adds the five PowerShell health files
    # to the package copy list; its compilation invocation is unchanged. All other
    # baseline inputs, including C# sources, projects and dependency locks, match.
    $expected=if($entry.Key -ceq 'scripts/Build-TokenForgeNative.ps1'){$packagingDriverSha256}else{$entry.Value}
    if($actual -cne $expected){throw 'Native compilation inputs changed; rebuild and review required.'}
}
$root=New-TokenForgeHealthPrivateDirectory $OutputPath
$stage=New-TokenForgeHealthPrivateDirectory (Join-Path $root linux-x64)
foreach($name in $baseline.files.Keys){
    $source=Join-Path $base $name;Assert-TokenForgeHealthPath $source
    if((Get-FileHash $source).Hash.ToLowerInvariant() -cne $baseline.files[$name]){throw 'Base package bytes changed.'}
    $dest=Join-Path $stage $name;$null=[IO.Directory]::CreateDirectory((Split-Path $dest -Parent),[IO.UnixFileMode]448)
    Copy-Item -LiteralPath $source -Destination $dest
}
# Overlay tracked current PowerShell source only. All compiled inputs were checked
# above; no native build/install or dependency download occurs.
$dllBytes=[IO.File]::ReadAllBytes((Join-Path $stage src/TokenForge/lib/net8.0/TokenForge.Credentials.dll))
# Discard only this task-created staging module, so removed source cannot survive an overlay.
Remove-Item -LiteralPath (Join-Path $stage src/TokenForge) -Recurse -Force
Copy-TokenForgePackageSource -SourceRoot $repo -DestinationRoot $stage -Prefix src/TokenForge
$null=[IO.Directory]::CreateDirectory((Join-Path $stage src/TokenForge/lib/net8.0),[IO.UnixFileMode]448)
[IO.File]::WriteAllBytes((Join-Path $stage src/TokenForge/lib/net8.0/TokenForge.Credentials.dll),$dllBytes)
foreach($name in $scriptNames){Copy-Item (Join-Path $PSScriptRoot $name) (Join-Path $stage scripts/$name)}
$null=[IO.Directory]::CreateDirectory((Join-Path $stage docs),[IO.UnixFileMode]448)
Copy-Item (Join-Path $repo docs/public-metadata-health.md) (Join-Path $stage docs/public-metadata-health.md)
$files=[ordered]@{}
foreach($item in Get-ChildItem $stage -Recurse -Force){
    if($item.PSIsContainer){[IO.File]::SetUnixFileMode($item.FullName,[IO.UnixFileMode]448);continue}
    Assert-TokenForgeHealthPath $item.FullName
    $relative=[IO.Path]::GetRelativePath($stage,$item.FullName)
    [IO.File]::SetUnixFileMode($item.FullName,([IO.UnixFileMode]$(if($relative -ceq 'tokenforge'){448}else{384})))
    $files[$relative]=@{sha256=(Get-FileHash $item.FullName).Hash.ToLowerInvariant();bytes=$item.Length}
}
@{schemaVersion=1;kind='TokenForgePublicHealthLinuxPackage';sourceRevision=$SourceRevision;nativeSource=$baseline.sourceRevision;nativeInputsVerified=$baseline.nativeInputs.Count;unchangedBaselineInputs=($baseline.nativeInputs.Count-1);reviewedPackagingDriverSha256=$packagingDriverSha256;files=$files;operationalPublication=$false}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $stage public-health-package.json) -Encoding utf8NoBOM
[IO.File]::SetUnixFileMode((Join-Path $stage public-health-package.json),[IO.UnixFileMode]384)
$archive=Join-Path $root TokenForge-public-health-linux-x64.tar.gz
& tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -czf $archive -C $stage .
if($LASTEXITCODE){throw 'Local package archive failed.'}
[IO.File]::SetUnixFileMode($archive,[IO.UnixFileMode]384)
@{sourceRevision=$SourceRevision;nativeSource=$baseline.sourceRevision;nativeInputsVerified=$baseline.nativeInputs.Count;unchangedBaselineInputs=($baseline.nativeInputs.Count-1);reviewedPackagingDriverSha256=$packagingDriverSha256;payloadFiles=$files.Count+1;sha256=(Get-FileHash $archive).Hash.ToLowerInvariant();bytes=(Get-Item $archive).Length;published=$false}|ConvertTo-Json
