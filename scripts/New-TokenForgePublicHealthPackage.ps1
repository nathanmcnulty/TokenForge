[CmdletBinding()]
param(
    [Parameter(Mandatory,ParameterSetName='Historical')][string]$BasePackagePath,
    [Parameter(Mandatory,ParameterSetName='Rebuilt')][string]$RebuiltPackagePath,
    [Parameter(Mandatory,ParameterSetName='Rebuilt')][string]$BuildReceiptPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceRevision)

$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicHealth.ps1)
. (Join-Path $PSScriptRoot Copy-TokenForgePackageSource.ps1)
$repo=Split-Path $PSScriptRoot -Parent
$rebuilt=$PSCmdlet.ParameterSetName -ceq 'Rebuilt'
$base=[IO.Path]::GetFullPath($(if($rebuilt){$RebuiltPackagePath}else{$BasePackagePath}))
Assert-TokenForgeHealthPath $base -Directory
if($rebuilt){
    Assert-TokenForgeHealthPath $BuildReceiptPath
    $receiptSha=(Get-FileHash -LiteralPath $BuildReceiptPath).Hash.ToLowerInvariant()
    $baseline=Get-Content -LiteralPath $BuildReceiptPath -Raw|ConvertFrom-Json -AsHashtable
    if($baseline.schemaVersion -ne 1 -or $baseline.kind -cne 'TokenForgePublicHealthExactLinuxBuild' -or $baseline.runtime -cne 'linux-x64' -or $baseline.sdk -cne '10.0.401' -or $baseline.sourceRevision -cnotmatch '^[a-f0-9]{40}$' -or $baseline.sourceRevision -ceq ('0'*40)){throw 'Rebuilt package receipt identity is invalid.'}
    & git -C $repo cat-file -e ($baseline.sourceRevision+'^{commit}') 2>$null
    if($LASTEXITCODE){throw 'Rebuilt package receipt identity is invalid.'}
}else{
    if((Get-FileHash (Join-Path $base local-package-manifest.json)).Hash.ToLowerInvariant() -cne '8295f2508bc95d67c1ce61904cd3a4bba5a7ccac0f8d30af8ef34066eff383c9'){throw 'Base package manifest is not the accepted receipt.'}
    $baseline=Get-Content (Join-Path $base local-package-manifest.json) -Raw|ConvertFrom-Json -AsHashtable
    if($baseline.sourceRevision -cne '0a1704d057417e58b92fd5eac8c546541d3f7ec2'){throw 'Unreviewed base package source.'}
}
$head=(& git -C $repo rev-parse HEAD).Trim()
if($LASTEXITCODE -or $SourceRevision -cne $head){throw 'Package source revision must be the owning HEAD.'}
$scriptNames=@('tokenforge.ps1','Invoke-TokenForgePublicHealth.ps1','Sync-TokenForgePublicHealth.ps1','Test-TokenForgePublicContribution.ps1','TokenForgePublicHealth.ps1','TokenForgePublicHealthSync.ps1')
$sourcePaths=@(& git -C $repo ls-files -- src/TokenForge)+@($scriptNames|ForEach-Object {'scripts/'+$_})+@('docs/public-metadata-health.md')
if($LASTEXITCODE -or $sourcePaths.Count -lt 7){throw 'Source inventory is unavailable.'}
foreach($relative in $sourcePaths){
    $expected=(& git -C $repo rev-parse ($SourceRevision+':'+$relative)).Trim()
    $actual=(& git -C $repo hash-object --no-filters -- (Join-Path $repo $relative)).Trim()
    if($LASTEXITCODE -or $actual -cne $expected){throw 'Package source differs from the declared Git revision.'}
}
$packagingDriverSha256='475ce7f727c264b021acdcc00baeca1a459be0e2c687fddc2fceeb22be7c94b5'
$packagingCopySha256='ddab6812fb9853c0d057131fb785dad5f2bd14436d66dd67fbb08a621a29a4c8'
if($rebuilt){
    # This receipt is local build evidence, not a signature or an authorization.
    # Require the complete tracked compilation/build inventory, never a caller-selected subset.
    $nativePaths=@(& git -C $repo ls-files -- global.json native src/TokenForge/Core scripts/Build-TokenForgeNative.ps1 scripts/Build-TokenForgeCredentials.ps1 scripts/Copy-TokenForgePackageSource.ps1)
    if($LASTEXITCODE -or $nativePaths.Count -lt 100 -or $baseline.nativeInputs -isnot [Collections.IDictionary] -or $baseline.nativeInputs.Count -ne $nativePaths.Count){throw 'Rebuilt native input inventory is incomplete.'}
    foreach($relative in $nativePaths){
        if(-not $baseline.nativeInputs.Contains($relative)){throw 'Rebuilt native input inventory is incomplete.'}
        $path=Join-Path $repo $relative;Assert-TokenForgeHealthPath $path
        $expected=(& git -C $repo rev-parse ($SourceRevision+':'+$relative)).Trim()
        # Compilation identity may precede a script/docs overlay, but every input
        # must be the same literal blob in both locally available commits.
        $built=(& git -C $repo rev-parse ($baseline.sourceRevision+':'+$relative) 2>$null)
        if($LASTEXITCODE -or $built.Trim() -cne $expected){throw 'Rebuilt native inputs differ from the build revision.'}
        $actual=(& git -C $repo hash-object --no-filters -- $path).Trim()
        if($LASTEXITCODE -or $actual -cne $expected -or (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant() -cne $baseline.nativeInputs[$relative]){throw 'Rebuilt native inputs differ from the owning revision.'}
    }
    if($baseline.files -isnot [Collections.IDictionary] -or $baseline.files.Count -lt 2){throw 'Rebuilt package file inventory is incomplete.'}
    $actualFiles=@(Get-ChildItem -LiteralPath $base -Recurse -Force|ForEach-Object {
        Assert-TokenForgeHealthPath $_.FullName -Directory:$_.PSIsContainer
        if(-not $_.PSIsContainer){[IO.Path]::GetRelativePath($base,$_.FullName)}
    })
    if($actualFiles.Count -ne $baseline.files.Count){throw 'Rebuilt package file inventory differs.'}
    foreach($relative in $actualFiles){
        if(-not $baseline.files.Contains($relative) -or $baseline.files[$relative] -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath (Join-Path $base $relative)).Hash.ToLowerInvariant() -cne $baseline.files[$relative]){throw 'Rebuilt package bytes changed.'}
        if($relative -cin @('tokenforge','src/TokenForge/lib/net10.0/TokenForge.Credentials.dll')){continue}
        # A receipt cannot authorize arbitrary additional package data. Every other
        # file must be an exact tracked source artifact under the build driver's layout.
        $sourceRelative=if($relative -ceq 'README.md'){'docs/native-cli.md'}elseif($relative.StartsWith('examples/',[StringComparison]::Ordinal)){'docs/'+$relative}elseif($relative.StartsWith('src/TokenForge/',[StringComparison]::Ordinal) -or $relative.StartsWith('scripts/',[StringComparison]::Ordinal) -or $relative -ceq 'THIRD-PARTY-NOTICES.md'){$relative}elseif($relative -cnotmatch '/'){ 'docs/'+$relative }else{throw 'Unexpected rebuilt package file.'}
        $expected=(& git -C $repo rev-parse ($SourceRevision+':'+$sourceRelative) 2>$null)
        if($LASTEXITCODE){throw 'Rebuilt package file is not a tracked source artifact.'}
        $actual=(& git -C $repo hash-object --no-filters -- (Join-Path $base $relative)).Trim()
        if($LASTEXITCODE -or $actual -cne $expected.Trim()){throw 'Rebuilt package source bytes differ from the owning revision.'}
    }
    # The reviewed fixed binary pins are independent of a caller-provided receipt.
    Initialize-TokenForgeHealthRuntime (Join-Path $base tokenforge)
}else{
    foreach($entry in $baseline.nativeInputs.GetEnumerator()){
        $actual=(Get-FileHash (Join-Path $repo $entry.Key)).Hash.ToLowerInvariant()
        # Historical overlay is valid only for these exact packaging-only deltas.
        $expected=if($entry.Key -ceq 'scripts/Build-TokenForgeNative.ps1'){$packagingDriverSha256}elseif($entry.Key -ceq 'scripts/Copy-TokenForgePackageSource.ps1'){$packagingCopySha256}else{$entry.Value}
        if($actual -cne $expected){throw 'Native compilation inputs changed; rebuild and review required.'}
    }
    Initialize-TokenForgeHealthRuntime (Join-Path $base tokenforge)
}
$root=New-TokenForgeHealthPrivateDirectory $OutputPath
$stage=New-TokenForgeHealthPrivateDirectory (Join-Path $root linux-x64)
foreach($name in $baseline.files.Keys){
    $source=Join-Path $base $name;Assert-TokenForgeHealthPath $source
    if((Get-FileHash $source).Hash.ToLowerInvariant() -cne $baseline.files[$name]){throw 'Base package bytes changed.'}
    $dest=Join-Path $stage $name;$null=[IO.Directory]::CreateDirectory((Split-Path $dest -Parent),[IO.UnixFileMode]448)
    Copy-Item -LiteralPath $source -Destination $dest
}
# Overlay tracked current PowerShell source only. All compiled inputs and rebuilt
# bytes (or historical accepted baseline) were checked before creating output.
$dllBytes=[IO.File]::ReadAllBytes((Join-Path $stage src/TokenForge/lib/net10.0/TokenForge.Credentials.dll))
# Discard only this task-created staging module, so removed source cannot survive an overlay.
Remove-Item -LiteralPath (Join-Path $stage src/TokenForge) -Recurse -Force
Copy-TokenForgePackageSource -SourceRoot $repo -DestinationRoot $stage -Prefix src/TokenForge
$null=[IO.Directory]::CreateDirectory((Join-Path $stage src/TokenForge/lib/net10.0),[IO.UnixFileMode]448)
[IO.File]::WriteAllBytes((Join-Path $stage src/TokenForge/lib/net10.0/TokenForge.Credentials.dll),$dllBytes)
$null=[IO.Directory]::CreateDirectory((Join-Path $stage scripts),[IO.UnixFileMode]448)
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
$provenance=[ordered]@{nativeSource=$baseline.sourceRevision;nativeInputsVerified=$baseline.nativeInputs.Count}
if($rebuilt){$provenance.buildReceiptSha256=$receiptSha;$provenance.nativeBuild='RebuiltExactSource';$provenance.sdk=$baseline.sdk}
else{$provenance.unchangedBaselineInputs=$baseline.nativeInputs.Count-2;$provenance.reviewedPackagingDriverSha256=$packagingDriverSha256;$provenance.reviewedPackagingCopySha256=$packagingCopySha256}
$manifest=[ordered]@{schemaVersion=1;kind='TokenForgePublicHealthLinuxPackage';sourceRevision=$SourceRevision;files=$files;operationalPublication=$false}
foreach($key in $provenance.Keys){$manifest[$key]=$provenance[$key]}
$manifest|ConvertTo-Json -Depth 20|Set-Content (Join-Path $stage public-health-package.json) -Encoding utf8NoBOM
[IO.File]::SetUnixFileMode((Join-Path $stage public-health-package.json),[IO.UnixFileMode]384)
$archive=Join-Path $root TokenForge-public-health-linux-x64.tar.gz
& tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -czf $archive -C $stage .
if($LASTEXITCODE){throw 'Local package archive failed.'}
[IO.File]::SetUnixFileMode($archive,[IO.UnixFileMode]384)
$result=[ordered]@{sourceRevision=$SourceRevision;payloadFiles=$files.Count+1;sha256=(Get-FileHash $archive).Hash.ToLowerInvariant();bytes=(Get-Item $archive).Length;published=$false}
foreach($key in $provenance.Keys){$result[$key]=$provenance[$key]}
$result|ConvertTo-Json
