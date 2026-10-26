[CmdletBinding()]
param([Parameter(Mandatory)][string]$WorkPath,[Parameter(Mandatory)][string]$NativeExecutablePath,[Parameter(Mandatory)][string]$SourceRevision)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicHealth.ps1)
Initialize-TokenForgeHealthRuntime $NativeExecutablePath
$root=New-TokenForgeHealthPrivateDirectory $WorkPath
$fixtures=New-TokenForgeHealthPrivateDirectory (Join-Path $root sources)
$apps=[ordered]@{};$names=[Collections.Generic.List[object]]::new()
$resources=@('10000000-0000-4000-8000-000000000001','10000001-0000-4000-8000-000000000001')
for($i=0;$i -lt 2000;$i++){
    $id='{0:x8}-0000-4000-8000-000000000001' -f $i
    $scopes=[ordered]@{};foreach($resource in $resources){$scopes[$resource]=@(0..24|ForEach-Object {'Fixture.Scope.{0:000}' -f $_})}
    $apps[$id]=[ordered]@{name="Fixture app $i";public_client=$true;foci=$false;redirect_uris=@('https://example.test/callback');preferred_noninteractive_redirurl=$null;preferred_interactive_redirurl=$null;result='ok';scopes=$scopes}
}
for($i=500;$i -lt 5500;$i++){$names.Add([ordered]@{AppId=('{0:x8}-0000-4000-8000-000000000001' -f $i);AppDisplayName="Fixture app $i";AppOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a';Source='Graph'})}
ConvertTo-Json -InputObject ([ordered]@{apps=$apps;resourceidentifiers=[ordered]@{'https://fixture.example.test'=$resources[0]}}) -Depth 100 -Compress|Set-Content (Join-Path $fixtures roadtools.json) -Encoding utf8NoBOM
ConvertTo-Json -InputObject @($names) -Depth 20 -Compress|Set-Content (Join-Path $fixtures microsoftApps.json) -Encoding utf8NoBOM
ConvertTo-Json -InputObject @($resources|ForEach-Object {[ordered]@{resourceId=$_;displayName='Fixture resource'}}) -Depth 20 -Compress|Set-Content (Join-Path $fixtures resources.json) -Encoding utf8NoBOM
$timer=[Diagnostics.Stopwatch]::StartNew()
$exchange=Join-Path $root exchange
$collection=& (Join-Path $PSScriptRoot Invoke-TokenForgePublicHealth.ps1) -OutputPath $exchange -NativeExecutablePath $NativeExecutablePath -SourceRevision $SourceRevision -FixturePath $fixtures|ConvertFrom-Json
$collectionSeconds=$timer.Elapsed.TotalSeconds
$state=Join-Path $root state
$sync=& (Join-Path $PSScriptRoot Sync-TokenForgePublicHealth.ps1) -ExchangePath $exchange -StatePath $state -NativeExecutablePath $NativeExecutablePath
$importSeconds=$timer.Elapsed.TotalSeconds-$collectionSeconds
$start=$timer.Elapsed.TotalSeconds
$repeat=& (Join-Path $PSScriptRoot Sync-TokenForgePublicHealth.ps1) -ExchangePath $exchange -StatePath $state -NativeExecutablePath $NativeExecutablePath
$repeatSeconds=$timer.Elapsed.TotalSeconds-$start
$start=$timer.Elapsed.TotalSeconds
$status=& (Join-Path $PSScriptRoot tokenforge.ps1) health status -StatePath $state -NativeExecutablePath $NativeExecutablePath -Json|ConvertFrom-Json
$statusSeconds=$timer.Elapsed.TotalSeconds-$start
if(-not $collection.CollectionComplete -or $collection.CandidateCount -ne 5502 -or $sync.import -cne 'Complete' -or $repeat.exchangeId -cne $sync.exchangeId -or $status.collection -cne 'Complete' -or $timer.Elapsed.TotalSeconds -gt 300){throw 'Public health realistic fixture acceptance failed.'}
$hashes=[ordered]@{};foreach($file in Get-ChildItem $fixtures){$hashes[$file.Name]=@{sha256=(Get-FileHash $file.FullName).Hash.ToLowerInvariant();bytes=$file.Length}}
[ordered]@{kind='FrozenSyntheticPublicHealthPerformance';fixtureVersion=1;sourceRows=@{roadtools=2000;microsoftApps=5000;resources=2};scopeEdges=100000;catalogCandidates=5502;sourcePayloads=$hashes;metadataBytes=(Get-Item (Join-Path $exchange metadata.json)).Length;collectionSeconds=[Math]::Round($collectionSeconds,3);importSeconds=[Math]::Round($importSeconds,3);repeatSeconds=[Math]::Round($repeatSeconds,3);statusSeconds=[Math]::Round($statusSeconds,3);totalSeconds=[Math]::Round($timer.Elapsed.TotalSeconds,3);maxAllowedSeconds=300;powershellParentPeakWorkingSetBytes=[Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64;passed=$true;liveProof=$false}|ConvertTo-Json -Depth 20
