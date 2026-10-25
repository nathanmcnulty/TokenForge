[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][string]$NativeExecutablePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceRevision,
    [string]$FixturePath,[string]$PreviousExchangePath,[string]$ContextPath,
    [ValidateRange(0.01,600)][double]$MaxSeconds=600
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TokenForgePublicHealth.ps1')
Initialize-TokenForgeHealthRuntime $NativeExecutablePath
$previous=if($PreviousExchangePath){Read-TokenForgeHealthExchange $PreviousExchangePath}else{$null}
$context=if($ContextPath){Read-TokenForgeHealthJson (Read-TokenForgeHealthBytes $ContextPath 8192)}else{$null}
Assert-TokenForgeHealthContext $context $SourceRevision
if($FixturePath){Assert-TokenForgeHealthPath $FixturePath -Directory;if($context){throw 'Fixture data cannot claim hosted provenance.'}}
$output=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $output){throw 'Exchange output is immutable; choose a new path.'}
$stage=New-TokenForgeHealthPrivateDirectory (Join-Path (Split-Path $output -Parent) ('.health-'+[guid]::NewGuid().ToString('N')))
$budget=New-TokenForgeHealthBudget -MaxSeconds $MaxSeconds
$now=[DateTimeOffset]::UtcNow.ToString('o');$rows=[Collections.Generic.List[object]]::new();$data=@{}
try{
    foreach($name in $script:HealthSources.Keys){
        $old=if($previous){@($previous.Health.sources|Where-Object name -CEQ $name)[0]}else{$null}
        $row=[ordered]@{name=$name;uri=$script:HealthSources[$name];status='Unavailable';attempts=0;lastSuccessAt=if($old){$old.lastSuccessAt}else{$null};sha256=if($old){$old.sha256}else{$null};candidateCount=if($old){$old.candidateCount}else{0};changed=$false}
        for($attempt=0;$attempt -lt 2;$attempt++){
            try{
                Assert-TokenForgeHealthBudget $budget;$row.attempts++
                if($FixturePath){$bytes=Read-TokenForgeHealthBytes (Join-Path $FixturePath ($name+'.json')) $script:HealthLimits.SourceBytes}
                else{
                    $reply=Invoke-TokenForgeHealthGet -Uri $script:HealthSources[$name] -MaxBytes $script:HealthLimits.SourceBytes -Budget $budget -AllowedHosts @('raw.githubusercontent.com')
                    if($reply.StatusCode -ne 200){if($reply.StatusCode -notin @(408,429,500,502,503,504)){$attempt=2};throw 'Source unavailable.'};$bytes=$reply.Bytes
                }
            }catch{continue}
            try{
                $parsed=Read-TokenForgeHealthJson $bytes
                $count=Assert-TokenForgeHealthSource $name $parsed
                $sha=Get-TokenForgeHealthHash $bytes
                $row.status='Success';$row.lastSuccessAt=$now;$row.sha256=$sha;$row.candidateCount=$count;$row.changed=(-not $old -or $old.sha256 -cne $sha);$data[$name]=$parsed
            }catch{if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw};$row.status='Invalid'}
            break # Schema errors are not transient; never retry malicious data.
        }
        if($row.status -ceq 'Success'){
            $projection=Invoke-TokenForgeHealthProjection -Data @{$name=$data[$name]} -CatalogPath (Join-Path $stage catalog.tmp) -Now $now
            if(-not $projection.Valid){$row.status='Invalid';$row.lastSuccessAt=if($old){$old.lastSuccessAt}else{$null};$row.sha256=if($old){$old.sha256}else{$null};$row.candidateCount=if($old){$old.candidateCount}else{0};$row.changed=$false;$data.Remove($name)}
        }
        $rows.Add($row)
    }
    $complete=@($rows|Where-Object status -CNE Success).Count -eq 0
    $discovery=$null
    if($complete){
        $projection=Invoke-TokenForgeHealthProjection -Data $data -CatalogPath (Join-Path $stage catalog.tmp) -Now $now
        if($projection.Valid){$discovery=$projection.Discovery}else{
            $complete=$false
            # The combination exceeded the claim contract. No source can claim
            # acceptance for this attempted complete snapshot.
            foreach($row in $rows){
                $old=if($previous){@($previous.Health.sources|Where-Object name -CEQ $row.name)[0]}else{$null}
                $row.status='Invalid';$row.lastSuccessAt=if($old){$old.lastSuccessAt}else{$null};$row.sha256=if($old){$old.sha256}else{$null};$row.candidateCount=if($old){$old.candidateCount}else{0};$row.changed=$false
            }
        }
    }
    $metadata=Join-Path $stage metadata.json
    if($previous){[IO.File]::WriteAllBytes($metadata,(Read-TokenForgeHealthBytes $previous.MetadataPath $script:HealthLimits.MetadataBytes))}
    else{
        $empty=[ordered]@{Format='TokenForgeApplicationMetadata';SchemaVersion=2;CreatedAt=$now;UpdatedAt=$now;Applications=@{};Origins=@{};Runs=@()}
        $empty|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $metadata -Encoding utf8NoBOM
    }
    $candidateCount=if($previous){$previous.Health.candidateCount}else{0};$conflictCount=if($previous){$previous.Health.conflictCount}else{0}
    if($complete){
        $discovery.FetchedAt=$now
        $discovery.SourceSnapshots=@($rows|ForEach-Object {[pscustomobject]@{Location=$_.uri;Sha256=$_.sha256;HashKind='RawPublicSource'}})
        $null=Update-TokenForgeApplicationMetadata -Path $metadata -Document $discovery -Kind Discovery
        # JSON writer lock belongs only to this private, completed staging write.
        if(Test-Path -LiteralPath ($metadata+'.lock')){Remove-Item -LiteralPath ($metadata+'.lock')}
        $candidateCount=$discovery.Applications.Count;$conflictCount=@($discovery.Applications|Where-Object {$_.MetadataConflicts.Count -gt 0}).Count
    }
    Assert-TokenForgeHealthBudget $budget
    $health=[ordered]@{schemaVersion=1;kind='TokenForgePublicHealth';collectedAt=$now;lastCompleteAt=if($complete){$now}elseif($previous){$previous.Health.lastCompleteAt}else{$null};complete=$complete;candidateCount=$candidateCount;conflictCount=$conflictCount;sources=@($rows)}
    $health|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $stage health.json) -Encoding utf8NoBOM
    $files=[ordered]@{}
    foreach($name in @('health.json','metadata.json')){$bytes=Read-TokenForgeHealthBytes (Join-Path $stage $name) $(if($name -eq 'health.json'){$script:HealthLimits.HealthBytes}else{$script:HealthLimits.MetadataBytes});$files[$name]=@{sha256=Get-TokenForgeHealthHash $bytes;bytes=$bytes.Length}}
    $manifest=[ordered]@{schemaVersion=1;kind='TokenForgePublicHealthExchange';collectedAt=$now;sourceRevision=$SourceRevision;context=$context;files=$files}
    $manifest|ConvertTo-Json -Depth 100|Set-Content -LiteralPath (Join-Path $stage manifest.json) -Encoding utf8NoBOM
    $null=Read-TokenForgeHealthExchange $stage
    Assert-TokenForgeHealthBudget $budget
    foreach($file in Get-ChildItem -LiteralPath $stage){[IO.File]::SetUnixFileMode($file.FullName,[IO.UnixFileMode]256)}
    [IO.Directory]::Move($stage,$output)
    [pscustomobject]@{CollectionComplete=$complete;ExchangeComplete=$true;ImportComplete=$false;OperationalPublication=$false;CandidateCount=$candidateCount;ConflictCount=$conflictCount;Requests=$budget.Requests;ElapsedSeconds=[Math]::Round($budget.Timer.Elapsed.TotalSeconds,3)}|ConvertTo-Json -Compress
}finally{if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}}
