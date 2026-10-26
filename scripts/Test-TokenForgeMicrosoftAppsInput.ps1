[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$NativeExecutablePath,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicHealth.ps1)
Initialize-TokenForgeHealthRuntime $NativeExecutablePath

# Offline, private diagnostics only. The existing whole-source validator and
# projector remain the acceptance authority; this locator only explains a refusal.
function Find-MicrosoftAppsContractFailure {
    param($Data)
    if($Data -isnot [array] -or $Data.Count -gt $script:HealthLimits.SourceRecords){return @{Code='SourceShape';Index=$null}}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for($i=0;$i -lt $Data.Count;$i++){
        $row=$Data[$i];$code='SourceShape'
        try{
            Assert-TokenForgeHealthKeys $row @('AppId','AppDisplayName','AppOwnerOrganizationId','Source')
            $code='ApplicationIdentity';Assert-TokenForgeHealthPublishedGuid $row.AppId -AllowEmpty
            $code='OwnerIdentity'
            if($null -ne $row.AppOwnerOrganizationId){
                if($row.AppOwnerOrganizationId -isnot [string]){throw [IO.InvalidDataException]::new('Invalid public owner hint.')}
                if($row.AppOwnerOrganizationId.Length){Assert-TokenForgeHealthPublishedGuid $row.AppOwnerOrganizationId}
            }
            $code='PublicText';Assert-TokenForgeHealthText $row.AppDisplayName;Assert-TokenForgeHealthText $row.Source -Maximum 128
            $code='DuplicateIdentity'
            if(-not $seen.Add($row.AppId.ToLowerInvariant()+'/'+$row.Source)){throw [IO.InvalidDataException]::new('Duplicate public source identity.')}
        }catch{
            if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw}
            return @{Code=$code;Index=$i}
        }
    }
    # Future validator changes may refuse a contract this explanatory locator
    # does not recognize. Never turn that disagreement into source acceptance.
    return @{Code='SourceContract';Index=$null}
}

$bytes=Read-TokenForgeHealthBytes $InputPath $script:HealthLimits.SourceBytes
$root=New-TokenForgeHealthPrivateDirectory $OutputPath
$report=[ordered]@{
    schemaVersion=1;kind='TokenForgeMicrosoftAppsInputDiagnostic';source=$script:HealthSources.microsoftApps
    inputSha256=Get-TokenForgeHealthHash $bytes;inputBytes=$bytes.Length;diagnosedAt=[DateTimeOffset]::UtcNow.ToString('o')
    status='Invalid';reasonCode='Utf8';recordIndex=$null;sourceRecordCount=$null;projectionAttempted=$false
    historicalTrialBytes=$false;networkRequests=0;exchangeEmitted=$false;importPerformed=$false
}
$parsed=$null;$decoded=$false;$sourceValid=$false;$committed=$false
try{
    try{$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);$decoded=$true}
    catch{if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw}}
    if($decoded){
        $report.reasonCode='JsonStructure'
        try{$parsed=Read-TokenForgeHealthJson $bytes}
        catch{
            if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw}
            $cause=$_.Exception
            while($cause -is [Management.Automation.MethodInvocationException] -and $cause.InnerException){$cause=$cause.InnerException}
            if($cause -is [Text.Json.JsonException]){$report.reasonCode='JsonSyntax'}
        }
        if($null -ne $parsed){
            if($parsed -is [array]){$report.sourceRecordCount=$parsed.Count}
            try{$null=Assert-TokenForgeHealthSource microsoftApps $parsed;$sourceValid=$true}
            catch{
                if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw}
                $failure=Find-MicrosoftAppsContractFailure $parsed;$report.reasonCode=$failure.Code;$report.recordIndex=$failure.Index
            }
        }elseif($text.Trim() -ceq 'null'){$report.reasonCode='SourceShape'}
    }
    if($sourceValid){
        $report.projectionAttempted=$true
        $projection=Invoke-TokenForgeHealthProjection -Data @{microsoftApps=$parsed} -CatalogPath (Join-Path $root catalog.tmp) -Now $report.diagnosedAt
        if($projection.Valid){$report.status='Success';$report.reasonCode='Accepted'}else{$report.reasonCode='SourceProjection'}
    }
    # The result contains only literals, hashes, bounded counts/indices and time.
    # No exception text, record values or caller-supplied path is serialized.
    $allowed=@('Accepted','Utf8','JsonSyntax','JsonStructure','SourceShape','ApplicationIdentity','OwnerIdentity','PublicText','DuplicateIdentity','SourceContract','SourceProjection')
    if($report.reasonCode -cnotin $allowed){throw 'Unexpected diagnostic reason code.'}
    $path=Join-Path $root diagnostic.json
    $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write;$options.Share=[IO.FileShare]::None;$options.UnixCreateMode=[IO.UnixFileMode]384
    $stream=[IO.FileStream]::new($path,$options)
    try{$output=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 5));$stream.Write($output);$stream.Flush($true)}finally{$stream.Dispose()}
    [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]256)
    $committed=$true
    $report|ConvertTo-Json -Compress
}finally{
    # Remove only this attempt's private directory if no result was committed.
    if(-not $committed){Remove-Item -LiteralPath $root -Recurse -Force}
}
