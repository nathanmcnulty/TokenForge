function Get-TokenForgeResearchCoverage {
    <# .SYNOPSIS
    Categorize catalog evidence and exact flow-plan coverage without authenticating or authorizing anything.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MetadataPath,[string]$FlowPath,[string]$NativeExecutablePath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [guid[]]$AppId,[ValidateRange(1,8760)][int]$MaxAgeHours=24,[switch]$SummaryOnly
    )
    if([bool]$TenantFingerprint -ne [bool]$PrincipalFingerprint){throw 'Select both tenant and principal for account-specific flow coverage.'}
    # Validate all history before deriving a current report; never prefilter attempts.
    if(-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)){throw 'Research metadata does not exist.'}
    if($FlowPath -and -not (Test-Path -LiteralPath $FlowPath -PathType Leaf)){throw 'Explicit flow evidence does not exist.'}
    # The native report validates complete SQLite history without a PowerShell
    # object/JSON round trip. Its CLI accepts only one application selector.
    if($MetadataPath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase) -and
        (-not $FlowPath -or $FlowPath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)) -and @($AppId).Count -le 1){
        $process=$null
        try{
            $metadataFull=Resolve-TokenForgeVaultPath $MetadataPath
            $flowFull=if($FlowPath){Resolve-TokenForgeVaultPath $FlowPath}else{$null}
            if(-not $NativeExecutablePath){$NativeExecutablePath=Join-Path $script:ModuleRoot $(if($IsWindows){'../../tokenforge.exe'}else{'../../tokenforge'})}
            if(-not(Test-Path -LiteralPath $NativeExecutablePath -PathType Leaf)){throw 'Native executable does not exist.'}
            $start=[Diagnostics.ProcessStartInfo]::new()
            $start.FileName=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NativeExecutablePath)
            $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            foreach($arg in @('research','report','--metadata-path',$metadataFull,'--max-age-hours',$MaxAgeHours.ToString([Globalization.CultureInfo]::InvariantCulture),'--json')){$start.ArgumentList.Add($arg)}
            if($flowFull){$start.ArgumentList.Add('--flow-path');$start.ArgumentList.Add($flowFull)}
            if($TenantFingerprint){
                $start.ArgumentList.Add('--tenant-fingerprint');$start.ArgumentList.Add($TenantFingerprint)
                $start.ArgumentList.Add('--principal-fingerprint');$start.ArgumentList.Add($PrincipalFingerprint)
            }
            if($AppId){$start.ArgumentList.Add('--app');$start.ArgumentList.Add($AppId[0].ToString())}
            if($SummaryOnly){$start.ArgumentList.Add('--summary-only')}
            $process=[Diagnostics.Process]::Start($start)
            $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
            if(-not $process.WaitForExit(300000)){$process.Kill($true);throw 'Native report timed out.'}
            $report=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
            if($process.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($report) -gt 134217728){throw 'Native report failed.'}
            return [pscustomobject][TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($report)
        }catch{throw 'Research coverage cannot be read; check private paths, complete history, and native executable. Details suppressed.'}
        finally{if($process){$process.Dispose()}}
    }
    $catalog=Get-TokenForgeApplicationMetadata $MetadataPath -NativeExecutablePath $NativeExecutablePath
    $flows=if($FlowPath -and (Test-Path -LiteralPath $FlowPath -PathType Leaf)){Get-TokenForgeFlowEvidence $FlowPath -NativeExecutablePath $NativeExecutablePath}else{$null}
    $flowJson=if($flows){$flows|ConvertTo-Json -Depth 20 -Compress}else{$null}
    $ids=if($AppId){[string[]]@($AppId|ForEach-Object ToString)}else{$null}
    $report=[TokenForge.Core.ResearchCoverage]::CreateFromValidatedDocuments(
        ($catalog|ConvertTo-Json -Depth 100 -Compress),$flowJson,
        $(if($TenantFingerprint){$TenantFingerprint}else{$null}),
        $(if($PrincipalFingerprint){$PrincipalFingerprint}else{$null}),$ids,$MaxAgeHours,[bool]$SummaryOnly,$null
    )
    [pscustomobject][TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($report)
}
