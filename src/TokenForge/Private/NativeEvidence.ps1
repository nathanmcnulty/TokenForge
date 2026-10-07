function Invoke-TokenForgeNativeEvidence {
    param([string]$Path,[ValidateSet('import','export','plan','attempt','update','cohort','cohort-export','pending','checkpoint')][string]$Operation,
        $Document,[string]$PlanFingerprint,[string]$NativeExecutablePath,[switch]$Latest,[string]$TenantFingerprint,[string]$PrincipalFingerprint,[ValidateSet('flows','catalog','evidence')][string]$Domain='flows',[guid]$AppId=[guid]::Empty,[switch]$CurrentOnly,[guid]$ResourceId=[guid]::Empty,[string]$SourcePath,[int]$BatchSize,[guid]$ClientId=[guid]::Empty,[string]$Outcome,[string]$FlowPlanFingerprint)
    $full=Resolve-TokenForgeVaultPath $Path -CreateDirectory
    if(-not $NativeExecutablePath){$NativeExecutablePath=Join-Path $script:ModuleRoot $(if($IsWindows){'../../tokenforge.exe'}else{'../../tokenforge'})}
    if(-not(Test-Path -LiteralPath $NativeExecutablePath -PathType Leaf)){throw 'SQLite metadata requires the native TokenForge executable. Supply NativeExecutablePath or use a native package.'}
    $temporary=$null;$process=$null
    try{
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NativeExecutablePath)
        $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        foreach($arg in @($Domain,$Operation,'--database',$full)){$start.ArgumentList.Add($arg)}
        if($Operation -in @('import','update','plan','attempt','cohort')){
            $temporary=Join-Path (Split-Path $full -Parent) ([guid]::NewGuid().ToString()+'.flow-input.json')
            $stream=Open-TokenForgeVaultFile $temporary -Create
            try{$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Document -Depth 32 -Compress));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
            $start.ArgumentList.Add('--input');$start.ArgumentList.Add($temporary)
        }
        if($BatchSize){$start.ArgumentList.Add('--batch-size');$start.ArgumentList.Add($BatchSize.ToString([Globalization.CultureInfo]::InvariantCulture))}
        if($SourcePath){$start.ArgumentList.Add('--source');$start.ArgumentList.Add($SourcePath)}
        if($TenantFingerprint){$start.ArgumentList.Add('--tenant');$start.ArgumentList.Add($TenantFingerprint)}
        if($PrincipalFingerprint){$start.ArgumentList.Add('--principal');$start.ArgumentList.Add($PrincipalFingerprint)}
        if($PlanFingerprint){$start.ArgumentList.Add($(if($Operation -eq 'plan'){'--fingerprint'}else{'--plan'}));$start.ArgumentList.Add($PlanFingerprint)}
        if($FlowPlanFingerprint){$start.ArgumentList.Add('--flow-plan');$start.ArgumentList.Add($FlowPlanFingerprint)}
        if($ClientId -ne [guid]::Empty){$start.ArgumentList.Add('--client');$start.ArgumentList.Add($ClientId.ToString())}
        if($Outcome){$start.ArgumentList.Add('--outcome');$start.ArgumentList.Add($Outcome)}
        if($AppId -ne [guid]::Empty){$start.ArgumentList.Add('--app');$start.ArgumentList.Add($AppId.ToString())}
        if($ResourceId -ne [guid]::Empty){$start.ArgumentList.Add('--resource');$start.ArgumentList.Add($ResourceId.ToString())}
        if($CurrentOnly){$start.ArgumentList.Add('--current')}
        if($Latest){$start.ArgumentList.Add('--latest')}
        $process=[Diagnostics.Process]::Start($start)
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(60000)){$process.Kill($true);throw 'Native metadata operation timed out; check its checkpoint before retrying.'}
        $json=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($json) -gt 134217728){throw 'Native metadata operation failed; details suppressed.'}
        $json|ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
    }finally{if($process){$process.Dispose()};if($temporary -and (Test-Path -LiteralPath $temporary)){Remove-Item -LiteralPath $temporary -Force}}
}
