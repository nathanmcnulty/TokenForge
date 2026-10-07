function Invoke-TokenForgeNativeFlow {
    param([string]$Path,[ValidateSet('import','export','plan','attempt')][string]$Operation,
        $Document,[string]$PlanFingerprint,[string]$NativeExecutablePath,[switch]$Latest,[string]$TenantFingerprint,[string]$PrincipalFingerprint)
    $full=Resolve-TokenForgeVaultPath $Path -CreateDirectory
    if(-not $NativeExecutablePath){$NativeExecutablePath=Join-Path $script:ModuleRoot $(if($IsWindows){'../../tokenforge.exe'}else{'../../tokenforge'})}
    if(-not(Test-Path -LiteralPath $NativeExecutablePath -PathType Leaf)){throw 'SQLite flow evidence requires the native TokenForge executable. Supply NativeExecutablePath or use a native package.'}
    $temporary=$null;$process=$null
    try{
        $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($NativeExecutablePath)
        $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        foreach($arg in @('flows',$Operation,'--database',$full)){$start.ArgumentList.Add($arg)}
        if($Operation -ne 'export'){
            $temporary=Join-Path (Split-Path $full -Parent) ([guid]::NewGuid().ToString()+'.flow-input.json')
            $stream=Open-TokenForgeVaultFile $temporary -Create
            try{$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Document -Depth 12 -Compress));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
            $start.ArgumentList.Add('--input');$start.ArgumentList.Add($temporary)
        }
        if($TenantFingerprint){$start.ArgumentList.Add('--tenant');$start.ArgumentList.Add($TenantFingerprint)}
        if($PrincipalFingerprint){$start.ArgumentList.Add('--principal');$start.ArgumentList.Add($PrincipalFingerprint)}
        if($PlanFingerprint){$start.ArgumentList.Add($(if($Operation -eq 'plan'){'--fingerprint'}else{'--plan'}));$start.ArgumentList.Add($PlanFingerprint)}
        if($Latest){$start.ArgumentList.Add('--latest')}
        $process=[Diagnostics.Process]::Start($start)
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(60000)){$process.Kill($true);throw 'Native flow operation timed out; check its checkpoint before retrying.'}
        $json=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0 -or [Text.Encoding]::UTF8.GetByteCount($json) -gt 134217728){throw 'Native flow operation failed; details suppressed.'}
        $json|ConvertFrom-Json -AsHashtable -Depth 12 -ErrorAction Stop
    }finally{if($process){$process.Dispose()};if($temporary -and (Test-Path -LiteralPath $temporary)){Remove-Item -LiteralPath $temporary -Force}}
}
