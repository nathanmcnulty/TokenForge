function Get-TokenForgeFlowEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[string]$NativeExecutablePath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PlanFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,[switch]$Latest)
    if([bool]$TenantFingerprint -ne [bool]$PrincipalFingerprint){throw 'Select both tenant and principal.'}
    $full=Resolve-TokenForgeVaultPath $Path -CreateDirectory
    if(-not(Test-Path -LiteralPath $full)){return @{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Plans=@{};Attempts=@()}}
    try{
        if($full.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
            $db=Invoke-TokenForgeNativeEvidence $full export -NativeExecutablePath $NativeExecutablePath -PlanFingerprint $PlanFingerprint -Latest:($Latest -or [bool]$PlanFingerprint) -TenantFingerprint $TenantFingerprint -PrincipalFingerprint $PrincipalFingerprint
        }else{
        if((Get-Item -LiteralPath $full).Length -gt 134217728){throw 'Oversized flow evidence.'}
        $db=Get-Content -LiteralPath $full -Raw|ConvertFrom-Json -AsHashtable -Depth 12
        }
        foreach($row in $db.Attempts){foreach($field in @('StartedAt','ObservedAt')){if($row[$field] -is [datetime]){$row[$field]=$row[$field].ToUniversalTime().ToString('o')}}}
        Assert-TokenForgeFlowDocument $db
        if(-not $full.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
            $selected=@{};foreach($hash in $db.Plans.Keys){$plan=$db.Plans[$hash];if(($PlanFingerprint -and $hash -ne $PlanFingerprint) -or ($TenantFingerprint -and ($plan.TenantFingerprint -ne $TenantFingerprint -or $plan.PrincipalFingerprint -ne $PrincipalFingerprint))){continue};$selected[$hash]=$plan}
            $db.Plans=$selected;$db.Attempts=@($db.Attempts|Where-Object {$selected.ContainsKey($_.PlanFingerprint)})
            if($Latest -or $PlanFingerprint){$slots=@{};foreach($row in @($db.Attempts|Sort-Object ObservedAt)){$slots[$row.AttemptKey]=$row};$db.Attempts=@($slots.Values)}
        }
        $db
    }catch{throw 'Flow evidence cannot be read; check private path, format, size, and context. Details suppressed.'}
}
function Export-TokenForgeFlowEvidence {
    <# .SYNOPSIS
    Export successful anonymous flow capabilities without private namespaces, plan IDs, callbacks, or timestamps.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$OutputPath,[string]$NativeExecutablePath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,[switch]$Latest)
    $selection=@{};if($TenantFingerprint){$selection.TenantFingerprint=$TenantFingerprint};if($PrincipalFingerprint){$selection.PrincipalFingerprint=$PrincipalFingerprint}
    $db=Get-TokenForgeFlowEvidence $Path -NativeExecutablePath $NativeExecutablePath -Latest:$Latest @selection
    $seen=@{}
    $rows=@(foreach($row in $db.Attempts){
        if($row.Outcome -ne 'Succeeded'){continue}
        $key=$row.ClientId+'|'+$row.ResourceId+'|'+$row.Protocol+'|'+[int]$row.Spa+'|'+(@($row.ScpScopes|Sort-Object -Unique) -join ' ')
        if($seen.ContainsKey($key)){continue};$seen[$key]=$true
        [ordered]@{ClientId=$row.ClientId;ResourceId=$row.ResourceId;Protocol=$row.Protocol;Spa=$row.Spa;Scopes=@($row.ScpScopes|Sort-Object -Unique);SignatureValidated=$false;Evidence='AnonymousObservedFlowNotUniversalCapability'}
    })
    Save-TokenForgeDocument -Path $OutputPath -Document @{Format='TokenForgeAnonymousFlows';SchemaVersion=1;Observations=$rows;Disclaimer='Account/session/tenant-dependent observations, not universal support or consent.'}
}

function Import-TokenForgeFlowEvidence {
    <# .SYNOPSIS
    Import a strict legacy JSON flow document into a private SQLite flow store transactionally.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$InputPath,[string]$NativeExecutablePath)
    if(-not $Path.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){throw 'Choose a .sqlite destination.'}
    $db=Get-TokenForgeFlowEvidence $InputPath -NativeExecutablePath $NativeExecutablePath
    Invoke-TokenForgeNativeEvidence $Path import -Document $db -NativeExecutablePath $NativeExecutablePath
}
