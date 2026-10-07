function Get-TokenForgeFlowEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full=Resolve-TokenForgeVaultPath $Path -CreateDirectory
    if(-not(Test-Path -LiteralPath $full)){return @{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Plans=@{};Attempts=@()}}
    try{
        if((Get-Item -LiteralPath $full).Length -gt 134217728){throw 'Oversized flow evidence.'}
        $db=Get-Content -LiteralPath $full -Raw|ConvertFrom-Json -AsHashtable -Depth 12
        foreach($row in $db.Attempts){foreach($field in @('StartedAt','ObservedAt')){if($row[$field] -is [datetime]){$row[$field]=$row[$field].ToUniversalTime().ToString('o')}}}
        Assert-TokenForgeFlowDocument $db
        $db
    }catch{throw 'Flow evidence cannot be read; check private path, format, size, and context. Details suppressed.'}
}
function Export-TokenForgeFlowEvidence {
    <# .SYNOPSIS
    Export successful anonymous flow capabilities without private namespaces, plan IDs, callbacks, or timestamps.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$OutputPath)
    $db=Get-TokenForgeFlowEvidence $Path
    $seen=@{}
    $rows=@(foreach($row in $db.Attempts){
        if($row.Outcome -ne 'Succeeded'){continue}
        $key=$row.ClientId+'|'+$row.ResourceId+'|'+$row.Protocol+'|'+[int]$row.Spa+'|'+(@($row.ScpScopes|Sort-Object -Unique) -join ' ')
        if($seen.ContainsKey($key)){continue};$seen[$key]=$true
        [ordered]@{ClientId=$row.ClientId;ResourceId=$row.ResourceId;Protocol=$row.Protocol;Spa=$row.Spa;Scopes=@($row.ScpScopes|Sort-Object -Unique);SignatureValidated=$false;Evidence='AnonymousObservedFlowNotUniversalCapability'}
    })
    Save-TokenForgeDocument -Path $OutputPath -Document @{Format='TokenForgeAnonymousFlows';SchemaVersion=1;Observations=$rows;Disclaimer='Account/session/tenant-dependent observations, not universal support or consent.'}
}
