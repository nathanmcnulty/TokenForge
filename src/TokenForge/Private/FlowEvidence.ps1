function Get-TokenForgeFlowPlanHash {
    param($Plan)
    $parts=@('FlowPolicy1',$Plan.TenantFingerprint,$Plan.PrincipalFingerprint,$Plan.ClientId,$Plan.ResourceId,$Plan.Tenant,$Plan.CatalogHash,$Plan.Eligibility)
    $parts+=@($Plan.ResourceAliases|Sort-Object -Unique)
    $parts+=@($Plan.Cells|ForEach-Object {$_.Protocol+'|'+[int]$_.Spa+'|'+$_.RedirectFingerprint})
    Get-TokenForgeFingerprint ($parts -join "`n")
}
function Assert-TokenForgeFlowDocument {
    param($Document)
    $checkKeys={param($value,$keys) if($value -isnot [Collections.IDictionary] -or $value.Keys.Count -ne $keys.Count -or @($value.Keys|Where-Object {$_ -cnotin $keys}).Count){throw 'Invalid flow evidence fields.'}}
    $guid={param($value) $id=[guid]::Empty;if($value -isnot [string] -or -not [guid]::TryParse($value,[ref]$id) -or $id -eq [guid]::Empty -or $value -cne $id.ToString()){throw 'Invalid flow application ID.'}}
    $hash={param($value) if($value -isnot [string] -or $value -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid flow fingerprint.'}}
    $date={param($value) $time=[DateTimeOffset]::MinValue;if($value -is [datetime]){$value=$value.ToUniversalTime().ToString('o')};if($value -isnot [string] -or -not [DateTimeOffset]::TryParse($value,[ref]$time) -or $time -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid flow date.'}}
    & $checkKeys $Document @('Format','SchemaVersion','UpdatedAt','Plans','Attempts')
    if($Document.Format -cne 'TokenForgeFlowEvidence' -or ($Document.SchemaVersion -isnot [int] -and $Document.SchemaVersion -isnot [long] -or $Document.SchemaVersion -ne 1) -or $Document.Plans -isnot [Collections.IDictionary] -or $Document.Attempts -isnot [array]){throw 'Invalid flow evidence schema.'}
    & $date $Document.UpdatedAt
    foreach($id in $Document.Plans.Keys){
        $plan=$Document.Plans[$id]
        & $hash $id
        & $checkKeys $plan @('TenantFingerprint','PrincipalFingerprint','ClientId','ResourceId','Tenant','CatalogHash','Eligibility','ResourceAliases','Cells','PlannedAt')
        foreach($field in @('TenantFingerprint','PrincipalFingerprint')){& $hash $plan[$field]}
        foreach($field in @('ClientId','ResourceId')){& $guid $plan[$field]}
        & $date $plan.PlannedAt
        if($null -ne $plan.CatalogHash){& $hash $plan.CatalogHash}
        if($plan.Tenant -isnot [string] -or $plan.Tenant -notmatch '^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$' -or $plan.Eligibility -cnotin @('Eligible','MissingRegistration','OwnerMismatch','Disabled','NoRedirect','BrokerRedirectHint','InvalidRedirectHints')){throw 'Invalid flow plan context.'}
        if($plan.ResourceAliases -isnot [array] -or @($plan.ResourceAliases|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.:/-]{1,256}$'}).Count -or $plan.Cells -isnot [array] -or $plan.Cells.Count -gt 4000){throw 'Invalid flow plan matrix.'}
        $seen=@{}
        foreach($cell in $plan.Cells){
            & $checkKeys $cell @('Protocol','Spa','RedirectFingerprint')
            if($cell.Protocol -cnotin @('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit') -or $cell.Spa -isnot [bool] -or ($cell.Spa -and $cell.Protocol -ne 'OAuth2V2Pkce')){throw 'Invalid flow mode.'}
            & $hash $cell.RedirectFingerprint
            $key=$cell.Protocol+'|'+[int]$cell.Spa+'|'+$cell.RedirectFingerprint
            if($seen.ContainsKey($key)){throw 'Duplicate flow slot.'};$seen[$key]=$true
        }
        if((Get-TokenForgeFlowPlanHash $plan) -cne $id){throw 'Flow plan hash mismatch.'}
    }
    $ids=@{}
    foreach($row in $Document.Attempts){
        & $checkKeys $row @('AttemptId','PlanFingerprint','AttemptKey','ClientId','ResourceId','TenantFingerprint','PrincipalFingerprint','StartedAt','ObservedAt','Protocol','Spa','RedirectFingerprint','Outcome','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','NamespaceVerification','RequestVerification','SignatureValidated','ErrorCodes','ElapsedSeconds')
        & $guid $row.AttemptId
        if($ids.ContainsKey($row.AttemptId)){throw 'Duplicate flow attempt ID.'};$ids[$row.AttemptId]=$true
        foreach($field in @('PlanFingerprint','AttemptKey','TenantFingerprint','PrincipalFingerprint','RedirectFingerprint')){& $hash $row[$field]}
        $plan=$Document.Plans[$row.PlanFingerprint]
        if(-not $plan){throw 'Unknown flow plan.'}
        foreach($field in @('ClientId','ResourceId','TenantFingerprint','PrincipalFingerprint')){if($row[$field] -cne $plan[$field]){throw 'Flow context mismatch.'}}
        $cell=@($plan.Cells|Where-Object {$_.Protocol -ceq $row.Protocol -and $_.Spa -eq $row.Spa -and $_.RedirectFingerprint -ceq $row.RedirectFingerprint})
        if($cell.Count -ne 1 -or $row.AttemptKey -cne (Get-TokenForgeFingerprint ($row.PlanFingerprint+'|'+$row.Protocol+'|'+[int]$row.Spa+'|'+$row.RedirectFingerprint))){throw 'Unknown flow slot.'}
        foreach($field in @('StartedAt','ObservedAt')){& $date $row[$field]}
        if(([DateTimeOffset]$row.StartedAt) -gt ([DateTimeOffset]$row.ObservedAt)){throw 'Invalid flow timing.'}
        if($row.Outcome -cnotin @('Started','Failed','Succeeded','OpaqueToken','NoDelegatedScp','ContextMismatch') -or $row.NamespaceVerification -cnotin @('Matched','Mismatch','Unverifiable') -or $row.RequestVerification -cnotin @('Matched','Mismatch','Unverifiable')){throw 'Invalid flow outcome.'}
        foreach($field in @('Spa','ClaimsReadable','HasScpClaim','SignatureValidated')){if($row[$field] -isnot [bool]){throw 'Invalid flow boolean.'}}
        if($row.SignatureValidated){throw 'Flow evidence does not establish signature validation.'}
        if(($row.ElapsedSeconds -isnot [int] -and $row.ElapsedSeconds -isnot [long] -and $row.ElapsedSeconds -isnot [double] -and $row.ElapsedSeconds -isnot [decimal]) -or -not [double]::IsFinite([double]$row.ElapsedSeconds) -or $row.ElapsedSeconds -lt 0 -or $row.ElapsedSeconds -gt 86400){throw 'Invalid flow duration.'}
        foreach($field in @('ResponseScopes','ScpScopes')){if($row[$field] -isnot [array] -or $row[$field].Count -gt 4096 -or @($row[$field]|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.:/-]{1,256}$'}).Count){throw 'Invalid flow scopes.'}}
        if($row.ErrorCodes -isnot [array] -or $row.ErrorCodes.Count -gt 16 -or @($row.ErrorCodes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[0-9]{4,9}$'}).Count){throw 'Invalid flow error codes.'}
        if($row.Outcome -eq 'Succeeded' -and (-not $row.ClaimsReadable -or -not $row.HasScpClaim -or -not $row.ScpScopes.Count -or $row.NamespaceVerification -ne 'Matched' -or $row.RequestVerification -ne 'Matched')){throw 'Flow success must have matched context and delegated scopes.'}
    }
}
function Save-TokenForgeFlowEvidence {
    param([string]$Path,$Plan,[string]$PlanFingerprint,$Attempt,$ExistingDocument,[string]$NativeExecutablePath,[Collections.IDictionary]$Changes)
    $full=Resolve-TokenForgeVaultPath $Path -CreateDirectory
    if($full.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
        if(-not $ExistingDocument){throw 'SQLite checkpointing requires the current plan document.'}
        $db=$ExistingDocument
        if($Plan){$db.Plans[$PlanFingerprint]=$Plan}
        if($Attempt){$db.Attempts=@($db.Attempts|Where-Object AttemptId -ne $Attempt.AttemptId)+@($Attempt)}
        $db.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
        Assert-TokenForgeFlowDocument $db
        if($Plan){$null=Invoke-TokenForgeNativeEvidence $full plan -Document $Plan -PlanFingerprint $PlanFingerprint -NativeExecutablePath $NativeExecutablePath}
        if($Attempt){$null=Invoke-TokenForgeNativeEvidence $full attempt -Document $Attempt -NativeExecutablePath $NativeExecutablePath}
        Add-TokenForgeFlowChanges $Changes $Plan $PlanFingerprint $Attempt
        return $db
    }
    $lockPath=Resolve-TokenForgeVaultPath "$full.lock"
    $lock=$null
    try{
        if(-not(Test-Path $lockPath)){try{$lock=Open-TokenForgeVaultFile $lockPath -Create}catch [IO.IOException]{}}
        if(-not $lock){$lock=Open-TokenForgeVaultFile $lockPath}
        $db=Get-TokenForgeFlowEvidence $full
        if($Plan){$db.Plans[$PlanFingerprint]=$Plan}
        if($Attempt){$db.Attempts=@($db.Attempts|Where-Object AttemptId -ne $Attempt.AttemptId)+@($Attempt)}
        $db.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
        # Reparse to dictionary form for the same strict boundary used by reads.
        $json=ConvertTo-Json -InputObject $db -Depth 12
        if([Text.Encoding]::UTF8.GetByteCount($json) -gt 134217728){throw 'Flow evidence exceeds 128 MiB; archive history before retrying.'}
        Assert-TokenForgeFlowDocument ($json|ConvertFrom-Json -AsHashtable -Depth 12)
        Save-TokenForgeDocument -Document $db -Path $full
        Add-TokenForgeFlowChanges $Changes $Plan $PlanFingerprint $Attempt
        $db
    }finally{if($lock){$lock.Dispose()}}
}

function Add-TokenForgeFlowChanges {
    param([Collections.IDictionary]$Changes,$Plan,[string]$PlanFingerprint,$Attempt)
    if($null -eq $Changes){return}
    if($Plan){$Changes.Plans[$PlanFingerprint]=$Plan.Clone()}
    if($Attempt){$Changes.Attempts[$Attempt.AttemptId]=$Attempt.Clone()}
}
