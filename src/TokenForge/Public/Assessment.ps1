function Get-TokenForgeAssessmentPlan {
    <# .SYNOPSIS
    Map declarative read-only checks to fresh scope observations in one observer namespace.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,8760)][int]$MaxAgeHours = 24
    )
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.SchemaVersion -ne 1 -or -not $manifest.PSObject.Properties['Checks'] -or @($manifest.Checks).Count -eq 0) { throw 'Unsupported or empty assessment manifest.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $checks = foreach ($check in $manifest.Checks) {
        foreach ($field in @('Id','ResourceId','Scopes','ApiUri','Roles','Licensing','Reference')) {
            if (-not $check.PSObject.Properties[$field]) { throw "Assessment check is missing $field." }
        }
        if ($check.Id -notmatch '^[A-Za-z0-9_-]{1,64}$' -or -not $seen.Add($check.Id)) { throw 'Check IDs must be unique simple names.' }
        $resource = [guid]::Empty
        if (-not [guid]::TryParse([string]$check.ResourceId,[ref]$resource) -or @($check.Scopes).Count -eq 0 -or @($check.Scopes | Where-Object { $_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -cin @('openid','profile','email','offline_access') }).Count) { throw 'Invalid assessment resource or explicit API scopes.' }
        $uri = [uri]$check.ApiUri
        $allowed = ($resource.ToString() -eq '00000003-0000-0000-c000-000000000000' -and $uri.Host -eq 'graph.microsoft.com') -or ($resource.ToString() -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013' -and $uri.Host -eq 'management.azure.com')
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or $uri.Port -ne 443 -or $uri.UserInfo -or $uri.Fragment -or -not $allowed) { throw 'Assessment API must match the supported Graph or ARM resource boundary.' }
        $reference = [uri]$check.Reference
        if (-not $reference.IsAbsoluteUri -or $reference.Scheme -ne 'https' -or $reference.UserInfo) { throw 'Assessment references must be HTTPS.' }
        foreach ($field in @('Roles','Licensing')) {
            if (@($check.$field | Where-Object { $_ -isnot [string] -or $_.Length -gt 512 }).Count) { throw 'Role and licensing requirements must be bounded strings.' }
        }
        $candidates = @(Get-TokenForgeAssessmentCoverage -Database $Database -ResourceId $resource -Scope $check.Scopes -TenantFingerprint $TenantFingerprint -PrincipalFingerprint $PrincipalFingerprint -MaxAgeHours $MaxAgeHours | Where-Object CoversAll)
        [pscustomobject]@{
            Id = $check.Id; ResourceId = $resource.ToString(); RequiredScopes = @($check.Scopes)
            ApiUri = $uri.AbsoluteUri; Method = 'GET'; Roles = @($check.Roles); Licensing = @($check.Licensing); Reference = $reference.AbsoluteUri
            Candidates = $candidates; BestClientId = if ($candidates.Count) { $candidates[0].ClientId } else { $null }
            ScopeStatus = if ($candidates.Count) { 'FreshObservedCoverage' } else { 'NeedsObservation' }
            RoleStatus = 'NotValidated'; LicensingStatus = 'NotValidated'; ApiStatus = 'NotValidated'
        }
    }
    [pscustomobject]@{ SchemaVersion = 1; GeneratedAt = [DateTimeOffset]::UtcNow.ToString('o'); TenantFingerprint = $TenantFingerprint; PrincipalFingerprint = $PrincipalFingerprint; MaxAgeHours = $MaxAgeHours; Checks = @($checks) }
}

function Get-TokenForgeMaintenanceReport {
    <# .SYNOPSIS
    Queue missing, failed, stale, or unverified client/resource evidence for one observer.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,8760)][int]$MaxAgeHours = 24
    )
    $latest = @{}
    foreach ($observation in @($Database.Observations | Sort-Object { [DateTimeOffset]::Parse($_.ObservedAt).UtcDateTime })) {
        if ($observation.TenantFingerprint -eq $Inventory.TenantFingerprint -and $observation.PrincipalFingerprint -eq $PrincipalFingerprint) { $latest["$($observation.ClientId)/$($observation.ResourceId)"] = $observation }
    }
    $now = [DateTimeOffset]::UtcNow
    $queue = foreach ($pair in Get-TokenForgeProbePlan -Inventory $Inventory -PrincipalFingerprint $PrincipalFingerprint) {
        $observation = $latest["$($pair.ClientId)/$($pair.ResourceId)"]
        $reason = if (-not $observation) { 'NotObserved' }
        elseif ([DateTimeOffset]::Parse($observation.ObservedAt) -lt $now.AddHours(-$MaxAgeHours)) { 'Stale' }
        elseif ([DateTimeOffset]::Parse($observation.ObservedAt) -gt $now.AddMinutes(5)) { 'InvalidFutureTimestamp' }
        elseif ($observation.Outcome -ne 'Succeeded') { 'Unavailable' }
        elseif (-not $observation.PSObject.Properties['NamespaceVerification'] -or $observation.NamespaceVerification -ne 'Matched' -or -not $observation.PSObject.Properties['RequestVerification'] -or $observation.RequestVerification -ne 'Matched') { 'Unverified' }
        else { $null }
        if ($reason) { [pscustomobject]@{ClientId=$pair.ClientId;ResourceId=$pair.ResourceId;Reason=$reason;ObservedAt=if($observation){$observation.ObservedAt}else{$null}} }
    }
    [pscustomobject]@{ SchemaVersion=1; GeneratedAt=$now.ToString('o'); TenantFingerprint=$Inventory.TenantFingerprint; PrincipalFingerprint=$PrincipalFingerprint; MaxAgeHours=$MaxAgeHours; InventoryCapturedAt=$Inventory.CapturedAt; InventoryRefreshRequired=([DateTimeOffset]::Parse($Inventory.CapturedAt) -lt $now.AddHours(-$MaxAgeHours) -or [DateTimeOffset]::Parse($Inventory.CapturedAt) -gt $now.AddMinutes(5)); ProbeQueue=@($queue) }
}
