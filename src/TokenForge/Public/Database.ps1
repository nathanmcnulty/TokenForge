function New-TokenForgeScopeDatabase {
    [CmdletBinding()]
    param()
    [pscustomobject]@{ SchemaVersion = 1; UpdatedAt = [DateTimeOffset]::UtcNow.ToString('o'); Observations = @(); RegistrationAttempts = @() }
}

function Get-TokenForgeScopeDatabase {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return New-TokenForgeScopeDatabase }
    $database = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($database.SchemaVersion -ne 1 -or -not $database.PSObject.Properties['Observations'] -or -not $database.PSObject.Properties['RegistrationAttempts']) { throw 'Unsupported scope database document.' }
    $database
}

function Add-TokenForgeScopeObservation {
    <# .SYNOPSIS
    Persist only an explicit whitelist of scope evidence; token objects are never serialized.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Database, [Parameter(Mandatory)]$Observation, [string]$Path)
    $required = @('ClientId','ResourceId','Outcome','TenantFingerprint','PrincipalFingerprint','ObservedAt')
    foreach ($field in $required) { if (-not $Observation.PSObject.Properties[$field]) { throw "Observation is missing $field." } }
    foreach ($field in @('ClientId','ResourceId')) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse([string]$Observation.$field,[ref]$guid)) { throw 'Observation contains an invalid public application ID.' }
    }
    foreach ($field in @('TenantFingerprint','PrincipalFingerprint')) {
        if ($Observation.$field -and $Observation.$field -notmatch '^[a-f0-9]{64}$') { throw 'Observations must use fingerprints, not tenant or user IDs.' }
    }
    if ($Observation.Outcome -notin @('Succeeded','NoDelegatedScp','OpaqueToken','Failed','NoRedirect','Disabled','MissingRegistration','OwnerMismatch','BrokerRequired','ContextMismatch')) { throw 'Invalid observation outcome.' }
    if ($Observation.PSObject.Properties['NamespaceVerification'] -and $Observation.NamespaceVerification -notin @('Matched','Mismatch','Unverifiable')) { throw 'Invalid namespace verification evidence.' }
    if ($Observation.PSObject.Properties['RequestVerification'] -and $Observation.RequestVerification -notin @('Matched','Mismatch','Unverifiable')) { throw 'Invalid request verification evidence.' }
    $clean = [ordered]@{}
    foreach ($field in @('ClientId','ResourceId','Outcome','TenantFingerprint','PrincipalFingerprint','ObservedAt','Protocol','Spa','RedirectFingerprint','RequestedScopes','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','NamespaceVerification','RequestVerification','SignatureValidated','ErrorCodes','AttemptCount','ElapsedSeconds','CatalogHash')) {
        if ($Observation.PSObject.Properties[$field]) { $clean[$field] = $Observation.$field }
    }
    foreach ($field in @('RequestedScopes','ResponseScopes','ScpScopes')) {
        if ($clean.Contains($field)) {
            $clean[$field] = @($clean[$field] | Where-Object { $_ -is [string] -and $_ -match '^[A-Za-z0-9_.:/-]{1,256}$' } | Sort-Object -Unique)
        }
    }
    if ($clean.Contains('ErrorCodes')) { $clean.ErrorCodes = @($clean.ErrorCodes | Where-Object { [string]$_ -match '^[0-9]{4,9}$' } | Sort-Object -Unique) }
    $clean.SignatureValidated = $false
    $Database.Observations += [pscustomobject]$clean
    $Database.UpdatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    if ($Path) { Save-TokenForgeDocument -Document $Database -Path $Path }
    $Database
}

function Compare-TokenForgeScopeDatabase {
    <# .SYNOPSIS
    Compare the latest successful observations in the same tenant/principal namespace.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After)
    $maps = @(@{},@{})
    $index = 0
    foreach ($database in @($Before,$After)) {
        foreach ($observation in @($database.Observations | Sort-Object ObservedAt)) {
            $key = "$($observation.TenantFingerprint)/$($observation.PrincipalFingerprint)/$($observation.ClientId)/$($observation.ResourceId)"
            $maps[$index][$key] = $observation
        }
        $index++
    }
    foreach ($key in @(@($maps[0].Keys) + @($maps[1].Keys) | Sort-Object -Unique)) {
        $old = $maps[0][$key]; $new = $maps[1][$key]
        $oldScopes = @(if ($old -and $old.Outcome -eq 'Succeeded') { $old.ScpScopes })
        $newScopes = @(if ($new -and $new.Outcome -eq 'Succeeded') { $new.ScpScopes })
        $added = @($newScopes | Where-Object { $oldScopes -cnotcontains $_ })
        # A failed re-probe is availability evidence, not proof that scopes were removed.
        $removed = @(if ($new -and $new.Outcome -eq 'Succeeded' -and $old -and $old.Outcome -eq 'Succeeded') { $oldScopes | Where-Object { $newScopes -cnotcontains $_ } })
        if ($added.Count -or $removed.Count -or ($old -and $new -and $old.Outcome -ne $new.Outcome)) {
            [pscustomobject]@{ Key = $key; AddedScopes = $added; RemovedScopes = $removed; BeforeOutcome = if ($old) { $old.Outcome } else { 'NotObserved' }; AfterOutcome = if ($new) { $new.Outcome } else { 'NotObserved' } }
        }
    }
}

function Export-TokenForgeScopeDatabase {
    <# .SYNOPSIS
    Export public app/resource scope observations without tenant or principal fingerprints.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Database, [Parameter(Mandatory)][string]$Path)
    $records = foreach ($observation in $Database.Observations) {
        if ($observation.Outcome -ne 'Succeeded' -or -not $observation.PSObject.Properties['RequestVerification'] -or $observation.RequestVerification -ne 'Matched') { continue }
        [pscustomobject]@{
            ClientId = $observation.ClientId; ResourceId = $observation.ResourceId
            ObservedAt = $observation.ObservedAt; Scopes = @($observation.ScpScopes)
            Evidence = 'AnonymousTenantTokenObservation'; SignatureValidated = $false
        }
    }
    Save-TokenForgeDocument -Path $Path -Document ([pscustomobject]@{ SchemaVersion = 1; Observations = @($records); Disclaimer = 'Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.' })
}

function Get-TokenForgeAssessmentCoverage {
    <#
    .SYNOPSIS
    Rank fresh, namespace-specific observed clients by additional API scopes for a required set.
    .DESCRIPTION
    Returns complete candidates first, then missing-scope gaps. Does not equate scope claims with API access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][string[]]$Scope,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,8760)][int]$MaxAgeHours = 24
    )
    $latest = @{}
    foreach ($observation in @($Database.Observations | Sort-Object ObservedAt)) {
        if ($observation.ResourceId -eq $ResourceId.ToString() -and $observation.TenantFingerprint -eq $TenantFingerprint -and $observation.PrincipalFingerprint -eq $PrincipalFingerprint) { $latest[$observation.ClientId] = $observation }
    }
    $rows = foreach ($observation in $latest.Values) {
        if (-not $observation.PSObject.Properties['NamespaceVerification'] -or $observation.NamespaceVerification -ne 'Matched') { continue }
        if (-not $observation.PSObject.Properties['RequestVerification'] -or $observation.RequestVerification -ne 'Matched') { continue }
        if ($observation.Outcome -ne 'Succeeded' -or [DateTimeOffset]::Parse($observation.ObservedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$MaxAgeHours)) { continue }
        $apiScopes = @($observation.ScpScopes | Where-Object { $_ -cnotin @('openid','profile','email','offline_access') })
        $missing = @($Scope | Where-Object { $apiScopes -cnotcontains $_ })
        $additional = @($apiScopes | Where-Object { $Scope -cnotcontains $_ })
        [pscustomobject]@{
            ClientId = $observation.ClientId; ResourceId = $observation.ResourceId
            CoversAll = $missing.Count -eq 0; MissingScopes = $missing; AdditionalScopes = $additional
            AdditionalScopeCount = $additional.Count; ObservedApiScopeCount = $apiScopes.Count
            ObservedAt = $observation.ObservedAt; Protocol = if ($observation.PSObject.Properties['Protocol']) { $observation.Protocol } else { 'Unknown' }; Spa = if ($observation.PSObject.Properties['Spa']) { $observation.Spa } else { $null }; Evidence = 'ObservedScpNotApiAuthorization'
        }
    }
    @($rows | Sort-Object @{ Expression = { $_.MissingScopes.Count } }, AdditionalScopeCount, ObservedApiScopeCount, ClientId)
}
