function Merge-TokenForgeScopeDatabase {
    <# .SYNOPSIS
    Merge independent checkpoints into one whitelisted history, retaining namespaces and deduplicating identical records.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Database, [string]$Path)
    $result = New-TokenForgeScopeDatabase
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($source in $Database) {
        if ($source.SchemaVersion -ne 1) { throw 'Unsupported merge source schema.' }
        foreach ($observation in $source.Observations) {
            $temporary = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $observation
            $clean = $temporary.Observations[0]
            $clean.ObservedAt = [DateTimeOffset]::Parse($clean.ObservedAt).ToUniversalTime().ToString('o')
            $key = 'scope/' + (Get-TokenForgeFingerprint -Value ($clean | ConvertTo-Json -Depth 20 -Compress))
            if ($seen.Add($key)) { $result.Observations += $clean }
        }
        foreach ($attempt in $source.RegistrationAttempts) {
            $id = [guid]::Empty
            if (-not [guid]::TryParse([string]$attempt.AppId,[ref]$id) -or $attempt.TenantFingerprint -notmatch '^[a-f0-9]{64}$') { throw 'Invalid registration merge identity.' }
            if ($attempt.Outcome -notin @('Created','AlreadyPresent','Failed','OwnerRejected','CleanupRequired','CleanupResolved')) { throw 'Invalid registration merge outcome.' }
            $status = $null
            if ($attempt.PSObject.Properties['HttpStatus'] -and $null -ne $attempt.HttpStatus) {
                $number = 0
                if (-not [int]::TryParse([string]$attempt.HttpStatus,[ref]$number) -or $number -lt 100 -or $number -gt 599) { throw 'Invalid registration HTTP status.' }
                $status = $number
            }
            $clean = [pscustomobject]@{ AppId=$id.ToString(); TenantFingerprint=[string]$attempt.TenantFingerprint; AttemptedAt=[DateTimeOffset]::Parse($attempt.AttemptedAt).ToUniversalTime().ToString('o'); Outcome=[string]$attempt.Outcome; HttpStatus=$status }
            $key = 'registration/' + (Get-TokenForgeFingerprint -Value ($clean | ConvertTo-Json -Compress))
            if ($seen.Add($key)) { $result.RegistrationAttempts += $clean }
        }
    }
    $result.Observations = @($result.Observations | Sort-Object ObservedAt)
    $result.RegistrationAttempts = @($result.RegistrationAttempts | Sort-Object AttemptedAt)
    if ($Path) { Save-TokenForgeDocument -Document $result -Path $Path }
    $result
}
