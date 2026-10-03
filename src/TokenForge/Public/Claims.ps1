function Get-TokenForgeTokenClaims {
    <#
    .SYNOPSIS
    Inspect audience, client ID, expiry, scp and context fingerprints; omit raw identity claims.
    .DESCRIPTION
    JWT payload parsing is diagnostic, not signature validation or proof of API access.
    Microsoft tokens can be opaque. Never use these claims as an authorization boundary.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][securestring]$AccessToken)
    $payload = ConvertFrom-TokenForgeJwtPayload -AccessToken $AccessToken
    $scopes = @()
    if ($payload -and $payload['scp'] -is [string]) {
        $scopes = @($payload['scp'] -split '\s+' | Where-Object { $_ -match '^[A-Za-z0-9_.-]+$' } | Sort-Object -Unique)
    }
    $expiresAt = $null
    if ($payload -and $payload['exp'] -is [long]) {
        try { $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds($payload['exp']) } catch { $expiresAt = $null }
    }
    [pscustomobject]@{
        Readable = $null -ne $payload
        Scopes = $scopes
        HasDelegatedScopeClaim = $null -ne $payload -and $payload.Contains('scp')
        Audience = if ($payload -and $payload['aud'] -is [string]) { $payload['aud'] } else { $null }
        ClientId = if ($payload -and $payload['azp']) { [string]$payload['azp'] } elseif ($payload -and $payload['appid']) { [string]$payload['appid'] } else { $null }
        TenantFingerprint = if ($payload -and $payload['tid']) { Get-TokenForgeFingerprint -Value ([string]$payload['tid']) } else { $null }
        PrincipalFingerprint = if ($payload -and $payload['tid'] -and $payload['oid']) { Get-TokenForgeFingerprint -Value "$($payload['tid'])/$($payload['oid'])" } else { $null }
        ExpiresAt = $expiresAt
        SignatureValidated = $false
        Evidence = if ($payload) { 'JwtPayloadUnverified' } else { 'OpaqueToken' }
    }
}
