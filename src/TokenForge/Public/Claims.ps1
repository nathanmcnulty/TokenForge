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
    [TokenForge.Core.V0180.TokenClaims]::Read($AccessToken) | Select-Object Readable,Scopes,HasDelegatedScopeClaim,Audience,ClientId,TenantFingerprint,PrincipalFingerprint,ExpiresAt,SignatureValidated,Evidence
}
