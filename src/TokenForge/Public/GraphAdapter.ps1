# Graph SDK owns one process-wide context. Use a dedicated PowerShell process for this adapter.
$script:GraphConnection=$null
function Connect-TokenForgeGraph {
    <# .SYNOPSIS
    Connect Graph PowerShell with an explicitly scoped TokenForge token in a dedicated process.
    .DESCRIPTION
    Refuses an existing Graph context. Does not replay SDK calls, grant consent, or refresh the SDK
    context automatically. Disconnect before reconnecting with new scopes or an expired token.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root,[securestring]$VaultPassword,
        [Parameter(Mandatory)][ValidateCount(1,64)][string[]]$Scope)
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    if($script:GraphConnection -or (Get-MgContext)){throw 'Graph already has a process-wide context; use a dedicated PowerShell process or disconnect it explicitly.'}
    $token=Get-TokenForgeProfileToken -Name $Name -Root $Root -VaultPassword $VaultPassword -Resource graph -Scope $Scope
    $secret=$null
    try{
        if(Get-MgContext){throw 'Graph context was established during acquisition; use a dedicated process.'}
        $secret=$token.AccessToken.Copy()
        $null=Connect-MgGraph -AccessToken $secret -NoWelcome -ErrorAction Stop
        $script:GraphConnection=@{Secret=$secret;Profile=$Name;ExpiresAt=$token.ExpiresAt;Context=(Get-MgContext)};$secret=$null
        [pscustomobject]@{Profile=$Name;Scopes=@($token.TokenClaims.Scopes);ExpiresAt=$token.ExpiresAt;Evidence=$token.Evidence;SdkRefresh='ExplicitDisconnectAndReconnect';ProcessIsolation='UseDedicatedPowerShellProcess'}
    }catch{if($secret){$secret.Dispose()};throw 'Graph connection failed; dependency details suppressed.'}
    finally{$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()}}
}
function Disconnect-TokenForgeGraph {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if(-not $script:GraphConnection){throw 'No Graph context is owned by TokenForge.'}
    if(-not [object]::ReferenceEquals((Get-MgContext),$script:GraphConnection.Context)){throw 'Graph context was replaced outside TokenForge; disconnect it explicitly through the SDK.'}
    if($PSCmdlet.ShouldProcess($script:GraphConnection.Profile,'Disconnect the Graph SDK context in this dedicated process')){
        try{$null=Disconnect-MgGraph -ErrorAction Stop}catch{throw 'Graph disconnection failed; owned credential retained so disconnection can be retried. Details suppressed.'}
        $script:GraphConnection.Secret.Dispose();$script:GraphConnection=$null
        [pscustomobject]@{Disconnected=$true;Evidence='LocalSdkContextRemovalNotServerRevocation'}
    }
}
function Find-TokenForgeGraphPermission {
    <# .SYNOPSIS
    Show SDK permission alternatives for a command without joining them into a broader scope request.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z]+-Mg[A-Za-z0-9]+$')][string]$Command)
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $matches=@(Find-MgGraphCommand -Command $Command -ErrorAction Stop)
    foreach($match in $matches){
        [pscustomobject]@{Command=$match.Command;Method=$match.Method;Uri=$match.Uri;Permissions=@($match.Permissions);Evidence='SdkPermissionMetadataChooseAnApplicableAlternative';AutomaticConsent=$false}
    }
}
