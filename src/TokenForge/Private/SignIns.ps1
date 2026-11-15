function Get-TokenForgeSignInSummaryValues {
    param([string]$Field)
    switch($Field){
        ProtocolCounts {@('none','oAuth2','ropc','wsFederation','saml20','deviceCode','unknownFutureValue','authenticationTransfer','nativeAuth','implicitAccessTokenAndGetResponseMode','implicitIdTokenAndGetResponseMode','implicitAccessTokenAndPostResponseMode','implicitIdTokenAndPostResponseMode','authorizationCodeWithoutPkce','authorizationCodeWithPkce','clientCredentials','refreshTokenGrant','encryptedAuthorizeResponse','directUserGrant','kerberos','prtGrant','seamlessSso','prtBrokerBased','prtNonBrokerBased','onBehalfOf','samlOnBehalfOf','Unknown')}
        ClientTypeCounts {@('Browser','Mobile Apps and Desktop clients','Modern clients','Exchange ActiveSync','Other clients','IMAP','MAPI','SMTP','POP','Authenticated SMTP','Exchange Web Services','Unknown')}
        EventTypeCounts {@('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')}
        AuthenticationMethodCounts {@('SMS','Authenticator App','App Verification code','Password','FIDO','PTA','PHS','Unknown')}
        CredentialTypeCounts {@('none','clientSecret','clientAssertion','federatedIdentityCredential','managedIdentity','certificate','unknownFutureValue','Unknown')}
        IncomingTokenTypeCounts {@('none','primaryRefreshToken','saml11','saml20','unknownFutureValue','remoteDesktopToken','refreshToken','Unknown')}
        OutcomeCounts {@('Succeeded','Failed','Unknown')}
        default {@()}
    }
}

function ConvertTo-TokenForgeSignInGuid {
    param($Value)
    $parsed=[guid]::Empty
    if($Value -is [string] -and [guid]::TryParse($Value,[ref]$parsed) -and $parsed -ne [guid]::Empty){return $parsed.ToString()}
    return $null
}

function Get-TokenForgeSignInField {
    param($Object,[string]$Name)
    if($null -eq $Object){return $null}
    if($Object -is [Collections.IDictionary]){if($Object.Contains($Name)){return $Object[$Name]};return $null}
    $property=$Object.PSObject.Properties[$Name]
    if($property){return $property.Value}
    return $null
}

function Resolve-TokenForgeSignInResource {
    param($Inventory,[string]$ResourceId,[string]$ResourceServicePrincipalId)
    $matches=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $evidence=[Collections.Generic.List[string]]::new()
    # A raw sign-in field is never assumed to be an app ID solely because it parses.
    $directoryEntries=@(Get-TokenForgeSignInField $Inventory DirectoryObjects)
    $directoryEntries+=@(Get-TokenForgeSignInField $Inventory Applications|Where-Object {(Get-TokenForgeSignInField $_ Registration) -ceq 'Present'})
    foreach($entry in $directoryEntries){
        if(-not $entry){continue}
        $app=ConvertTo-TokenForgeSignInGuid ([string](Get-TokenForgeSignInField $entry AppId))
        if(-not $app){continue}
        $object=ConvertTo-TokenForgeSignInGuid ([string](Get-TokenForgeSignInField $entry ServicePrincipalObjectId))
        if(-not $object){$object=ConvertTo-TokenForgeSignInGuid ([string](Get-TokenForgeSignInField $entry Id))}
        if($ResourceId -and $app -ceq $ResourceId){$null=$matches.Add($app);$evidence.Add('ResourceIdMatchesDirectoryAppId')}
        if($ResourceId -and $object -and $object -ceq $ResourceId){$null=$matches.Add($app);$evidence.Add('ResourceIdMatchesDirectoryObject')}
        if($ResourceId -and $ResourceId -cin @(Get-TokenForgeSignInField $entry IdentifierUris)){$null=$matches.Add($app);$evidence.Add('ResourceIdMatchesDirectoryIdentifierUri')}
        if($ResourceServicePrincipalId -and $object -and $object -ceq $ResourceServicePrincipalId){$null=$matches.Add($app);$evidence.Add('ResourceServicePrincipalIdMatchesDirectoryObject')}
    }
    $ids=@($matches|Sort-Object)
    [ordered]@{Resolution=if($ids.Count -eq 1){'DirectoryMatched'}elseif($ids.Count -gt 1){'Ambiguous'}else{'Unresolved'};ResolvedAppId=if($ids.Count -eq 1){$ids[0]}else{$null};CandidateAppIds=$ids;MappingEvidence=@($evidence|Sort-Object -Unique)}
}

function Save-TokenForgeSignInCheckpoint {
    param([string]$Path,$Payload)
    if(-not $Path){return}
    $json=ConvertTo-Json -InputObject $Payload -Depth 100 -Compress
    Save-TokenForgeDocument -Document ([ordered]@{Format='TokenForgePrivateSignInCheckpoint';SchemaVersion=1;Payload=$Payload;ContentSha256=(Get-TokenForgeFingerprint $json)}) -Path $Path
}

function Read-TokenForgeSignInCheckpoint {
    param([string]$Path,[string]$Binding)
    $bytes=[IO.File]::ReadAllBytes($Path)
    if($bytes.Length -gt 67108864){throw 'Sign-in checkpoint exceeds the supported size.'}
    $value=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
    if($value.Format -cne 'TokenForgePrivateSignInCheckpoint' -or $value.SchemaVersion -ne 1 -or $value.Payload.Binding -cne $Binding -or $value.ContentSha256 -cne (Get-TokenForgeFingerprint (ConvertTo-Json -InputObject $value.Payload -Depth 100 -Compress))){throw 'Sign-in checkpoint binding or integrity mismatch.'}
    return $value.Payload
}

function ConvertTo-TokenForgeSignInResourceIdentifier {
    param($Value)
    $guid=ConvertTo-TokenForgeSignInGuid $Value
    if($guid){return $guid}
    if($Value -isnot [string] -or $Value.Length -gt 2048){return $null}
    $uri=$null
    if([uri]::TryCreate($Value,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -cin @('https','api') -and $uri.Host -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment){return $Value}
    return $null
}
