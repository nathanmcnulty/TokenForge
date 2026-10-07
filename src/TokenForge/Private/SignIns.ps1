function Get-TokenForgeSignInSummaryValues {
    param([string]$Field)
    switch($Field){
        ProtocolCounts {@('none','oAuth2','ropc','wsFederation','saml20','deviceCode','unknownFutureValue','authenticationTransfer','nativeAuth','implicitAccessTokenAndGetResponseMode','implicitIdTokenAndGetResponseMode','implicitAccessTokenAndPostResponseMode','implicitIdTokenAndPostResponseMode','authorizationCodeWithoutPkce','authorizationCodeWithPkce','clientCredentials','refreshTokenGrant','encryptedAuthorizeResponse','directUserGrant','kerberos','prtGrant','seamlessSso','prtBrokerBased','prtNonBrokerBased','onBehalfOf','samlOnBehalfOf','Unknown')}
        ClientTypeCounts {@('Browser','Mobile Apps and Desktop clients','Modern clients','Exchange ActiveSync','Other clients','IMAP','MAPI','SMTP','POP','Authenticated SMTP','Exchange Web Services','Unknown')}
        EventTypeCounts {@('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')}
        OutcomeCounts {@('Succeeded','Failed','Unknown')}
        default {@()}
    }
}
