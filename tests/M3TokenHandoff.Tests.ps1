BeforeAll {
    Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
    $plan=Get-Content -LiteralPath $env:TOKENFORGE_M3_HANDOFF -Raw | ConvertFrom-Json -AsHashtable
    $cli=Join-Path "$PSScriptRoot/.." $plan.Script
    $configuredClient=[string]$plan.Parameters.ClientId
    $alternativeClient='11111111-1111-1111-1111-111111111111'
    $bootstrapClient='14d82eec-204b-4c2f-b7e8-296a70dab67e'
    $resource=[string]$plan.Parameters.ResourceId
    $tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    $observer='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    $callback='https://login.microsoftonline.com/common/oauth2/nativeclient'

    function New-MockAccessToken($Client, $Audience, $Scope) {
        $payload=@{tid=$tenant;oid=$observer;appid=$Client;aud=$Audience;scp=$Scope} | ConvertTo-Json -Compress
        $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
        "e30.$encoded.mock-access-secret"
    }
}

Describe 'M3 operator-run scoped-token handoff' -Skip:(-not $env:TOKENFORGE_M3_HANDOFF) {
    BeforeEach {
        $bootstrapAccess=New-MockAccessToken $bootstrapClient $resource User.Read
        $secureBootstrap=ConvertTo-SecureString $bootstrapAccess -AsPlainText -Force
        try {$claims=Get-TokenForgeTokenClaims -AccessToken $secureBootstrap} finally {$secureBootstrap.Dispose()}
        $inventory=@{
            CapturedAt=[DateTimeOffset]::UtcNow.ToString('o')
            TenantFingerprint=$claims.TenantFingerprint
            DiscoveryCatalogHash=("d"*64)
            Applications=@(foreach($id in $bootstrapClient,$alternativeClient,$configuredClient,$resource){
                @{AppId=$id;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner'
                  AccountEnabled=$true;PublicClient=$true;Foci=$false;RedirectUris=@($callback)
                  PreferredRedirectUri=$callback;IdentifierUris=@();DelegatedScopeDefinitions=@(@{Enabled=$true;Value='User.Read'})}
            })
        }
        $observations=@(foreach($id in $alternativeClient,$configuredClient){
            @{ClientId=$id;ResourceId=$resource;Outcome='Succeeded';ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')
              TenantFingerprint=$claims.TenantFingerprint;PrincipalFingerprint=$claims.PrincipalFingerprint
              ScpScopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched'
              Spa=$false;Protocol='OAuth2V2Pkce'}
        })
        $inventory | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $TestDrive inventory.json)
        @{SchemaVersion=1;Observations=$observations;RegistrationAttempts=@()} |
            ConvertTo-Json -Depth 8 | Set-Content (Join-Path $TestDrive scopes.json)
        $options=@{}; foreach($entry in $plan.Parameters.GetEnumerator()){$options[$entry.Key]=$entry.Value}
        $options.StatePath=$TestDrive
        $options.EstsAuth=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
        $requests=[Collections.Generic.List[string]]::new()
        # Keep the already imported real module and its mocked identity transport.
        Mock Import-Module {} -ParameterFilter {$Name -like '*/src/TokenForge/TokenForge.psd1'}
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{id=$observer} }
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge {
            param($Client,$Uri,$Form,$Origin)
            if($Uri.AbsolutePath.EndsWith('/authorize')){
                $query=[System.Web.HttpUtility]::ParseQueryString($Uri.Query)
                $query['prompt'] | Should -BeExactly 'none'
                $query['scope'] | Should -BeExactly "$resource/User.Read"
                $clientId=$query['client_id']
                $requests.Add($clientId)
                if($clientId -eq $configuredClient -and $case -eq 'interaction'){
                    return @{Status=302;Location="${callback}?error=interaction_required&error_description=AADSTS50076%20private-details&state=$($query['state'])";Content=''}
                }
                return @{Status=302;Location="${callback}?code=mock-authorization-code&state=$($query['state'])";Content=''}
            }
            $Uri.AbsolutePath | Should -Match '/token$'
            $Form.client_id | Should -BeIn @($bootstrapClient,$configuredClient)
            $accessToken=if($Form.client_id -eq $bootstrapClient){$bootstrapAccess}else{$issuedAccess}
            $body=@{access_token=$accessToken;refresh_token='mock-refresh-secret';scope='User.Read';token_type='Bearer';expires_in=3600}
            @{Status=200;Content=($body|ConvertTo-Json -Compress)}
        }
    }

    AfterEach {
        $options.EstsAuth.Dispose()
    }

    It 'handles <case> with only the configured final client' -TestCases @(
        @{case='success';audience='00000003-0000-0000-c000-000000000000';issuedScope='User.Read'}
        @{case='missing scopes';audience='00000003-0000-0000-c000-000000000000';issuedScope='Mail.Read'}
        @{case='wrong audience';audience='https://other.example.test';issuedScope='User.Read'}
        @{case='interaction';audience='00000003-0000-0000-c000-000000000000';issuedScope='User.Read'}
    ) {
        $issuedAccess=New-MockAccessToken $configuredClient $audience $issuedScope
        if($case -eq 'success'){
            $result=& $cli @options
            try {
                $result.ClientId | Should -Be $configuredClient
                $result.TokenClaims.Scopes | Should -Be 'User.Read'
                [Net.NetworkCredential]::new('', $result.AccessToken).Password | Should -BeExactly $issuedAccess
                [Net.NetworkCredential]::new('', $result.RefreshToken).Password | Should -BeExactly 'mock-refresh-secret'
            } finally {
                $result.AccessToken.Dispose()
                $result.RefreshToken.Dispose()
            }
        }else{
            $output=[Collections.Generic.List[object]]::new()
            $failure=try {& $cli @options | ForEach-Object {$output.Add($_)}} catch {$_}
            $output.Count | Should -Be 0
            $failure.Exception.Message | Should -Match '^No candidate'
            $details=$failure.Exception.Data['TokenForgeAttempts']
            @($details).Count | Should -Be 1
            $details[0].ClientId | Should -Be $configuredClient
            if($case -eq 'interaction'){
                ($details[0].EntraCodes -join ',') | Should -BeExactly 'AADSTS50076'
            }else{
                $details[0].EntraCodes | Should -BeNullOrEmpty
            }
            ($failure.Exception.Message + ($details | ConvertTo-Json -Compress)) |
                Should -Not -Match 'mock-access-secret|mock-refresh-secret|private-details'
        }
        ($requests -join ',') | Should -BeExactly "$bootstrapClient,$configuredClient"
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -Exactly
        $expectedHttpCalls=if($case -eq 'interaction'){3}else{4}
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times $expectedHttpCalls -Exactly
    }
}
