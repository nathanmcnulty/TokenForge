BeforeAll {
    Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
    $catalog = Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
    $graph = '00000003-0000-0000-c000-000000000000'
    $clientId = '11111111-1111-1111-1111-111111111111'
    $base = @{ Catalog = $catalog; ClientId = $clientId; ResourceId = $graph; Scope = @('User.Read','Mail.Read'); RedirectUri = 'https://example.test/callback' }
}

Describe 'Catalog and request planning' {
    It 'preserves provenance and client metadata' {
        $catalog.Applications.Count | Should -Be 2
        $catalog.ContentSha256 | Should -Match '^[a-f0-9]{64}$'
        $catalog.Applications[0].PublicClient | Should -BeTrue
    }
    It 'matches every scope for the selected resource' {
        $found = @(Find-TokenForgeApplication -Catalog $catalog -ResourceId $graph -Scope User.Read,Mail.Read)
        $found.Count | Should -Be 1
        $found[0].ClientId | Should -Be $clientId
        $found[0].Evidence | Should -Be PublishedMetadata
    }
    It 'does not mix resource scopes or use substring matching' {
        @(Find-TokenForgeApplication -Catalog $catalog -ResourceId $graph -Scope User).Count | Should -Be 0
        @(Find-TokenForgeApplication -Catalog $catalog -ResourceId '33333333-3333-3333-3333-333333333333' -Scope User.Read).Count | Should -Be 0
    }
    It 'filters public clients and literal names' {
        @(Find-TokenForgeApplication -Catalog $catalog -ResourceId $graph -Scope User.Read -PublicClientOnly).Count | Should -Be 1
        @(Find-TokenForgeApplication -Catalog $catalog -ResourceId $graph -Scope User.Read -Name '*').Count | Should -Be 0
    }
    It 'builds explicit scopes without requesting all published scopes' {
        $plan = New-TokenForgeRequest @base -OfflineAccess -ResourceUri 'https://graph.microsoft.com'
        $plan.OAuthScopes | Should -Contain 'https://graph.microsoft.com/User.Read'
        $plan.OAuthScopes | Should -Contain offline_access
        $plan.OAuthScopes.Count | Should -Be 3
    }
    It 'uses a resource application ID when no identifier URI is specified' {
        (New-TokenForgeRequest @base).OAuthScopes | Should -Contain "$graph/User.Read"
    }
    It 'rejects unpublished scopes' {
        $planArgs = $base.Clone(); $planArgs.Scope = @('Directory.Read.All')
        { New-TokenForgeRequest @planArgs } | Should -Throw '*does not publish*'
    }
    It 'rejects an unlisted callback and a mismatched resource URI' {
        $planArgs = $base.Clone(); $planArgs.RedirectUri = 'https://unlisted.test/'
        { New-TokenForgeRequest @planArgs } | Should -Throw '*not published*'
        { New-TokenForgeRequest @base -ResourceUri 'https://other.test' } | Should -Throw '*must map*'
    }
    It 'rejects mixed resource and default scope inputs' {
        foreach ($scope in @('.default','https://graph.microsoft.com/User.Read','openid','offline_access','User.Read Mail.Read')) {
            $planArgs = $base.Clone(); $planArgs.Scope = @($scope)
            { New-TokenForgeRequest @planArgs } | Should -Throw '*explicit delegated*'
        }
    }
    It 'rejects tenant path injection' {
        { New-TokenForgeRequest @base -Tenant '../evil' } | Should -Throw '*Invalid tenant*'
    }
    It 'supports native callbacks without treating them as SPA callbacks' {
        $planArgs = $base.Clone(); $planArgs.RedirectUri = 'native-test://callback'
        (New-TokenForgeRequest @planArgs).Spa | Should -BeFalse
        { New-TokenForgeRequest @planArgs -Spa } | Should -Throw '*HTTPS*'
    }
    It 'rejects malformed catalogs' {
        '{"apps":[]}' | Set-Content "$TestDrive/bad.json"
        { Get-TokenForgeCatalog -Path "$TestDrive/bad.json" } | Should -Throw '*apps object*'
    }
    It 'validates a download before replacing the previous catalog' {
        Copy-Item "$PSScriptRoot/fixtures/catalog.json" "$TestDrive/catalog.json"
        $before = Get-FileHash "$TestDrive/catalog.json"
        Mock Invoke-RestMethod -ModuleName TokenForge { @{ apps = @() } }
        { Update-TokenForgeCatalog -Path "$TestDrive/catalog.json" } | Should -Throw '*apps object*'
        (Get-FileHash "$TestDrive/catalog.json").Hash | Should -Be $before.Hash
    }
}

Describe 'Offline identity protocol' {
    BeforeEach {
        $plan = New-TokenForgeRequest @base -ResourceUri 'https://graph.microsoft.com'
        $secret = ConvertTo-SecureString 'synthetic-secret' -AsPlainText -Force
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge {
            param($Client, $Uri, $Form, $Origin)
            if ($Uri.AbsolutePath.EndsWith('/authorize')) {
                $query = [System.Web.HttpUtility]::ParseQueryString($Uri.Query)
                $query['prompt'] | Should -Be none
                $query['code_challenge_method'] | Should -Be S256
                $query['code_challenge'] | Should -Match '^[a-zA-Z0-9_-]{43}$'
                $Client | Should -Not -BeNullOrEmpty
                $null = $Client.DefaultRequestHeaders.TryAddWithoutValidation('X-Test-Challenge', $query['code_challenge'])
                return @{ Status = 302; Location = "https://example.test/callback?code=synthetic-code&state=$($query['state'])"; Content = '' }
            }
            $Form.client_id | Should -Be '11111111-1111-1111-1111-111111111111'
            $Form.scope | Should -Be 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read'
            if ($Form.grant_type -eq 'refresh_token') { $Form.refresh_token | Should -Be 'synthetic-secret' }
            if ($Form.grant_type -eq 'authorization_code') {
                $Form.code | Should -Be synthetic-code
                $Form.code_verifier | Should -Match '^[a-zA-Z0-9_-]{43}$'
                $actualChallenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($Form.code_verifier))).TrimEnd('=').Replace('+','-').Replace('/','_')
                @($Client.DefaultRequestHeaders.GetValues('X-Test-Challenge'))[0] | Should -BeExactly $actualChallenge
            }
            return @{ Status = 200; Content = '{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","scope":"User.Read Mail.Read","expires_in":3600}' }
        }
    }
    It 'acquires cookie tokens and returns secure strings' {
        $result = Get-TokenForgeToken -Request $plan -EstsAuth $secret
        $result.AccessToken | Should -BeOfType securestring
        $result.RefreshToken | Should -BeOfType securestring
        $result.ScopeEvidence | Should -Be TokenResponse
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 2
    }
    It 'redeems a refresh token without an authorize request' {
        $result = Get-TokenForgeToken -Request $plan -RefreshToken $secret
        $result.GrantedScopes | Should -Contain User.Read
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 1 -ParameterFilter { $Uri.AbsolutePath.EndsWith('/token') }
    }
    It 'does not echo malformed expiry response contents through numeric conversion errors' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{Status=200;Content='{"access_token":"synthetic-access","token_type":"Bearer","scope":"User.Read Mail.Read","expires_in":"private-expiry-value"}'} }
        $result=Get-TokenForgeToken -Request $plan -RefreshToken $secret
        $result.ExpiresAt | Should -BeNullOrEmpty
        ($result|ConvertTo-Json -Depth 10) | Should -Not -Match 'private-expiry-value'
        $result.AccessToken.Dispose()
    }
    It 'sets Origin only for explicitly selected SPA requests' {
        $plan.Spa = $true
        $null = Get-TokenForgeToken -Request $plan -RefreshToken $secret
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 1 -ParameterFilter { $Origin -eq 'https://example.test' }
    }
    It 'rejects state mismatch before exchanging any code' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 302; Location = 'https://example.test/callback?code=secret-code&state=wrong'; Content = '' } }
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*state mismatch*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 1
    }
    It 'rejects missing callback state' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 302; Location = 'https://example.test/callback?code=secret-code'; Content = '' } }
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*state mismatch*'
    }
    It 'rejects an external redirect before making another request' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 302; Location = 'https://login.microsoftonline.com.evil.test/path?code=secret-code'; Content = '' } }
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*outside*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 1
    }
    It 'stops at browser interrupts without echoing HTML' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Location = $null; Content = '<html>synthetic-secret</html>' } }
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*browser interaction*'
    }
    It 'bounds redirect loops' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 302; Location = '/loop'; Content = '' } }
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*redirect limit*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Exactly -Times 10
    }
    It 'suppresses token endpoint error contents' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 400; Content = 'synthetic-secret' } }
        { Get-TokenForgeToken -Request $plan -RefreshToken $secret } | Should -Throw '*HTTP 400*details suppressed*'
    }
    It 'rejects partial scope issuance' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Content = '{"access_token":"synthetic-access","token_type":"Bearer","scope":"User.Read"}' } }
        { Get-TokenForgeToken -Request $plan -RefreshToken $secret } | Should -Throw '*missing one or more*'
    }
    It 'marks omitted response scopes as unverified' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Content = '{"access_token":"synthetic-access","token_type":"Bearer"}' } }
        (Get-TokenForgeToken -Request $plan -RefreshToken $secret -WarningAction SilentlyContinue).ScopeEvidence | Should -Be Unverified
    }
    It 'reports additional API scopes without treating OIDC scopes as extra API permissions' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Content = '{"access_token":"synthetic-access","token_type":"Bearer","scope":"User.Read Mail.Read Directory.Read.All openid profile email"}' } }
        $result = Get-TokenForgeToken -Request $plan -RefreshToken $secret -WarningVariable notices -WarningAction SilentlyContinue
        $result.AdditionalScopes | Should -Be @('Directory.Read.All')
        $notices | Should -Match '1 additional API scopes'
    }
    It 'recognizes fully qualified scopes when calculating additional permissions' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Content = '{"access_token":"synthetic-access","token_type":"Bearer","scope":"https://graph.microsoft.com/User.Read https://graph.microsoft.com/Mail.Read"}' } }
        (Get-TokenForgeToken -Request $plan -RefreshToken $secret).AdditionalScopes.Count | Should -Be 0
    }
    It 'identifies a server-rejected published redirect without echoing HTML' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 200; Location = $null; Content = '<html>AADSTS50011: rejected synthetic-secret and user@example.test</html>' } }
        try { Get-TokenForgeToken -Request $plan -EstsAuth $secret; throw 'NoFailure' } catch {
            $_.Exception.Message | Should -Match 'AADSTS50011.*Entra rejected the redirect URI'
            $_.Exception.Message | Should -Not -Match 'synthetic-secret|user@example.test'
        }
    }
    It 'retains numeric token-endpoint failure codes without identity response contents' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 400; Content = '{"error_description":"AADSTS65001: synthetic-secret user@example.test"}' } }
        try { Get-TokenForgeToken -Request $plan -RefreshToken $secret; throw 'NoFailure' } catch {
            $_.Exception.Message | Should -Match 'HTTP 400.*AADSTS65001'
            $_.Exception.Message | Should -Not -Match 'synthetic-secret|user@example.test'
        }
    }
    It 'rejects tampered plans before any request' {
        $plan.OAuthScopes = @('https://other.test/.default')
        { Get-TokenForgeToken -Request $plan -RefreshToken $secret } | Should -Throw '*do not match*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 0
    }
}

Describe 'HTTP transport' {
    BeforeAll {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class TokenForgeFixtureHandler : HttpMessageHandler {
    public string Body;
    public string Origin;
    public string Method;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
        Method = request.Method.Method;
        Body = request.Content == null ? null : await request.Content.ReadAsStringAsync();
        Origin = request.Headers.Contains("Origin") ? String.Join("", request.Headers.GetValues("Origin")) : null;
        var response = new HttpResponseMessage(HttpStatusCode.Found);
        response.Headers.Location = new Uri("https://example.test/callback?code=synthetic");
        response.Content = new StringContent("synthetic-content");
        return response;
    }
}
'@
    }
    It 'encodes form values and returns the redirect without following it' {
        $handler = [TokenForgeFixtureHandler]::new()
        $client = [Net.Http.HttpClient]::new($handler)
        try {
            $response = & (Get-Module TokenForge) {
                param($testClient)
                Invoke-TokenForgeHttp -Client $testClient -Uri 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' -Form @{ code = 'a+b&c'; scope = 'User.Read Mail.Read' } -Origin 'https://example.test'
            } $client
            $handler.Method | Should -Be POST
            $handler.Origin | Should -Be 'https://example.test'
            $decoded = [System.Web.HttpUtility]::ParseQueryString($handler.Body)
            $decoded['code'] | Should -BeExactly 'a+b&c'
            $decoded['scope'] | Should -BeExactly 'User.Read Mail.Read'
            $response.Status | Should -Be 302
            $response.Location | Should -Be 'https://example.test/callback?code=synthetic'
            $response.Content | Should -Be synthetic-content
        } finally { $client.Dispose() }
    }
}
