BeforeAll {
    Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
    $graph = '00000003-0000-0000-c000-000000000000'
    $clientId = '11111111-1111-1111-1111-111111111111'
    $owner = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    $catalog = Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
    function New-TestJwt {
        param([hashtable]$Payload)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
        ConvertTo-SecureString "e30.$encoded.c3ludGhldGlj" -AsPlainText -Force
    }
    function New-TestObservation {
        param([string]$Client = '11111111-1111-1111-1111-111111111111', [string[]]$Scopes = @('User.Read'), [string]$Outcome = 'Succeeded', [string]$Time = ([DateTimeOffset]::UtcNow.ToString('o')))
        [pscustomobject]@{ ClientId = $Client; ResourceId = '00000003-0000-0000-c000-000000000000'; Outcome = $Outcome; ObservedAt = $Time; TenantFingerprint = ('a'*64); PrincipalFingerprint = ('b'*64); ScpScopes = $Scopes; ResponseScopes = $Scopes; SignatureValidated = $false; NamespaceVerification = 'Matched'; RequestVerification = 'Matched' }
    }
}

Describe 'Claims inspection and discovery requests' {
    It 'extracts scp while omitting identity claims and never asserting signature validation' {
        $jwt = New-TestJwt @{ scp = 'User.Read Mail.Read'; tid = 'private-tenant'; oid = 'private-user'; name = 'private-name'; aud = $graph; appid = $clientId; exp = [DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds() }
        $claims = Get-TokenForgeTokenClaims -AccessToken $jwt
        $claims.Readable | Should -BeTrue
        $claims.Scopes.Count | Should -Be 2
        $claims.ClientId | Should -Be $clientId
        $claims.SignatureValidated | Should -BeFalse
        ($claims | ConvertTo-Json) | Should -Not -Match 'private-tenant|private-user|private-name'
    }
    It 'handles opaque and malformed tokens without echoing their contents' {
        foreach ($text in @('private-secret','a.invalid!.c','a.e30.c')) {
            $claims = Get-TokenForgeTokenClaims -AccessToken (ConvertTo-SecureString $text -AsPlainText -Force)
            $claims.SignatureValidated | Should -BeFalse
            $claims.Scopes.Count | Should -Be 0
        }
    }
    It 'requires registered ownership-verified applications for default-scope discovery' {
        $app = [pscustomobject]@{ AppId = $clientId; Registration = 'Missing'; Ownership = 'PublishedMicrosoftOwner'; RedirectUris = @('https://example.test/callback') }
        { New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://example.test/callback } | Should -Throw '*registered*'
        $app.Registration = 'Present'; $app.Ownership = 'VerifiedMicrosoftOwner'
        $plan = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://example.test/callback -Spa
        $plan.Discovery | Should -BeTrue
        $plan.OAuthScopes | Should -Contain "$graph/.default"
        $plan.Scopes.Count | Should -Be 0
    }
    It 'rejects an unpublished callback even in discovery mode' {
        $app = [pscustomobject]@{ AppId = $clientId; Registration = 'Present'; Ownership = 'VerifiedMicrosoftOwner'; RedirectUris = @('https://example.test/callback') }
        { New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://evil.test } | Should -Throw '*not present*'
    }
}

Describe 'Source aggregation' {
    It 'unions candidates, preserves scope evidence, and distinguishes published ownership' {
        $apps = @([pscustomobject]@{ AppId = $clientId; AppDisplayName = 'Other name'; AppOwnerOrganizationId = $owner; Source = 'Graph' }, [pscustomobject]@{ AppId = '33333333-3333-3333-3333-333333333333'; AppDisplayName = 'New candidate'; AppOwnerOrganizationId = ''; Source = 'EntraDocs' })
        $resources = @([pscustomobject]@{ resourceId = $graph; displayName = 'Microsoft Graph' })
        $discovery = Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps $apps -Resources $resources
        $discovery.Applications.Count | Should -Be 4
        $app = $discovery.Applications | Where-Object AppId -eq $clientId
        $app.Ownership | Should -Be PublishedMicrosoftOwner
        $app.Grants.Count | Should -Be 1
        $app.Sources.Count | Should -Be 2
        ($discovery.Applications | Where-Object AppId -eq $graph).IsResourceCandidate | Should -BeTrue
    }
    It 'retains resource-only catalog edges with a published source and identifier URI' {
        $discovery = Get-TokenForgeDiscovery -Catalog $catalog
        $resource = @($discovery.Applications | Where-Object AppId -eq $graph)
        $resource.Count | Should -Be 1
        $resource[0].IsResourceCandidate | Should -BeTrue
        $resource[0].Ownership | Should -Be Unverified
        $resource[0].Sources.Evidence | Should -Contain PublishedResource
        $resource[0].IdentifierUris | Should -Contain 'https://graph.microsoft.com'
    }
    It 'counts invalid source records without discarding valid candidates' {
        $apps = @([pscustomobject]@{ AppId = 'not-an-id'; AppDisplayName = 'Invalid'; AppOwnerOrganizationId = ''; Source = 'Graph' })
        $discovery = Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps $apps
        $discovery.Applications.Count | Should -Be 3
        $discovery.InvalidSourceRecordCount | Should -Be 1
    }
}

Describe 'Graph paging and network boundary' {
    It 'collects every page' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge {
            param($AccessToken,$Uri)
            if ($Uri.Query -eq '?page=2') { return @{ value = @(@{ appId = 'second' }) } }
            @{ value = @(@{ appId = 'first' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals?page=2' }
        }
        $items = & (Get-Module TokenForge) { Get-TokenForgeGraphCollection -AccessToken (ConvertTo-SecureString synthetic -AsPlainText -Force) -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' }
        $items.Count | Should -Be 2
    }
    It 'fails closed on pagination loops' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals' } }
        { & (Get-Module TokenForge) { Get-TokenForgeGraphCollection -AccessToken (ConvertTo-SecureString synthetic -AsPlainText -Force) -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' } } | Should -Throw '*loop*'
    }
    It 'rejects malicious host, scheme and path before sending a credential' {
        foreach ($uri in @('https://evil.test/v1.0/me','http://graph.microsoft.com/v1.0/me','https://graph.microsoft.com:444/v1.0/me','https://graph.microsoft.com/other','https://user@graph.microsoft.com/v1.0/me')) {
            { & (Get-Module TokenForge) { param($address) Invoke-TokenForgeGraph -AccessToken (ConvertTo-SecureString synthetic -AsPlainText -Force) -Uri $address } $uri } | Should -Throw '*boundary*'
        }
    }
    It 'fails rather than returning a partial page-limited inventory' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{ value = @(@{ appId = 'first' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals?page=2' } }
        { & (Get-Module TokenForge) { Get-TokenForgeGraphCollection -AccessToken (ConvertTo-SecureString synthetic -AsPlainText -Force) -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -MaxPages 1 } } | Should -Throw '*page limit*'
    }
}

Describe 'Tenant inventory' {
    BeforeEach {
        $discovery = Get-TokenForgeDiscovery -Catalog $catalog
        $jwt = New-TestJwt @{ tid = 'synthetic-tenant'; oid = 'synthetic-user' }
        Mock Get-TokenForgeGraphCollection -ModuleName TokenForge {
            param($AccessToken,$Uri)
            if ($Uri.AbsolutePath -eq '/v1.0/oauth2PermissionGrants') { return ,@(@{ clientId = 'private-client-object'; resourceId = 'private-resource-object'; principalId = 'synthetic-user'; consentType = 'Principal'; scope = 'User.Read' }) }
            return ,@(
                @{ id = 'private-client-object'; displayName='Tenant fixture';servicePrincipalType='Application';preferredSingleSignOnMode='oidc';loginUrl='https://example.test/login';logoutUrl='https://example.test/logout';homepage='https://example.test';appId = '11111111-1111-1111-1111-111111111111'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; accountEnabled = $true; replyUrls = @('https://example.test/callback'); oauth2PermissionScopes = @(); appRoles = @(); servicePrincipalNames = @(); appRoleAssignmentRequired = $false; signInAudience = 'AzureADMultipleOrgs' },
                @{ id = 'private-resource-object'; appId = '00000003-0000-0000-c000-000000000000'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; accountEnabled = $true; replyUrls = @(); oauth2PermissionScopes = @(@{ value = 'User.Read'; isEnabled = $true; type = 'User' }); appRoles = @(); servicePrincipalNames = @(); appRoleAssignmentRequired = $false; signInAudience = 'AzureADMultipleOrgs' }
            )
        }
    }
    It 'verifies owner and keeps configured grants distinct from published scopes' {
        $inventory = Get-TokenForgeTenantInventory -GraphToken $jwt -Discovery $discovery
        $inventory.VerifiedMicrosoftServicePrincipalCount | Should -Be 2
        $inventory.GrantEnumeration | Should -Be Complete
        $inventory.TenantGrants[0].AppliesToCurrentPrincipal | Should -BeTrue
        $inventory.TenantGrants[0].Evidence | Should -Be TenantConfiguredGrant
        $app = $inventory.Applications | Where-Object AppId -eq $clientId
        $app.Registration | Should -Be Present
        $app.Ownership | Should -Be VerifiedMicrosoftOwner
        $app.Name | Should -Be 'Tenant fixture'
        $app.PreferredSingleSignOnMode | Should -Be oidc
        $app.ServicePrincipalType | Should -Be Application
        $app.LoginUrl | Should -Be 'https://example.test/login'
        ($inventory | ConvertTo-Json -Depth 30) | Should -Not -Match 'synthetic-tenant|synthetic-user|private-client-object|private-resource-object'
    }
    It 'does not describe failed grant enumeration as an absence of grants' {
        Mock Get-TokenForgeGraphCollection -ModuleName TokenForge { throw 'Graph request failed (HTTP 403)' } -ParameterFilter { $Uri.AbsolutePath -eq '/v1.0/oauth2PermissionGrants' }
        (Get-TokenForgeTenantInventory -GraphToken $jwt -Discovery $discovery).GrantEnumeration | Should -Be Forbidden
    }
}

Describe 'Service principal registration' {
    BeforeEach {
        $secret = ConvertTo-SecureString synthetic -AsPlainText -Force
        Mock Get-TokenForgeTokenClaims -ModuleName TokenForge { [pscustomobject]@{TenantFingerprint=('a'*64)} }
        $app = [pscustomobject]@{ AppId = $clientId; OwnerTenantId = $owner; Ownership = 'PublishedMicrosoftOwner' }
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge {
            param($AccessToken,$Uri,$Method,$Body)
            if ($Method -eq 'POST') { return @{ id = '33333333-3333-3333-3333-333333333333'; appId = '11111111-1111-1111-1111-111111111111'; appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' } }
            return $null
        }
    }
    It 'checkpoints an expired Graph session before stopping registration' {
        $app | Add-Member Registration Missing
        $inventory = [pscustomobject]@{ Applications=@($app);TenantFingerprint=('a'*64) }
        Mock Register-TokenForgeApplication -ModuleName TokenForge { throw 'Graph request failed (HTTP 401); details suppressed.' }
        { Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath "$TestDrive/expired.json" -DelayMilliseconds 0 -Confirm:$false } | Should -Throw '*stopped*401*'
        (Get-TokenForgeScopeDatabase -Path "$TestDrive/expired.json").RegistrationAttempts.Count | Should -Be 1
        (Get-TokenForgeScopeDatabase -Path "$TestDrive/expired.json").RegistrationAttempts[0].HttpStatus | Should -Be 401
    }
    It 'continues bounded registration batches after checkpointed candidates' {
        $app | Add-Member Registration Missing
        $second=$app.PSObject.Copy();$second.AppId='22222222-2222-2222-2222-222222222222'
        $inventory=[pscustomobject]@{Applications=@($app,$second);TenantFingerprint=('a'*64)}
        Mock Register-TokenForgeApplication -ModuleName TokenForge { [pscustomobject]@{Outcome='Created'} }
        $path="$TestDrive/register-bounded.json"
        @(Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath $path -MaxApplications 1 -DelayMilliseconds 0 -Confirm:$false).Count | Should -Be 1
        @(Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath $path -MaxApplications 1 -DelayMilliseconds 0 -Confirm:$false).Count | Should -Be 1
        (Get-TokenForgeScopeDatabase -Path $path).RegistrationAttempts.Count | Should -Be 2
    }
    It 'creates only the application service principal without granting consent' {
        (Register-TokenForgeApplication -GraphToken $secret -Application $app -Confirm:$false).Outcome | Should -Be Created
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Body.Count -eq 1 -and $Body.ContainsKey('appId') -and $Uri.AbsolutePath -eq '/v1.0/servicePrincipals' }
    }
    It 'can explicitly resolve a resource-only published candidate and still verifies its owner' {
        $app.OwnerTenantId=$null;$app.Ownership='Unverified'
        $app | Add-Member Sources @([pscustomobject]@{Evidence='PublishedResource'})
        { Register-TokenForgeApplication -GraphToken $secret -Application $app -Confirm:$false } | Should -Throw '*published*'
        (Register-TokenForgeApplication -GraphToken $secret -Application $app -ResolvePublishedCandidate -Confirm:$false).Outcome | Should -Be Created
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter {$Method -eq 'POST'}
    }
    It 'honors WhatIf' {
        Register-TokenForgeApplication -GraphToken $secret -Application $app -WhatIf | Out-Null
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }
    It 'does not change an existing verified application' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{ appOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' } }
        (Register-TokenForgeApplication -GraphToken $secret -Application $app).Outcome | Should -Be AlreadyPresent
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }
    It 'rejects a display-name-only candidate' {
        $app.Ownership = 'Unverified'; $app.OwnerTenantId = $null
        { Register-TokenForgeApplication -GraphToken $secret -Application $app -Confirm:$false } | Should -Throw '*ownership evidence*'
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }
    It 'rejects an existing principal with non-Microsoft ownership' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{ appOwnerOrganizationId = '44444444-4444-4444-4444-444444444444' } }
        { Register-TokenForgeApplication -GraphToken $secret -Application $app } | Should -Throw '*not verified*'
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter { $Method -eq 'POST' }
    }
    It 'checkpoints a cleanup failure and stops instead of claiming a rejected principal was removed' {
        $app | Add-Member Registration Missing
        $inventory=[pscustomobject]@{Applications=@($app);TenantFingerprint=('a'*64)}
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{id='33333333-3333-3333-3333-333333333333';appId='11111111-1111-1111-1111-111111111111';appOwnerOrganizationId='44444444-4444-4444-4444-444444444444'} } -ParameterFilter {$Method -eq 'POST'}
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { throw 'Graph request failed (HTTP 403)' } -ParameterFilter {$Method -eq 'DELETE'}
        $path="$TestDrive/cleanup.json"
        { Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath $path -DelayMilliseconds 0 -Confirm:$false } | Should -Throw '*cleanup*'
        $attempts=(Get-TokenForgeScopeDatabase -Path $path).RegistrationAttempts
        $attempts.Count | Should -Be 1
        $attempts[0].Outcome | Should -Be CleanupRequired
        $attempts[0].AppId | Should -Be $clientId
        (Get-Content $path -Raw) | Should -Not -Match '33333333-3333-3333-3333-333333333333|44444444-4444-4444-4444-444444444444'
        { Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath $path -DelayMilliseconds 0 -Confirm:$false } | Should -Throw '*unresolved*'
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter {$Method -eq 'POST'}
    }
    It 'removes only a just-created candidate that fails ownership verification' {
        Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{ id = '33333333-3333-3333-3333-333333333333'; appId = '11111111-1111-1111-1111-111111111111'; appOwnerOrganizationId = '44444444-4444-4444-4444-444444444444' } } -ParameterFilter { $Method -eq 'POST' }
        { Register-TokenForgeApplication -GraphToken $secret -Application $app -Confirm:$false } | Should -Throw '*was removed*'
        Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter { $Method -eq 'DELETE' -and $Uri.AbsolutePath -eq '/v1.0/servicePrincipals/33333333-3333-3333-3333-333333333333' }
    }
}

Describe 'Scope database and assessment selection' {
    It 'whitelists evidence fields and drops secret and identity material' {
        $observation = New-TestObservation
        $observation | Add-Member AccessToken 'private-secret'
        $observation | Add-Member Identity 'private-person'
        $db = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $observation -Path "$TestDrive/db.json"
        $text = Get-Content "$TestDrive/db.json" -Raw
        $text | Should -Not -Match 'private-secret|private-person|AccessToken|Identity'
        (Get-TokenForgeScopeDatabase -Path "$TestDrive/db.json").Observations.Count | Should -Be 1
        if (-not $IsWindows) { ([int][IO.File]::GetUnixFileMode("$TestDrive/db.json") -band 63) | Should -Be 0 }
    }
    It 'rejects raw identity values in fingerprint fields' {
        $observation = New-TestObservation; $observation.TenantFingerprint = 'private-tenant'
        { Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $observation } | Should -Throw '*fingerprints*'
    }
    It 'ranks the smallest observed scope set satisfying a test before broader clients' {
        $db = New-TokenForgeScopeDatabase
        $db = Add-TokenForgeScopeObservation -Database $db -Observation (New-TestObservation -Scopes @('User.Read','Mail.Read','openid'))
        $db = Add-TokenForgeScopeObservation -Database $db -Observation (New-TestObservation -Client '22222222-2222-2222-2222-222222222222' -Scopes @('User.Read','Mail.Read','Directory.Read.All'))
        $coverage = @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read,Mail.Read -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64))
        $coverage[0].ClientId | Should -Be $clientId
        $coverage[0].AdditionalScopeCount | Should -Be 0
        $coverage[1].AdditionalScopeCount | Should -Be 1
    }
    It 'does not reuse other tenant evidence or stale successful observations' {
        $db = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation (New-TestObservation -Time ([DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')))
        @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read -TenantFingerprint ('c'*64) -PrincipalFingerprint ('b'*64)).Count | Should -Be 0
        @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Count | Should -Be 0
    }
    It 'does not select legacy or unverified token namespaces for assessments' {
        $observation=New-TestObservation
        $observation.NamespaceVerification='Unverifiable'
        $db=Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $observation
        @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Count | Should -Be 0
        $db.Observations[0].PSObject.Properties.Remove('NamespaceVerification')
        @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Count | Should -Be 0
    }
    It 'does not report scopes removed when the latest probe fails' {
        $old = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation (New-TestObservation)
        $new = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation (New-TestObservation -Outcome Failed -Scopes @())
        $diff = @(Compare-TokenForgeScopeDatabase -Before $old -After $new)
        $diff.Count | Should -Be 1
        $diff[0].RemovedScopes.Count | Should -Be 0
        $diff[0].AfterOutcome | Should -Be Failed
    }
    It 'exports scope evidence without tenant or user fingerprints' {
        $db = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation (New-TestObservation)
        Export-TokenForgeScopeDatabase -Database $db -Path "$TestDrive/public.json"
        $text = Get-Content "$TestDrive/public.json" -Raw
        $text | Should -Not -Match 'TenantFingerprint|PrincipalFingerprint|aaaaaaa|bbbbbbb'
        $text | Should -Match 'AnonymousTenantTokenObservation'
    }
}

Describe 'Resumable probe and matrix planning' {
    BeforeEach {
        $probeRoot=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
        $null=New-Item -ItemType Directory $probeRoot
        if(-not $IsWindows){[IO.File]::SetUnixFileMode($probeRoot,[IO.UnixFileMode]448)}
        $app = [pscustomobject]@{ AppId = $clientId; Name = 'Fixture'; Registration = 'Present'; Ownership = 'VerifiedMicrosoftOwner'; AccountEnabled = $true; RedirectUris = @('https://example.test/callback'); PreferredRedirectUri = 'https://example.test/callback'; PublishedGrants = @([pscustomobject]@{ ResourceId = $graph; Scopes = @('User.Read') }); DelegatedScopeDefinitions = @(); PublicClient = $true; Foci = $false; Sources = @(); OwnerTenantId = $owner }
        $inventory = [pscustomobject]@{ Applications = @($app); TenantGrants = @(); TenantFingerprint = ('a'*64); PrincipalFingerprint = ('b'*64); DiscoveryCatalogHash = ('c'*64) }
        $secret = ConvertTo-SecureString synthetic -AsPlainText -Force
        Mock Get-TokenForgeToken -ModuleName TokenForge {
            param($Request)
            [pscustomobject]@{ AccessToken = ConvertTo-SecureString 'private-access' -AsPlainText -Force; RefreshToken = ConvertTo-SecureString 'private-refresh' -AsPlainText -Force; GrantedScopes = @('User.Read'); TokenClaims = [pscustomobject]@{ Readable = $true; HasDelegatedScopeClaim = $true; Scopes = @('User.Read'); TenantFingerprint=('a'*64); PrincipalFingerprint=('b'*64); Audience=$Request.ResourceId; ClientId=$Request.ClientId } }
        }
    }
    It 'deduplicates Graph and published edges without inventing client consent' {
        $plan = @(Get-TokenForgeProbePlan -Inventory $inventory)
        $plan.Count | Should -Be 1
        $plan[0].Sources | Should -Contain GraphDiscovery
        $plan[0].Sources | Should -Contain PublishedScopeEdge
    }
    It 'plans principal grants for an explicitly selected assessment user instead of the inventory administrator' {
        $inventory.TenantGrants=@(
            [pscustomobject]@{ClientId=$clientId;ResourceId='33333333-3333-3333-3333-333333333333';ConsentType='Principal';PrincipalFingerprint=('b'*64);AppliesToCurrentPrincipal=$true},
            [pscustomobject]@{ClientId=$clientId;ResourceId='44444444-4444-4444-4444-444444444444';ConsentType='Principal';PrincipalFingerprint=('d'*64);AppliesToCurrentPrincipal=$false}
        )
        $plan=@(Get-TokenForgeProbePlan -Inventory $inventory -PrincipalFingerprint ('d'*64))
        $plan.ResourceId | Should -Contain '44444444-4444-4444-4444-444444444444'
        $plan.ResourceId | Should -Not -Contain '33333333-3333-3333-3333-333333333333'
    }
    It 'attributes a different authorized probe user only after matching the explicit fingerprint' {
        Mock Get-TokenForgeToken -ModuleName TokenForge {
            param($Request)
            [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('d'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
        }
        $result=Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -PrincipalFingerprint ('d'*64) -DatabasePath "$probeRoot/observer.json" -DelayMilliseconds 0
        $result.Outcome | Should -Be Succeeded
        $result.PrincipalFingerprint | Should -Be ('d'*64)
        $result.NamespaceVerification | Should -Be Matched
    }
    It 'forwards persistent ESTS cookie names to every protocol request' {
        $null=Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -CookieName ESTSAUTHPERSISTENT -ResourceId $graph -DatabasePath "$probeRoot/persistent.json" -DelayMilliseconds 0
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Exactly -Times 1 -ParameterFilter {$CookieName -eq 'ESTSAUTHPERSISTENT'}
    }
    It 'checkpoints scope claims but no credentials, and resumes without another request' {
        $path = "$probeRoot/probes.json"
        $first = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0)
        $first.Count | Should -Be 1
        $first[0].Outcome | Should -Be Succeeded
        (Get-Content $path -Raw) | Should -Not -Match 'private-access|private-refresh|AccessToken|RefreshToken'
        @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0).Count | Should -Be 0
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Exactly -Times 1
    }
    It 'probes only the supplied matrix edges' {
        $plan = @([pscustomobject]@{ ClientId = $clientId; ResourceId = $graph })
        @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -Plan $plan -DatabasePath "$probeRoot/matrix.json" -DelayMilliseconds 0).Count | Should -Be 1
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Exactly -Times 1
    }
    It 'continues through multiple clients without replacing the matrix parameter' {
        $second = $app.PSObject.Copy()
        $second.AppId = '22222222-2222-2222-2222-222222222222'
        $inventory.Applications += $second
        $plan = @($inventory.Applications | ForEach-Object { [pscustomobject]@{ClientId=$_.AppId;ResourceId=$graph} })
        $results = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -Plan $plan -DatabasePath "$probeRoot/multi.json" -DelayMilliseconds 0)
        $results.Count | Should -Be 2
        @($results | Where-Object Outcome -eq Succeeded).Count | Should -Be 2
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Exactly -Times 2
    }
    It 'resumes bounded batches beyond previously completed clients' {
        $second = $app.PSObject.Copy()
        $second.AppId = '22222222-2222-2222-2222-222222222222'
        $inventory.Applications += $second
        $path = "$probeRoot/bounded.json"
        $first = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0 -MaxApplications 1)
        $next = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0 -MaxApplications 1)
        $first.Count | Should -Be 1
        $next.Count | Should -Be 1
        $next[0].ClientId | Should -Not -Be $first[0].ClientId
        (Get-TokenForgeScopeDatabase -Path $path).Observations.Count | Should -Be 2
    }
    It 'rejects cookie tokens from a different inventory principal without retaining their scopes' {
        Mock Get-TokenForgeToken -ModuleName TokenForge {
            [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('d'*64)}}
        }
        $result=Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/context.json" -DelayMilliseconds 0
        $result.Outcome | Should -Be ContextMismatch
        $result.NamespaceVerification | Should -Be Mismatch
        $result.ScpScopes.Count | Should -Be 0
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Exactly -Times 1
    }
    It 'does not label another resource token as the requested API' {
        Mock Get-TokenForgeToken -ModuleName TokenForge {
            [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$clientId;Audience='https://other-api.test'}}
        }
        $result=Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/audience.json" -DelayMilliseconds 0
        $result.Outcome | Should -Be ContextMismatch
        $result.RequestVerification | Should -Be Mismatch
        $result.ScpScopes.Count | Should -Be 0
    }
    It 'records opaque token evidence without claiming verified scp' {
        Mock Get-TokenForgeToken -ModuleName TokenForge { [pscustomobject]@{ AccessToken = ConvertTo-SecureString synthetic -AsPlainText -Force; RefreshToken = $null; GrantedScopes = @('User.Read'); TokenClaims = [pscustomobject]@{ Readable = $false; HasDelegatedScopeClaim = $false; Scopes = @() } } }
        $result = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/opaque.json" -DelayMilliseconds 0)
        $result[0].Outcome | Should -Be OpaqueToken
    }
    It 'does not send credentials for an ownership mismatch or disabled client' {
        $app.Registration = 'OwnerMismatch'
        (Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/mismatch.json" -DelayMilliseconds 0).Outcome | Should -Be OwnerMismatch
        $app.Registration = 'Present'; $app.AccountEnabled = $false
        (Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/disabled.json" -DelayMilliseconds 0).Outcome | Should -Be Disabled
        Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
    }
    It 'stores numeric failure codes without exception contents' {
        Mock Get-TokenForgeToken -ModuleName TokenForge { throw 'AADSTS65001 private-access private-user' }
        $result = @(Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -ResourceId $graph -DatabasePath "$probeRoot/failure.json" -DelayMilliseconds 0 -MaxRedirects 1)
        $result[0].Outcome | Should -Be Failed
        $result[0].ErrorCodes | Should -Contain 65001
        (Get-Content "$probeRoot/failure.json" -Raw) | Should -Not -Match 'private-access|private-user'
    }
    It 'uses tenant scope definitions for explicit requests without inventing published grants' {
        $resource = [pscustomobject]@{ AppId = $graph; Registration = 'Present'; Ownership = 'VerifiedMicrosoftOwner'; DelegatedScopeDefinitions = @([pscustomobject]@{ Value = 'User.Read'; Enabled = $true },[pscustomobject]@{ Value = 'Mail.Read'; Enabled = $false }) }
        $inventory.Applications += $resource
        $plan = New-TokenForgeTenantRequest -Inventory $inventory -ClientId $clientId -ResourceId $graph -Scope User.Read -RedirectUri https://example.test/callback
        $plan.Evidence | Should -Be TenantResourceScopeDefinitionNotClientConsent
        { New-TokenForgeTenantRequest -Inventory $inventory -ClientId $clientId -ResourceId $graph -Scope Mail.Read -RedirectUri https://example.test/callback } | Should -Throw '*does not publish*'
    }
}

Describe 'Explicit requests from observed scope evidence' {
    BeforeEach {
        $app = [pscustomobject]@{ AppId=$clientId; Name='Fixture'; Registration='Present'; Ownership='VerifiedMicrosoftOwner'; PublicClient=$true; Foci=$false; RedirectUris=@('https://example.test/callback'); PreferredRedirectUri='https://example.test/callback' }
        $resource = [pscustomobject]@{ AppId=$graph; Registration='Present'; Ownership='VerifiedMicrosoftOwner'; DelegatedScopeDefinitions=@() }
        $inventory = [pscustomobject]@{ Applications=@($app,$resource); TenantFingerprint=('a'*64); PrincipalFingerprint=('b'*64); DiscoveryCatalogHash=('c'*64) }
        $observation = New-TestObservation -Scopes Private.Unlisted
        $db = Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $observation
        $arguments = @{ Inventory=$inventory; Database=$db; ClientId=$clientId; ResourceId=$graph; Scope=@('Private.Unlisted'); RedirectUri='https://example.test/callback' }
    }
    It 'plans an observed scope absent from definitions without treating discovery as explicit authorization' {
        $plan = New-TokenForgeTenantRequest @arguments
        $plan.Scopes | Should -Contain Private.Unlisted
        $plan.Source | Should -Be VerifiedPrivateScopeObservation
        $plan.Evidence | Should -Be MatchedObservedScpNotGuaranteedExplicitAuthorization
        $plan.ObservedAt | Should -Be $observation.ObservedAt
        $plan.ContentSha256 | Should -BeNullOrEmpty
        $plan.OAuthScopes | Should -Contain "$graph/Private.Unlisted"
        $plan.PSObject.Properties['Discovery'] | Should -BeNullOrEmpty
    }
    It 'does not extend observed coverage to an unobserved scope or different resource' {
        $arguments.Scope=@('Other.Unlisted')
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
        $arguments.Scope=@('Private.Unlisted'); $arguments.ResourceId=$clientId
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
    }
    It 'rejects stale observations and a later failed probe' {
        $db.Observations[0].ObservedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
        $db.Observations[0].ObservedAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
        $null=Add-TokenForgeScopeObservation -Database $db -Observation (New-TestObservation -Outcome Failed -Scopes @())
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
    }
    It 'rejects unverified request or namespace evidence' -ForEach @('RequestVerification','NamespaceVerification') {
        $db.Observations[0].$_='Unverifiable'
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
    }
    It 'selects another authorized observer only with an explicit matching fingerprint' {
        $db.Observations[0].PrincipalFingerprint=('d'*64)
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*No fresh*'
        $plan=New-TokenForgeTenantRequest @arguments -PrincipalFingerprint ('d'*64)
        $plan.Scopes | Should -Contain Private.Unlisted
    }
    It 'retains ownership and published redirect boundaries' {
        $arguments.RedirectUri='https://unpublished.test/callback'
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*redirect*'
        $arguments.RedirectUri='https://example.test/callback';$resource.Ownership='Unknown'
        { New-TokenForgeTenantRequest @arguments } | Should -Throw '*ownership-verified*'
    }
}

Describe 'Resource API boundary' {
    It 'rejects token/resource mismatch before contacting the API' {
        $token = [pscustomobject]@{ ResourceId = $graph; AccessToken = ConvertTo-SecureString synthetic -AsPlainText -Force }
        { Test-TokenForgeTokenAccess -Token $token -Uri https://management.azure.com/subscriptions } | Should -Throw '*boundary*'
        { Test-TokenForgeTokenAccess -Token $token -Uri https://graph.microsoft.com.evil.test/me } | Should -Throw '*boundary*'
    }
}

Describe 'Implicit discovery protocols' {
    BeforeEach {
        $app = [pscustomobject]@{ AppId = $clientId; Registration = 'Present'; Ownership = 'VerifiedMicrosoftOwner'; RedirectUris = @('https://example.test/callback') }
        $secret = ConvertTo-SecureString synthetic -AsPlainText -Force
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge {
            param($Client,$Uri,$Form)
            $query = [Web.HttpUtility]::ParseQueryString($Uri.Query)
            $query['response_type'] | Should -Be token
            $query['code_challenge'] | Should -BeNullOrEmpty
            $body = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"scp":"User.Read","aud":"00000003-0000-0000-c000-000000000000"}')).TrimEnd('=').Replace('+','-').Replace('/','_')
            @{ Status = 302; Location = "https://example.test/callback#access_token=e30.$body.c3ludGhldGlj&token_type=Bearer&expires_in=3600&state=$($query['state'])"; Content = '' }
        }
    }
    It 'captures v2 fragment tokens with state verification and no redemption request' {
        $plan = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://example.test/callback -Protocol OAuth2V2Implicit
        $token = Get-TokenForgeToken -Request $plan -EstsAuth $secret -WarningAction SilentlyContinue
        $token.TokenClaims.Scopes | Should -Contain User.Read
        $token.Protocol | Should -Be OAuth2V2Implicit
        $token.RefreshToken | Should -BeNullOrEmpty
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 1 -Exactly
    }
    It 'uses the v1 resource parameter rather than a v2 scope parameter' {
        $plan = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://example.test/callback -Protocol OAuth2V1Implicit
        $null = Get-TokenForgeToken -Request $plan -EstsAuth $secret -WarningAction SilentlyContinue
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 1 -ParameterFilter { $Uri.AbsolutePath -eq '/organizations/oauth2/authorize' -and $Uri.Query -match 'resource=' -and $Uri.Query -notmatch 'scope=' }
    }
    It 'rejects implicit state mismatch and never follows the callback' {
        Mock Invoke-TokenForgeHttp -ModuleName TokenForge { @{ Status = 302; Location = 'https://example.test/callback#access_token=private-token&token_type=Bearer&state=wrong'; Content = '' } }
        $plan = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $graph -RedirectUri https://example.test/callback -Protocol OAuth2V2Implicit
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*state mismatch*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 1 -Exactly
    }
    It 'does not allow an explicit assessment plan to silently switch to implicit discovery' {
        $plan = New-TokenForgeRequest -Catalog $catalog -ClientId $clientId -ResourceId $graph -Scope User.Read -RedirectUri https://example.test/callback
        $plan | Add-Member Protocol OAuth2V2Implicit
        { Get-TokenForgeToken -Request $plan -EstsAuth $secret } | Should -Throw '*only for explicit discovery*'
        Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 0
    }
}

Describe 'Independent checkpoint merging' {
    It 'deduplicates identical observations while preserving different principal namespaces' {
        $one=Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation (New-TestObservation)
        $different=New-TestObservation;$different.PrincipalFingerprint=('d'*64)
        $two=Add-TokenForgeScopeObservation -Database (New-TokenForgeScopeDatabase) -Observation $different
        $merged=Merge-TokenForgeScopeDatabase -Database $one,$one,$two -Path "$TestDrive/merged.json"
        $merged.Observations.Count | Should -Be 2
        @($merged.Observations.PrincipalFingerprint | Sort-Object -Unique).Count | Should -Be 2
    }
    It 'drops unapproved fields from registration history and preserves safe failure status' {
        $db=New-TokenForgeScopeDatabase
        $db.RegistrationAttempts=@([pscustomobject]@{AppId=$clientId;TenantFingerprint=('a'*64);AttemptedAt=[DateTimeOffset]::UtcNow.ToString('o');Outcome='Failed';HttpStatus=400;AccessToken='private-secret';ObjectId='private-object'})
        $merged=Merge-TokenForgeScopeDatabase -Database $db,$db
        $merged.RegistrationAttempts.Count | Should -Be 1
        $merged.RegistrationAttempts[0].HttpStatus | Should -Be 400
        ($merged|ConvertTo-Json -Depth 10) | Should -Not -Match 'private-secret|private-object|AccessToken|ObjectId'
    }
    It 'does not replace a target if a merge source contains invalid registration identity' {
        $path="$TestDrive/preserved.json";Set-Content $path 'preserved'
        $db=New-TokenForgeScopeDatabase
        $db.RegistrationAttempts=@([pscustomobject]@{AppId='private-secret';TenantFingerprint=('a'*64);AttemptedAt='invalid';Outcome='Failed'})
        { Merge-TokenForgeScopeDatabase -Database $db -Path $path } | Should -Throw '*identity*'
        (Get-Content $path -Raw).Trim() | Should -Be preserved
    }
}
