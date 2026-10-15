BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {
    Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
    $appId = '11111111-1111-1111-1111-111111111111'
    $owner = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

    function New-RoleOriginGraphToken {
        $payload = @{ tid = 'synthetic-tenant'; oid = 'synthetic-user' } | ConvertTo-Json -Compress
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
        ConvertTo-SecureString "e30.$encoded.c3ludGhldGlj" -AsPlainText -Force
    }

    function New-RoleOriginDiscovery {
        [pscustomobject]@{
            CatalogContentSha256 = 'a' * 64
            Applications = @([pscustomobject]@{
                AppId = $appId; Name = 'Synthetic app'; Sources = @()
                PublicClient = $false; Foci = $false; RedirectUris = @(); PreferredRedirectUri = ''
                Grants = @(); OwnerTenantId = $owner; Ownership = 'PublishedMicrosoftOwner'
                IdentifierUris = @(); IsResourceCandidate = $false
            })
        }
    }

    function New-RoleOriginGraphRole {
        param([string]$Value, [AllowNull()][string]$Origin)
        $role = @{
            id = '22222222-2222-2222-2222-222222222222'; value = $Value; displayName = $Value
            description = 'Synthetic role'; allowedMemberTypes = @('Application'); isEnabled = $true
        }
        if ($PSBoundParameters.ContainsKey('Origin')) { $role.origin = $Origin }
        $role
    }
}

Describe 'Graph application role origin' {
    It 'collects delegated scope definitions and classifies raw role origins exactly' {
        $graphToken = New-RoleOriginGraphToken
        $roles = @(
            (New-RoleOriginGraphRole -Value 'App.Role' -Origin 'Application')
            (New-RoleOriginGraphRole -Value 'ServicePrincipal.Role' -Origin 'ServicePrincipal')
            (New-RoleOriginGraphRole -Value 'Lowercase.Role' -Origin 'application')
            (New-RoleOriginGraphRole -Value 'Future.Role' -Origin 'FutureValue')
            (New-RoleOriginGraphRole -Value 'Missing.Role')
        )
        $servicePrincipal = @{
            id = '33333333-3333-3333-3333-333333333333'; appId = $appId
            appOwnerOrganizationId = $owner; displayName = 'Synthetic app'; servicePrincipalType = 'Application'
            oauth2PermissionScopes = @(@{
                id = '44444444-4444-4444-4444-444444444444'; value = 'Synthetic.Read'; isEnabled = $true; type = 'User'
                adminConsentDisplayName = 'Read synthetic data'; adminConsentDescription = 'Read fixture data'
                userConsentDisplayName = 'Read data'; userConsentDescription = 'Read fixture data'
            })
            appRoles = $roles; replyUrls = @(); servicePrincipalNames = @()
            accountEnabled = $true; appRoleAssignmentRequired = $false; signInAudience = 'AzureADMultipleOrgs'
        }
        Mock Get-TokenForgeGraphCollection -ModuleName TokenForge {
            param($AccessToken, $Uri)
            if ($Uri.AbsolutePath -eq '/v1.0/servicePrincipals') { return ,@($servicePrincipal) }
            throw 'Unexpected synthetic Graph collection request.'
        }

        $inventory = Get-TokenForgeTenantInventory -GraphToken $graphToken -Discovery (New-RoleOriginDiscovery) -SkipGrants
        $app = $inventory.Applications | Where-Object AppId -eq $appId

        $app.DelegatedScopeDefinitions | Should -HaveCount 1
        $scope = $app.DelegatedScopeDefinitions[0]
        $scope.Value | Should -BeExactly 'Synthetic.Read'
        $scope.ConsentType | Should -BeExactly 'User'
        $scope.AdminConsentDisplayName | Should -BeExactly 'Read synthetic data'
        $scope.UserConsentDescription | Should -BeExactly 'Read fixture data'

        $app.AppRoleDefinitions | Should -HaveCount 5
        @($app.AppRoleDefinitions.Origin) | Should -Be @('Application','ServicePrincipal','Unknown','Unknown','Unknown')
        @($app.AppRoleDefinitions[0].PSObject.Properties.Name) | Should -Be @('Id','Value','DisplayName','Description','AllowedMemberTypes','Enabled','Origin')
        $app.AppRoleDefinitions[0].Origin | Should -BeExactly 'Application'
        $app.AppRoleDefinitions[1].Origin | Should -BeExactly 'ServicePrincipal'
        $app.AppRoleDefinitions[2].Origin | Should -BeExactly 'Unknown'
        $app.AppRoleDefinitions[3].Origin | Should -BeExactly 'Unknown'
        $app.AppRoleDefinitions[4].Origin | Should -BeExactly 'Unknown'
        Should -Invoke Get-TokenForgeGraphCollection -ModuleName TokenForge -Times 1 -ParameterFilter { $Uri.AbsolutePath -eq '/v1.0/servicePrincipals' }
    }

    It 'roundtrips classified origins through application metadata JSON' {
        $graphToken = New-RoleOriginGraphToken
        $servicePrincipal = @{
            id = '33333333-3333-3333-3333-333333333333'; appId = $appId
            appOwnerOrganizationId = $owner; displayName = 'Synthetic app'; servicePrincipalType = 'Application'
            oauth2PermissionScopes = @()
            appRoles = @((New-RoleOriginGraphRole -Value 'App.Role' -Origin 'Application'),(New-RoleOriginGraphRole -Value 'SP.Role' -Origin 'ServicePrincipal'))
            replyUrls = @(); servicePrincipalNames = @(); accountEnabled = $true
            appRoleAssignmentRequired = $false; signInAudience = 'AzureADMultipleOrgs'
        }
        Mock Get-TokenForgeGraphCollection -ModuleName TokenForge {
            param($AccessToken, $Uri)
            if ($Uri.AbsolutePath -eq '/v1.0/servicePrincipals') { return ,@($servicePrincipal) }
            throw 'Unexpected synthetic Graph collection request.'
        }
        $app = (Get-TokenForgeTenantInventory -GraphToken $graphToken -Discovery (New-RoleOriginDiscovery) -SkipGrants).Applications[0]
        $path = Join-Path $TestDrive 'role-origin.json'
        $document = [pscustomobject]@{
            CapturedAt = '2026-01-01T00:00:00Z'; TenantFingerprint = 'a' * 64
            Applications = @($app)
        }

        $null = Update-TokenForgeApplicationMetadata -Path $path -Document $document -Kind Inventory
        $state = Get-TokenForgeApplicationMetadata -Path $path
        $record = $state.Applications[$appId].Records["Inventory/$('a' * 64)//"]

        @($record.Attributes.AppRoleDefinitions.Origin) | Should -Be @('Application','ServicePrincipal')
        (Get-Content -LiteralPath $path -Raw) | Should -Match '"Origin"\s*:\s*"Application"'
    }

    It 'accepts historical role rows without Origin and leaves their stored hash unchanged' {
        $path = Join-Path $TestDrive 'historical-role-origin.json'
        $document = [pscustomobject]@{
            CapturedAt = '2026-01-01T00:00:00Z'; TenantFingerprint = 'a' * 64
            Applications = @([pscustomobject]@{
                AppId = $appId; Sources = @(); AppRoleDefinitions = @([pscustomobject]@{
                    Id = '22222222-2222-2222-2222-222222222222'; Value = 'Old.Role'; DisplayName = 'Old role'
                    Description = 'Historical fixture'; AllowedMemberTypes = @('Application'); Enabled = $true
                })
            })
        }

        $null = Update-TokenForgeApplicationMetadata -Path $path -Document $document -Kind Inventory
        $rawBefore = Get-Content -LiteralPath $path -Raw
        $storedBefore = $rawBefore | ConvertFrom-Json -AsHashtable
        $recordName = "Inventory/$('a' * 64)//"
        $hashBefore = $storedBefore.Applications[$appId].Records[$recordName].ContentSha256

        $state = Get-TokenForgeApplicationMetadata -Path $path
        $record = $state.Applications[$appId].Records[$recordName]
        $record.Attributes.AppRoleDefinitions[0].Contains('Origin') | Should -BeFalse
        $record.ContentSha256 | Should -BeExactly $hashBefore
        (Get-Content -LiteralPath $path -Raw) | Should -BeExactly $rawBefore
    }

    It 'preserves classified roles in SQLite and refuses public reads of tenant records' -Skip:(-not $nativeAvailable) {
        $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
        $path=Join-Path $root 'private-roles.sqlite'
        $roles=@(foreach($origin in @('Application','ServicePrincipal','Unknown')){
            [pscustomobject]@{Id=[guid]::NewGuid().ToString();Value=($origin+'.Role');DisplayName='Fixture role';Description='Fixture';AllowedMemberTypes=@('User');Enabled=$true;Origin=$origin}
        })
        $document=@{CapturedAt='2026-01-01T00:00:00Z';TenantFingerprint=('a'*64);Applications=@(@{AppId=$appId;Sources=@();AppRoleDefinitions=$roles})}
        $null=Update-TokenForgeApplicationMetadata $path $document Inventory -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
        $record=(Get-TokenForgeApplicationMetadata $path -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE).Applications[$appId].Records["Inventory/$('a'*64)//"]
        @($record.Attributes.AppRoleDefinitions.Origin)|Should -Be @('Application','ServicePrincipal','Unknown')
        {Get-TokenForgeApplicationMetadata $path -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE -PublicOnly}|Should -Throw
    }

    It 'imports historical role rows into SQLite without adding origin or changing their hash' -Skip:(-not $nativeAvailable) {
        $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
        $json=Join-Path $root 'legacy-role.json';$sqlite=Join-Path $root 'legacy-role.sqlite'
        $document=@{CapturedAt='2026-01-01T00:00:00Z';TenantFingerprint=('a'*64);Applications=@(@{AppId=$appId;Sources=@();AppRoleDefinitions=@(@{Id='22222222-2222-2222-2222-222222222222';Value='Old.Role';DisplayName='Old role';Description='Legacy';AllowedMemberTypes=@('User');Enabled=$true})})}
        $null=Update-TokenForgeApplicationMetadata $json $document Inventory
        $name="Inventory/$('a'*64)//"
        $before=(Get-TokenForgeApplicationMetadata $json).Applications[$appId].Records[$name]
        $null=Import-TokenForgeApplicationMetadata -Path $sqlite -InputPath $json -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
        $after=(Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE).Applications[$appId].Records[$name]
        $after.ContentSha256|Should -BeExactly $before.ContentSha256
        $after.Attributes.AppRoleDefinitions[0].Contains('Origin')|Should -BeFalse
    }

    It 'rejects app role origins outside the exact supported values' {
        $path = Join-Path $TestDrive 'invalid-role-origin.json'
        $document = [pscustomobject]@{
            CapturedAt = '2026-01-01T00:00:00Z'; TenantFingerprint = 'a' * 64
            Applications = @([pscustomobject]@{
                AppId = $appId; Sources = @(); AppRoleDefinitions = @([pscustomobject]@{
                    Id = '22222222-2222-2222-2222-222222222222'; Value = 'Bad.Role'; DisplayName = 'Bad role'
                    Description = 'Synthetic fixture'; AllowedMemberTypes = @('Application'); Enabled = $true; Origin = 'application'
                })
            })
        }

        { Update-TokenForgeApplicationMetadata -Path $path -Document $document -Kind Inventory } | Should -Throw
        (Test-Path -LiteralPath $path) | Should -BeFalse
    }
}
