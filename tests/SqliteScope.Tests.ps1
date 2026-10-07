BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $native=$env:TOKENFORGE_TEST_NATIVE
}
Describe 'Primary SQLite scope and registration history' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $path=Join-Path $root scopes.sqlite;$flow=Join-Path $root flows.sqlite;$metadata=Join-Path $root applications.sqlite
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
 }
 AfterEach {$secret.Dispose()}
 It 'checkpoints every flow aggregate and resumes without token issuance, retaining metadata repair evidence' {
  $probe=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;FlowDatabasePath=$flow;NativeExecutablePath=$native;DelayMilliseconds=0;ExploreAllFlows=$true}
  $changes=@{};$null=Invoke-TokenForgeScopeProbe @probe -ScopeChanges $changes
  $changes.Count|Should -Be 1
  $db=Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native
  $db.Observations.Count|Should -Be 1
  $db.Observations[0].Outcome|Should -Be Succeeded
  $null=Update-TokenForgeApplicationMetadata $metadata -Document $db -Kind ScopeObservations -NativeExecutablePath $native
  $changes=@{};@(Invoke-TokenForgeScopeProbe @probe -ScopeChanges $changes).Count|Should -Be 0
  $changes.Count|Should -Be 1
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations.Count|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3
  @($db|ConvertTo-Json -Depth 12|Select-String private-access).Count|Should -Be 0
  @(Get-ChildItem $root -Filter '*.flow-input.json').Count|Should -Be 0
 }
 It 'imports history idempotently and selects the latest failure in its own namespace' {
  $legacy=Join-Path $root scopes.json
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $legacy -DelayMilliseconds 0
  (Import-TokenForgeScopeDatabase $path $legacy -NativeExecutablePath $native).Imported|Should -Be 1
  (Import-TokenForgeScopeDatabase $path $legacy -NativeExecutablePath $native).Imported|Should -Be 0
  $db=Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native
  $row=$db.Observations[0].PSObject.Copy();$row.Outcome='Failed';$row.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o')
  $null=Add-TokenForgeScopeObservation $db $row -Path $path -NativeExecutablePath $native
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations.Count|Should -Be 2
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native -Latest -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Observations[0].Outcome|Should -Be Failed
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native -Latest -TenantFingerprint ('a'*64) -PrincipalFingerprint ('d'*64)).Observations.Count|Should -Be 0
 }
 It 'checkpoints registration 403 before stopping and resumes without repeating the request' {
  $inventory.Applications[0].Registration='Missing';$inventory.Applications[0].Ownership='PublishedMicrosoftOwner'
  Mock Register-TokenForgeApplication -ModuleName TokenForge {throw 'Registration failed (HTTP 403); details suppressed.'}
  $options=@{Inventory=$inventory;GraphToken=$secret;DatabasePath=$path;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0;Confirm=$false}
  {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*403*'
  $db=Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native
  $db.RegistrationAttempts[0].HttpStatus|Should -Be 403
  @(Sync-TokenForgeApplicationRegistration @options).Count|Should -Be 0
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1
 }
 It 'requires an explicit cleanup resolution even after an unrelated later failure' {
  $legacy=Join-Path $root cleanup.json
  $db=New-TokenForgeScopeDatabase
  $db.RegistrationAttempts=@([pscustomobject]@{AppId=$client;TenantFingerprint=('a'*64);AttemptedAt='2026-10-01T00:00:00Z';Outcome='CleanupRequired';HttpStatus=$null},[pscustomobject]@{AppId=$client;TenantFingerprint=('a'*64);AttemptedAt='2026-10-02T00:00:00Z';Outcome='Failed';HttpStatus=403})
  $db|ConvertTo-Json -Depth 12|Set-Content $legacy
  (Get-TokenForgeScopeDatabase $legacy -Latest).RegistrationAttempts[0].Outcome|Should -Be CleanupRequired
  $null=Import-TokenForgeScopeDatabase $path $legacy -NativeExecutablePath $native
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native -Latest).RegistrationAttempts[0].Outcome|Should -Be CleanupRequired
  $inventory.Applications[0].Registration='Missing';$inventory.Applications[0].Ownership='PublishedMicrosoftOwner'
  Mock Register-TokenForgeApplication -ModuleName TokenForge {[pscustomobject]@{Outcome='AlreadyPresent'}}
  $options=@{Inventory=$inventory;GraphToken=$secret;DatabasePath=$path;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0;Confirm=$false;RetryFailures=$true}
  {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*cleanup*'
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 0
  $db.RegistrationAttempts+= [pscustomobject]@{AppId=$client;TenantFingerprint=('a'*64);AttemptedAt='2026-10-03T00:00:00Z';Outcome='CleanupResolved';HttpStatus=$null}
  $db|ConvertTo-Json -Depth 12|Set-Content $legacy
  $null=Import-TokenForgeScopeDatabase $path $legacy -NativeExecutablePath $native
  {Sync-TokenForgeApplicationRegistration @options}|Should -Not -Throw
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1
  (Get-TokenForgeScopeDatabase $legacy -Latest).RegistrationAttempts[0].Outcome|Should -Be CleanupResolved
 }
 It 'keeps WhatIf registration from initializing evidence or repairing metadata' {
  $inventory.Applications[0].Registration='Missing';$inventory.Applications[0].Ownership='PublishedMicrosoftOwner'
  $null=Sync-TokenForgeApplicationRegistration $inventory $secret -DatabasePath $path -MetadataPath $metadata -NativeExecutablePath $native -WhatIf
  Test-Path $path|Should -BeFalse
  Test-Path $metadata|Should -BeFalse
 }
 It 'rejects a missing native dependency before issuance' {
  {Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -NativeExecutablePath "$root/missing" -DelayMilliseconds 0}|Should -Throw '*native*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
 }
}
