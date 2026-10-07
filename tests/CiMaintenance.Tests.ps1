BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeCiMaintenance.ps1"
 $discovery=Get-TokenForgeDiscovery -Catalog (Get-TokenForgeCatalog "$PSScriptRoot/fixtures/catalog.json")
 $privateId='f0000000-0000-0000-0000-000000000009'
 function Read-Snapshot([string]$Path){
  $plain=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes($Path)) $env:TOKENFORGE_CHECKPOINT_KEY "private-maintenance/v1/$('a'*64)/$('b'*64)"
  try{[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json -AsHashtable -Depth 100}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
 }
}
Describe 'Encrypted read-only private maintenance' {
 BeforeEach {
  Mock Import-Module {}
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie';$env:TOKENFORGE_COOKIE_NAME='ESTSAUTH';$env:TOKENFORGE_TENANT_FINGERPRINT='a'*64;$env:TOKENFORGE_PRINCIPAL_FINGERPRINT='b'*64;$env:TOKENFORGE_CHECKPOINT_KEY=[Convert]::ToBase64String([byte[]](1..32))
  Mock Get-TokenForgeToken {[pscustomobject]@{AccessToken=(ConvertTo-SecureString 'synthetic-access' -AsPlainText -Force);RefreshToken=$null;TokenClaims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  Mock ConvertFrom-TokenForgeJwtPayload -ModuleName TokenForge {@{oid='synthetic-oid'}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{id='synthetic-oid'}}
  Mock Update-TokenForgeDiscovery {
   $doc=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json
   $doc.FetchedAt=[DateTimeOffset]::UtcNow.ToString('o')
   $null=Update-TokenForgeApplicationMetadata $MetadataPath -Document $doc -Kind Discovery
   $doc
  }
  Mock Get-TokenForgeTenantInventory {
   [pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';TenantGrants=@([pscustomobject]@{ClientId=$Discovery.Applications[0].AppId;ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');PrincipalFingerprint=$null;ConsentType='AllPrincipals';AppliesToCurrentPrincipal=$true;Evidence='TenantConfiguredGrant'});Applications=@($Discovery.Applications|ForEach-Object {$_|Add-Member -NotePropertyName Registration -NotePropertyValue Missing -PassThru})}
  }
  Mock Get-TokenForgeSignInApplications {
   [pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);Enumeration='Complete';Since=[DateTimeOffset]::UtcNow.AddDays(-7).ToString('o');Until=[DateTimeOffset]::UtcNow.ToString('o');EventTypes=@('interactiveUser');Applications=@([pscustomobject]@{AppId=$privateId;SignInCount=1;KnownInInventory=$false;RegisteredMicrosoft=$false;Evidence='ObservedSignInNotOwnership';ProtocolCounts=@([pscustomobject]@{Value='oAuth2';Count=1});AccessToken='must-not-persist'})}
  }
 }
 AfterEach {foreach($name in @('TOKENFORGE_ESTS_COOKIE','TOKENFORGE_COOKIE_NAME','TOKENFORGE_TENANT_FINGERPRINT','TOKENFORGE_PRINCIPAL_FINGERPRINT','TOKENFORGE_CHECKPOINT_KEY')){[Environment]::SetEnvironmentVariable($name,$null,'Process')}}
 It 'stores only projected metadata and encrypted statuses' {
  $result=& $runner -CheckpointPath "$root/maintenance.sealed"
  $result.Status|Should -Be Complete
  $saved=Read-Snapshot "$root/maintenance.sealed"
  $saved.Metadata.Applications.ContainsKey($privateId)|Should -BeTrue
  ($saved|ConvertTo-Json -Depth 100)|Should -Not -Match 'synthetic-cookie|synthetic-access|must-not-persist|AccessToken'
  $saved.LastRun.Registration|Should -Be NotRun
  $saved.GrantHistory.Count|Should -Be 1
  $saved.GrantHistory[0].Grants[0].Scopes[0]|Should -Be 'User.Read'
  $env:TOKENFORGE_ESTS_COOKIE|Should -BeNullOrEmpty
 }
 It 'preserves the prior sign-in origin and private candidate on Forbidden' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed"
  $before=Read-Snapshot "$root/maintenance.sealed"
  $origin="SignIns/$('a'*64)//"
  Mock Get-TokenForgeSignInApplications {throw 'Graph request failed (HTTP 403); response details suppressed.'}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  $result=& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed"
  $result.Status|Should -Be Partial;$result.SignIns|Should -Be Forbidden
  $after=Read-Snapshot "$root/next.sealed"
  $after.Metadata.Origins[$origin].LastObservedAt|Should -Be $before.Metadata.Origins[$origin].LastObservedAt
  @($after.Metadata.Runs|Where-Object Kind -eq SignIns)[-1].Window.Since|Should -Be @($before.Metadata.Runs|Where-Object Kind -eq SignIns)[-1].Window.Since
  $after.Metadata.Applications[$privateId].Records.ContainsKey("Inventory/$('a'*64)//")|Should -BeTrue
  Should -Invoke Get-TokenForgeTenantInventory -Times 1 -ParameterFilter {@($Discovery.Applications|Where-Object AppId -eq $privateId).Count -eq 1}
 }
 It 'preserves successful inventory history when fresh enumeration fails' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed" -SkipSignIns
  $before=Read-Snapshot "$root/maintenance.sealed"
  Mock Get-TokenForgeTenantInventory {throw 'Graph request failed (HTTP 503); response details suppressed.'}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  {& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed"}|Should -Throw '*did not finish*'
  $after=Read-Snapshot "$root/next.sealed"
  $after.Metadata.Origins["Inventory/$('a'*64)//"].LastObservedAt|Should -Be $before.Metadata.Origins["Inventory/$('a'*64)//"].LastObservedAt
  $after.LastRun.SignIns|Should -Be SkippedInventoryUnavailable
 }
 It 'records a bounded enumeration failure without advancing successful sign-in history' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed"
  $before=Read-Snapshot "$root/maintenance.sealed"
  Mock Get-TokenForgeSignInApplications {throw 'Sign-in page limit or pagination loop reached; no complete discovery returned.'}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  {& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed"}|Should -Throw '*did not finish*'
  $after=Read-Snapshot "$root/next.sealed"
  $after.LastRun.SignInFailureReason|Should -Be EnumerationBounded
  $after.Metadata.Origins["SignIns/$('a'*64)//"].LastObservedAt|Should -Be $before.Metadata.Origins["SignIns/$('a'*64)//"].LastObservedAt
 }
 It 'deduplicates grants despite enumeration and scope ordering changes' {
  $reverse=$false
  Mock Get-TokenForgeTenantInventory {
   $scopes=if($reverse){@('User.Read','Directory.Read.All')}else{@('Directory.Read.All','User.Read')}
   $grants=@('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222'|ForEach-Object {[pscustomobject]@{ClientId=$_;ResourceId='00000003-0000-0000-c000-000000000000';Scopes=$scopes;PrincipalFingerprint=$null;ConsentType='AllPrincipals';AppliesToCurrentPrincipal=$true;Evidence='TenantConfiguredGrant'}})
   if($reverse){[array]::Reverse($grants)}
   [pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';TenantGrants=$grants;Applications=$Discovery.Applications}
  }
  $null=& $runner -CheckpointPath "$root/maintenance.sealed" -SkipSignIns
  $reverse=$true;$env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  $null=& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed" -SkipSignIns
  (Read-Snapshot "$root/next.sealed").GrantHistory.Count|Should -Be 1
 }
 It 'records a complete empty configured grant set without confusing it with unavailable data' {
  Mock Get-TokenForgeTenantInventory {[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';TenantGrants=@();Applications=$Discovery.Applications}}
  $result=& $runner -CheckpointPath "$root/maintenance.sealed" -SkipSignIns
  $result.Status|Should -Be Complete
  $saved=Read-Snapshot "$root/maintenance.sealed"
  $saved.GrantHistory.Count|Should -Be 1
  $saved.GrantHistory[0].Grants|Should -HaveCount 0
 }
 It 'retains configured grant history when a later grant read is forbidden' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed" -SkipSignIns
  $before=Read-Snapshot "$root/maintenance.sealed"
  Mock Get-TokenForgeTenantInventory {[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Forbidden';TenantGrants=@();Applications=$Discovery.Applications}}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  $result=& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed" -SkipSignIns
  $result.Status|Should -Be Partial;$result.Grants|Should -Be Forbidden
  $after=Read-Snapshot "$root/next.sealed"
  (Get-TfCiHash $after.GrantHistory)|Should -Be (Get-TfCiHash $before.GrantHistory)
 }
 It 'rejects credential fields in an authenticated but malformed restore' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed"
  $saved=Read-Snapshot "$root/maintenance.sealed"
  $saved.Metadata.Applications[$privateId].Records.Values[0].Attributes.PrivateKey='must-not-persist'
  $plain=[Text.Encoding]::UTF8.GetBytes(($saved|ConvertTo-Json -Depth 100 -Compress))
  try{$blob=Protect-TfCiCheckpoint $plain $env:TOKENFORGE_CHECKPOINT_KEY "private-maintenance/v1/$('a'*64)/$('b'*64)";[IO.File]::WriteAllBytes("$root/malformed.sealed",$blob)}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  {& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/malformed.sealed"}|Should -Throw
  Test-Path "$root/next.sealed"|Should -BeFalse
 }
 It 'rejects an encrypted snapshot from another account before refreshing metadata' {
  $null=& $runner -CheckpointPath "$root/maintenance.sealed"
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie';$env:TOKENFORGE_PRINCIPAL_FINGERPRINT='c'*64
  Mock Get-TokenForgeToken {[pscustomobject]@{AccessToken=(ConvertTo-SecureString 'synthetic-access' -AsPlainText -Force);RefreshToken=$null;TokenClaims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('c'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  {& $runner -CheckpointPath "$root/next.sealed" -CheckpointInputPath "$root/maintenance.sealed"}|Should -Throw
  Test-Path "$root/next.sealed"|Should -BeFalse
  $env:TOKENFORGE_ESTS_COOKIE|Should -BeNullOrEmpty
 }
 It 'disposes credentials and clears the cookie even if snapshot output fails' {
  {& $runner -CheckpointPath "$root/nonexistent/maintenance.sealed"}|Should -Throw
  $env:TOKENFORGE_ESTS_COOKIE|Should -BeNullOrEmpty
 }
}
