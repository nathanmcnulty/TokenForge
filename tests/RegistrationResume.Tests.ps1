BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Registration source shapes' {
 BeforeEach {
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {
   if($Method -eq 'POST'){@{id='33333333-3333-3333-3333-333333333333';appId='11111111-1111-1111-1111-111111111111';appOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'}}
  }
 }
 AfterEach {$secret.Dispose()}
 It 'preserves explicit <Kind> candidate resolution after <Shape> serialization' -ForEach @(
  @{Kind='Published';Shape='PSObject'},@{Kind='Published';Shape='Hashtable'},@{Kind='Published';Shape='BclDictionary'},
  @{Kind='Documentation';Shape='PSObject'},@{Kind='Documentation';Shape='Hashtable'},@{Kind='Documentation';Shape='BclDictionary'},
  @{Kind='SignIn';Shape='PSObject'},@{Kind='SignIn';Shape='Hashtable'},@{Kind='SignIn';Shape='BclDictionary'}
 ) {
  $evidence=if($Kind -eq 'Published'){'PublishedResource'}elseif($Kind -eq 'Documentation'){'PublishedEntraDocs'}else{'ObservedSignInNotOwnership'}
  $app=[pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Ownership='Unverified';OwnerTenantId=$null;Sources=@([pscustomobject]@{Evidence=$evidence})}
  $json=$app|ConvertTo-Json -Depth 10
  if($Shape -eq 'Hashtable'){$app=$json|ConvertFrom-Json -AsHashtable}
  if($Shape -eq 'BclDictionary'){$app=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($json)}
  {Register-TokenForgeApplication $secret $app -Confirm:$false}|Should -Throw '*requires*'
  if($Kind -eq 'Documentation') {
   {Register-TokenForgeApplication $secret $app -ResolvePublishedCandidate -Confirm:$false}|Should -Throw '*requires*'
  }
  $flags=if($Kind -eq 'Published'){@{ResolvePublishedCandidate=$true}}elseif($Kind -eq 'Documentation'){@{ResolveDocumentationCandidate=$true}}else{@{ResolveSignInCandidate=$true}}
  (Register-TokenForgeApplication $secret $app @flags -Confirm:$false).Outcome|Should -Be Created
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Method -eq 'POST' -and $Body.Count -eq 1}
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=Get-TokenForgeFlowEvidence (Join-Path $state missing.json)
  if($app -is [Collections.IDictionary]){$app['Registration']='Missing'}else{$app|Add-Member Registration Missing}
  $cached=[pscustomobject]@{TenantFingerprint=('a'*64);Applications=@($app)}
  if($Shape -eq 'BclDictionary'){$cached=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($cached|ConvertTo-Json -Depth 10))}
  $resolve=if($Kind -eq 'Published'){@{ResolvePublishedCandidates=$true}}elseif($Kind -eq 'Documentation'){@{ResolveDocumentationCandidates=$true}}else{@{ResolveSignInCandidates=$true}}
  if($Kind -eq 'Documentation'){
   @(Sync-TokenForgeApplicationRegistration -Inventory $cached -GraphToken $secret -DatabasePath (Join-Path $state scopes.json) -ResolvePublishedCandidates -DelayMilliseconds 0 -Confirm:$false).Count|Should -Be 0
   Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Method -eq 'POST'}
  }
  @(Sync-TokenForgeApplicationRegistration -Inventory $cached -GraphToken $secret -DatabasePath (Join-Path $state scopes.json) @resolve -DelayMilliseconds 0 -Confirm:$false).Count|Should -Be 1

 }
 It 'keeps documentation candidates eligible with independent <Evidence> evidence' -ForEach @(@{Evidence='PublishedResource'},@{Evidence='MicrosoftOwner'}) {
  $app=[pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Ownership='Unverified';OwnerTenantId=$null;Registration='Missing';Sources=@([pscustomobject]@{Evidence='PublishedEntraDocs'})}
  $flags=@{}
  if($Evidence -eq 'MicrosoftOwner'){$app.Ownership='PublishedMicrosoftOwner';$app.OwnerTenantId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'}
  else{$app.Sources+=@([pscustomobject]@{Evidence=$Evidence});$flags.ResolvePublishedCandidates=$true}
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);Applications=@($app)}
  $attempts=@(Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $secret -DatabasePath (Join-Path $root scopes.json) @flags -DelayMilliseconds 0 -Confirm:$false)
  $attempts.Count|Should -Be 1
  $attempts[0].Outcome|Should -Be Created
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Method -eq 'POST'}
 }

}
Describe 'Ambiguous registration ownership' {
 It 'checkpoints cleanup and refuses later retries without deleting the observed principal' {
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $counter=Join-Path $root reads.txt;Set-Content $counter 0
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);Applications=@([pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Registration='Missing';Ownership='PublishedMicrosoftOwner';OwnerTenantId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'})}
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {
   if($Method -eq 'POST'){throw 'Graph request failed (HTTP 503); details suppressed.'}
   $n=[int](Get-Content $counter);Set-Content $counter ($n+1)
   if($n -gt 0){@{appId='11111111-1111-1111-1111-111111111111';appOwnerOrganizationId='44444444-4444-4444-4444-444444444444'}}
  }
  $options=@{Inventory=$inventory;GraphToken=$secret;DatabasePath=(Join-Path $root scopes.json);DelayMilliseconds=0;Confirm=$false}
  try{
   {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*cleanup*'
   (Get-TokenForgeScopeDatabase $options.DatabasePath).RegistrationAttempts[0].Outcome|Should -Be CleanupRequired
   {Sync-TokenForgeApplicationRegistration @options -RetryFailures}|Should -Throw '*cleanup*'
   Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Method -eq 'POST'}
   Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter {$Method -eq 'DELETE'}
  }finally{$secret.Dispose()}
 }
}
Describe 'Registration interruption and selective resume' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$path=Join-Path $root scopes.json
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $first='11111111-1111-1111-1111-111111111111';$second='22222222-2222-2222-2222-222222222222'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);Applications=@($first,$second|ForEach-Object {[pscustomobject]@{AppId=$_;Ownership='PublishedMicrosoftOwner';Registration='Missing'}})}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $options=@{Inventory=$inventory;GraphToken=$secret;DatabasePath=$path;DelayMilliseconds=0;Confirm=$false}
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
  Mock Register-TokenForgeApplication -ModuleName TokenForge {[pscustomobject]@{Outcome='AlreadyPresent'}}
 }
 AfterEach {$secret.Dispose()}
 It 'checkpoints and stops at HTTP <Status> then retries only unfinished temporary work' -ForEach @(@{Status=429},@{Status=500},@{Status=503}) {
  Mock Register-TokenForgeApplication -ModuleName TokenForge {throw "Graph request failed (HTTP $Status); response details suppressed."}
  $caught=$null
  try{$null=Sync-TokenForgeApplicationRegistration @options}catch{$caught=$_}
  $caught.FullyQualifiedErrorId.Split(',')[0]|Should -BeExactly TokenForge.TransientRegistration
  $db=Get-TokenForgeScopeDatabase $path
  $db.RegistrationAttempts.Count|Should -Be 1
  $db.RegistrationAttempts[0].HttpStatus|Should -Be $Status
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1 -Exactly
  Mock Register-TokenForgeApplication -ModuleName TokenForge {[pscustomobject]@{Outcome='AlreadyPresent'}}
  @(Sync-TokenForgeApplicationRegistration @options -MaxApplications 1).Count|Should -Be 1
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 2 -Exactly -ParameterFilter {$Application.AppId -eq $first}
  @(Sync-TokenForgeApplicationRegistration @options -MaxApplications 1).Count|Should -Be 1
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Application.AppId -eq $second}
 }
 It 'repairs skipped checkpoints in one projection without repeating requests' {
  $null=Sync-TokenForgeApplicationRegistration @options
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {}
  @(Sync-TokenForgeApplicationRegistration @options -MaxApplications 1).Count|Should -Be 0
  Should -Invoke Update-TokenForgeApplicationMetadata -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Document.RegistrationAttempts.Count -eq 2}
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 2 -Exactly
 }
 It 'does not issue another registration when skipped-checkpoint projection fails' {
  $null=Sync-TokenForgeApplicationRegistration @options -MaxApplications 1
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {throw 'Synthetic metadata failure'}
  {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*metadata failure*'
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'leaves permanent HTTP failures skipped unless explicitly requested' {
  Mock Register-TokenForgeApplication -ModuleName TokenForge {throw 'Graph request failed (HTTP 400); details suppressed.'}
  @(Sync-TokenForgeApplicationRegistration @options -MaxApplications 1).Count|Should -Be 1
  Mock Register-TokenForgeApplication -ModuleName TokenForge {[pscustomobject]@{Outcome='AlreadyPresent'}}
  $r=@(Sync-TokenForgeApplicationRegistration @options -MaxApplications 1)
  $r[0].AppId|Should -Be $second
  @(Sync-TokenForgeApplicationRegistration @options -RetryFailures).Count|Should -Be 1
 }
 It 'stops on an unverified transport response and requires deliberate retry (<Message>)' -ForEach @(
  @{Message='Graph transport failed; details suppressed.'},
  @{Message='Graph returned invalid JSON; details suppressed.'},
  @{Message='Service principal creation failed; no consent was granted.'}
 ) {
  Mock Register-TokenForgeApplication -ModuleName TokenForge {throw $Message}
  {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*unverified Graph response*'
  (Get-TokenForgeScopeDatabase $path).RegistrationAttempts.Count|Should -Be 1
  Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 1 -Exactly
 }
}
Describe 'Native registration temporary checkpoints' -Skip:(-not $nativeAvailable) {
 It 'roundtrips a 429 failure and reconsiders that candidate on default resume' {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$path=Join-Path $root scopes.sqlite
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);Applications=@([pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Registration='Missing';Ownership='PublishedMicrosoftOwner'})}
  $inventory.Applications+=@([pscustomobject]@{AppId='22222222-2222-2222-2222-222222222222';Registration='Missing';Ownership='PublishedMicrosoftOwner'})
  Mock Get-TokenForgeTokenClaims -ModuleName TokenForge {[pscustomobject]@{TenantFingerprint=('a'*64)}}
  Mock Register-TokenForgeApplication -ModuleName TokenForge {throw 'Graph request failed (HTTP 429); details suppressed.'}
  $options=@{Inventory=$inventory;GraphToken=$secret;DatabasePath=$path;MetadataPath=(Join-Path $root applications.sqlite);NativeExecutablePath=$env:TOKENFORGE_TEST_NATIVE;DelayMilliseconds=0;Confirm=$false}
  try{
   {Sync-TokenForgeApplicationRegistration @options}|Should -Throw '*temporary Graph failure*'
   $db=Get-TokenForgeScopeDatabase $path -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
   $db.RegistrationAttempts.Count|Should -Be 1
   $db.RegistrationAttempts[0].HttpStatus|Should -Be 429
   Mock Register-TokenForgeApplication -ModuleName TokenForge {[pscustomobject]@{Outcome='AlreadyPresent'}}
   @(Sync-TokenForgeApplicationRegistration @options).Count|Should -Be 2
   @(Sync-TokenForgeApplicationRegistration @options).Count|Should -Be 0
   (Get-TokenForgeApplicationMetadata $options.MetadataPath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE).Applications.Count|Should -Be 2
   Should -Invoke Register-TokenForgeApplication -ModuleName TokenForge -Times 3 -Exactly
  }finally{$secret.Dispose()}
 }
}
