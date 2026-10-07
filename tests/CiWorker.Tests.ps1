BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeCiDiscovery.ps1"
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 $discovery.Applications=@($discovery.Applications|Select-Object -First 2)
}
Describe 'Actual weekly worker with synthetic identity transport' {
 BeforeEach {
  Mock Import-Module {}
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  $state=New-TfCiState $discovery
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/state.json"
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=$discovery.CatalogContentSha256;TenantGrants=@();Applications=@($state.Recipe.AppIds|ForEach-Object {[pscustomobject]@{AppId=$_;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}})}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie';$env:TOKENFORGE_COOKIE_NAME='ESTSAUTH'
  $env:TOKENFORGE_TENANT_FINGERPRINT='a'*64;$env:TOKENFORGE_PRINCIPAL_FINGERPRINT='b'*64
  $env:TOKENFORGE_CHECKPOINT_KEY=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
  Mock Get-TokenForgeToken {
   param($Request)
   $access=if($Request.ClientId -eq '14d82eec-204b-4c2f-b7e8-296a70dab67e'){'e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"tid":"synthetic-tenant","oid":"synthetic-principal"}')).TrimEnd('=').Replace('+','-').Replace('/','_')+'.signature'}else{'synthetic-access'}
   [pscustomobject]@{AccessToken=ConvertTo-SecureString $access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  Mock Get-TokenForgeTenantInventory {$inventory}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{id='synthetic-principal'}}
  $options=@{DataPath="$root/public";WeeklyStatePath="$root/state.json";ChunkIndex=0;ReceiptPath="$root/receipt.json";CheckpointPath="$root/checkpoint.sealed"}
 }
 AfterEach {foreach($name in @('TOKENFORGE_ESTS_COOKIE','TOKENFORGE_COOKIE_NAME','TOKENFORGE_TENANT_FINGERPRINT','TOKENFORGE_PRINCIPAL_FINGERPRINT','TOKENFORGE_CHECKPOINT_KEY')){[Environment]::SetEnvironmentVariable($name,$null)}}
 It 'assesses wholly missing inventory without probe issuance' {
  foreach($app in $inventory.Applications){$app.Registration='Missing';$app.Ownership='Unverified';$app.AccountEnabled=$false}
  $null=& $runner @options
  $receipt=Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json
  $receipt.Status|Should -Be Complete;$receipt.Assessed|Should -Be 2;$receipt.Successful|Should -Be 0
  Should -Invoke Get-TokenForgeToken -Times 1
 }
 It 'encrypts private evidence and resumes without repeating issuance' {
  $null=& $runner @options
  $context="$('a'*64)/$('b'*64)/$($state.PlanId)/0"
  $plain=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes("$root/checkpoint.sealed")) $env:TOKENFORGE_CHECKPOINT_KEY $context
  $saved=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json
  @($saved.Scopes.Observations).Count|Should -Be 2
  [Text.Encoding]::UTF8.GetString($plain)|Should -Not -Match 'synthetic-cookie|synthetic-access'
  [Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  $null=& $runner @options -CheckpointInputPath "$root/checkpoint.sealed"
  Should -Invoke Get-TokenForgeToken -Times 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2
 }
 It 'excludes earlier success when refreshed eligibility is disabled' {
  $null=& $runner @options
  foreach($app in $inventory.Applications){$app.AccountEnabled=$false}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie';Remove-Item "$root/public/scopes/chunk-0000.json"
  $null=& $runner @options -CheckpointInputPath "$root/checkpoint.sealed"
  (Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json).Successful|Should -Be 0
  @((Get-Content "$root/public/scopes/chunk-0000.json" -Raw|ConvertFrom-Json).Observations).Count|Should -Be 0
 }
 It 'assesses both resources and resumes their completed cells without issuance' {
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/state.json"
  $null=& $runner @options
  $receipt=Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json
  $receipt.SchemaVersion|Should -Be 2
  $receipt.Assessed|Should -Be 2;$receipt.Successful|Should -Be 2
  $receipt.AssessedPairs|Should -Be 4;$receipt.SuccessfulPairs|Should -Be 4
  $context="$('a'*64)/$('b'*64)/$($state.PlanId)/0"
  $plain=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes("$root/checkpoint.sealed")) $env:TOKENFORGE_CHECKPOINT_KEY $context
  try{$saved=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json;@($saved.Scopes.Observations).Count|Should -Be 4}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  $null=& $runner @options -CheckpointInputPath "$root/checkpoint.sealed"
  Should -Invoke Get-TokenForgeToken -Times 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 12
 }
 It 'records ARM success and Graph failure as one successful app per client' {
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/state.json"
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Token request failed (AADSTS65001). Details suppressed.'} -ParameterFilter {$Request.ResourceId -eq '00000003-0000-0000-c000-000000000000'}
  $null=& $runner @options
  $receipt=Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json
  $receipt.Status|Should -Be Complete
  $receipt.Assessed|Should -Be 2;$receipt.Successful|Should -Be 2
  $receipt.AssessedPairs|Should -Be 4;$receipt.SuccessfulPairs|Should -Be 2
 }
 It 'cannot complete a missing resource pair using stale summaries' {
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/state.json"
  $null=& $runner @options
  Mock Invoke-TokenForgeScopeProbe {}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  {& $runner @options -CheckpointInputPath "$root/checkpoint.sealed"}|Should -Throw '*No private state*'
  (Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json).Status|Should -Be Failed
 }
 It 'rejects an authenticated checkpoint containing an unplanned resource' {
  $null=& $runner @options
  $context="$('a'*64)/$('b'*64)/$($state.PlanId)/0"
  $plain=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes("$root/checkpoint.sealed")) $env:TOKENFORGE_CHECKPOINT_KEY $context
  try{$saved=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json -AsHashtable}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
  $saved.Scopes.Observations[0].ResourceId='797f4846-ba00-4fd7-ba43-dac1f8f63013'
  $bytes=[Text.Encoding]::UTF8.GetBytes(($saved|ConvertTo-Json -Depth 100 -Compress))
  try{[IO.File]::WriteAllBytes("$root/checkpoint.sealed",(Protect-TfCiCheckpoint $bytes $env:TOKENFORGE_CHECKPOINT_KEY $context))}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)}
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie'
  {& $runner @options -CheckpointInputPath "$root/checkpoint.sealed"}|Should -Throw '*No private state*'
  (Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json).Status|Should -Be Failed
 }
 It 'clears credentials and plaintext state even when receipt writing fails' {
  $before=@(Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter TokenForge-ci-*|ForEach-Object FullName)
  $options.ReceiptPath="$root/absent/receipt.json"
  {& $runner @options}|Should -Throw
  $env:TOKENFORGE_ESTS_COOKIE|Should -BeNullOrEmpty
  @((Get-ChildItem ([IO.Path]::GetTempPath()) -Directory -Filter TokenForge-ci-*|Where-Object FullName -NotIn $before)).Count|Should -Be 0
 }
 It 'writes an encrypted recovery point before later issuance through the cross-module callback' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {
   param($Request)
   if($Request.ClientId -eq $inventory.Applications[0].AppId){Start-Sleep -Milliseconds 1100}
   else{if(-not(Test-Path "$root/checkpoint.sealed")){throw 'AADSTS99999 checkpoint callback was not invoked'}}
   [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  $null=& $runner @options -CheckpointIntervalSeconds 1
  (Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json).Successful|Should -Be 2
 }
 It 'recovers a transient flow from an encrypted Started checkpoint' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Token request failed (HTTP 429). Details suppressed.'} -ParameterFilter {$Request.ClientId -ne '14d82eec-204b-4c2f-b7e8-296a70dab67e'}
  {& $runner @options}|Should -Throw '*No private state*'
  (Get-Content "$root/receipt.json" -Raw|ConvertFrom-Json).Status|Should -Be Failed
  Test-Path "$root/checkpoint.sealed"|Should -BeTrue
 }
}
