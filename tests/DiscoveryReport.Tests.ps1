BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1"
}
Describe 'Read-only reports during discovery' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=Get-TokenForgeFlowEvidence (Join-Path $state missing.json)
  $metadata=Join-Path $state applications.json;$flow=Join-Path $state flows.json
  $app=[pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@();PublicClient=$true;IsResourceCandidate=$false;Sources=@();OwnerTenantId='f8cdef31-a31e-4b4a-93e4-5f571e91255a';PublishedGrants=@();DelegatedScopeDefinitions=@()}
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($app)}
  & (Get-Module TokenForge) {param($path,$doc) Save-TokenForgeDocument -Path $path -Document $doc} (Join-Path $state inventory.json) $inventory
  $null=Update-TokenForgeApplicationMetadata $metadata $inventory Inventory
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request)
   [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  try{$null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId '00000003-0000-0000-c000-000000000000' -DatabasePath (Join-Path $state scopes.json) -FlowDatabasePath $flow -Protocols OAuth2V2Pkce -DelayMilliseconds 0}finally{$secret.Dispose()}
  Mock Import-Module {}
 }
 It 'selects the saved account while the writer lock is held and leaves files unchanged' {
  $lock=[IO.File]::Open((Join-Path $state '.writer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{
   $before=@(Get-ChildItem $state -Force -File|Sort-Object FullName|Where-Object Name -ne '.writer.lock'|ForEach-Object {(Get-FileHash $_.FullName).Hash})
   $r=& $runner -Action Report -StatePath $state -InventoryAccount -SummaryOnly
   $r.ApplicationCount|Should -Be 1
   $r.ApplicationsWithSelectedPlans|Should -Be 1
   $r.ApplicationsWithObservedSuccess|Should -Be 1
   $r.Applications.Count|Should -Be 0
   $r.RequiredAuthenticationFlow|Should -BeExactly NotInferred
   Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
   $after=@(Get-ChildItem $state -Force -File|Sort-Object FullName|Where-Object Name -ne '.writer.lock'|ForEach-Object {(Get-FileHash $_.FullName).Hash})
   $after|Should -Be $before
  }finally{$lock.Dispose()}
 }
 It 'retains catalog-only reporting unless an account is explicitly selected' {
  $r=& $runner -Action Report -StatePath $state
  $r.ApplicationsWithSelectedPlans|Should -Be 0
  $r.Applications[0].FlowContext|Should -BeExactly SelectTenantAndPrincipal
  $r=& $runner -Action Report -StatePath $state -PrincipalFingerprint ('b'*64)
  $r.ApplicationsWithSelectedPlans|Should -Be 1
 }
 It 'allows metadata-only reporting without creating an optional flow file or writer lock' {
  Remove-Item $flow
  $r=& $runner -Action Report -StatePath $state -InventoryAccount
  $r.ApplicationCount|Should -Be 1
  $r.ApplicationsWithSelectedPlans|Should -Be 0
  Test-Path $flow|Should -BeFalse
  Test-Path (Join-Path $state '.writer.lock')|Should -BeFalse
 }
 It 'does not create a missing state directory or silently ignore an explicit missing flow file' {
  $missing=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  {& $runner -Action Report -StatePath $missing}|Should -Throw '*metadata does not exist*'
  Test-Path $missing|Should -BeFalse
  {& $runner -Action Report -StatePath $state -FlowPath (Join-Path $state absent.json)}|Should -Throw '*flow evidence does not exist*'
 }
 It 'does not change overly broad inventory directory permissions' -Skip:$IsWindows {
  $before=[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupRead
  [IO.File]::SetUnixFileMode($state,$before)
  {& $runner -Action Report -StatePath $state -InventoryAccount}|Should -Throw
  [IO.File]::GetUnixFileMode($state)|Should -Be $before
 }
 It 'rejects an invalid saved account without echoing its contents (<Kind>)' -ForEach @(@{Kind='array'},@{Kind='newline'},@{Kind='duplicate'},@{Kind='UTF8'}) {
  $path=Join-Path $state inventory.json
  if($Kind -eq 'array'){$inventory.PrincipalFingerprint=@(('b'*64),('b'*64));$text=$inventory|ConvertTo-Json -Depth 10}
  elseif($Kind -eq 'newline'){$inventory.PrincipalFingerprint=('b'*64)+"`n";$text=$inventory|ConvertTo-Json -Depth 10}
  elseif($Kind -eq 'duplicate'){$text='{"TenantFingerprint":"'+('a'*64)+'","TenantFingerprint":"'+('a'*64)+'","PrincipalFingerprint":"'+('b'*64)+'"}'}
  if($Kind -eq 'UTF8'){[IO.File]::WriteAllBytes($path,[byte[]]@(255))}else{[IO.File]::WriteAllText($path,$text)}
  {& $runner -Action Report -StatePath $state -InventoryAccount}|Should -Throw '*Cannot select a valid account*'
  Test-Path (Join-Path $state '.writer.lock')|Should -BeFalse
 }
 It 'rejects ambiguous selection and use on a mutating action before creating state' {
  {& $runner -Action Report -StatePath $state -InventoryAccount -PrincipalFingerprint ('b'*64)}|Should -Throw '*InventoryAccount requires*'
  $missing=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  {& $runner -Action Register -StatePath $missing -InventoryAccount}|Should -Throw '*InventoryAccount requires*'
  Test-Path $missing|Should -BeFalse
 }
}
