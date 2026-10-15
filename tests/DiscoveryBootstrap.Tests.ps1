BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeDiscoveryRun.ps1"
}
Describe 'Standalone discovery bootstrap boundaries' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  $inventory=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CapturedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $inventory|ConvertTo-Json|Set-Content (Join-Path $state inventory.json)
  '{}'|Set-Content (Join-Path $state discovery.json)
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute);foreach($file in @('inventory.json','discovery.json')){[IO.File]::SetUnixFileMode((Join-Path $state $file),[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)}}
  $cookie=ConvertTo-SecureString synthetic -AsPlainText -Force
  $claims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Application.Read.All')}
  Mock Import-Module {}
  Mock Get-TokenForgeToken {[pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic -AsPlainText -Force);TokenClaims=$claims}}
  Mock ConvertFrom-TokenForgeJwtPayload -ModuleName TokenForge {@{oid='synthetic'}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{id='synthetic'}}
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{Status='Complete';CredentialOutput=$false}}
 }
 AfterEach {$cookie.Dispose()}
 It 'requests existing inventory permission and completes with matching cached identity' {
  $r=& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie|ConvertFrom-Json
  $r.Status|Should -Be Complete
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1 -ParameterFilter {$ExploreAllFlows}
  Should -Invoke Get-TokenForgeToken -Times 1 -ParameterFilter {$Request.Scopes -contains 'Application.Read.All'}
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1
 }
 It 'keeps JSON output clean and emits only fixed orchestration stages with Verbose' {
  Mock Get-TokenForgeToken {
   Write-Warning 'synthetic token warning'
   Write-Verbose 'synthetic provider details'
   [pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic -AsPlainText -Force);TokenClaims=$claims}
  }
  $output=@(& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie -Verbose 3>&1 4>&1)
  $messages=@($output|Where-Object {$_ -is [Management.Automation.VerboseRecord]}|ForEach-Object Message)
  $messages|Should -Be @('Discovery stage: Configuration','Discovery stage: Authentication','Discovery stage: Authorization','Discovery stage: Identity','Discovery stage: PublicSources','Discovery stage: Inventory','Discovery stage: Discovery','Discovery stage: Finished')
  @($output|Where-Object {$_ -is [Management.Automation.WarningRecord]}).Count|Should -Be 0
  $json=@($output|Where-Object {$_ -is [string]})
  $json.Count|Should -Be 1
  ($json[0]|ConvertFrom-Json).Status|Should -Be Complete
 }
 It 'stops before inventory or discovery when issued permissions are insufficient' {
  $claims.Scopes=@('User.Read')
  $r=& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie|ConvertFrom-Json
  $r.Status|Should -Be Stopped
  $r.Reason|Should -Be Authorization
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0
 }
 It 'rejects a cached workspace belonging to another principal' {
  $claims.PrincipalFingerprint='e'*64
  $r=& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie|ConvertFrom-Json
  $r.Status|Should -Be Stopped
  $r.Reason|Should -Be Authorization
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0
 }
 It 'refuses concurrent orchestration before authentication and releases its own locks' {
  $path=Join-Path $state '.discovery.lock'
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open($path,$true)
  try{
   $r=& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie|ConvertFrom-Json
   $r.Status|Should -Be Stopped
   Should -Invoke Get-TokenForgeToken -Times 0
  }finally{$lock.Dispose()}
  $r=& $runner -StatePath $state -NativeExecutablePath /synthetic/tokenforge -EstsAuth $cookie|ConvertFrom-Json
  $r.Status|Should -Be Complete
 }
}
