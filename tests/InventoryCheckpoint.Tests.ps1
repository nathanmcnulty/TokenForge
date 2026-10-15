BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $stage="$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1"
}
Describe 'Inventory snapshot publication follows metadata persistence' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  '{}'|Set-Content (Join-Path $state discovery.json)
  $path=Join-Path $state inventory.json
  $prior='{"CapturedAt":"2026-01-01T00:00:00Z","Marker":"previous"}'
  Set-Content $path $prior -NoNewline
  $token=ConvertTo-SecureString synthetic -AsPlainText -Force
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);Applications=@()}
  Mock Import-Module {}
  Mock Get-TokenForgeTenantInventory {$inventory}
  Mock Update-TokenForgeApplicationMetadata {}
  $options=@{Action='Inventory';StatePath=$state;GraphToken=$token}
 }
 AfterEach {$token.Dispose()}
 It 'retains the previous snapshot when metadata persistence fails' {
  Mock Update-TokenForgeApplicationMetadata {throw 'synthetic persistence failure'}
  {& $stage @options}|Should -Throw '*persistence failure*'
  [IO.File]::ReadAllText($path)|Should -BeExactly $prior
 }
 It 'does not publish a fresh snapshot on first-run metadata failure' {
  Remove-Item $path
  Mock Update-TokenForgeApplicationMetadata {throw 'synthetic persistence failure'}
  {& $stage @options}|Should -Throw
  Test-Path $path|Should -BeFalse
 }
 It 'publishes a complete private snapshot after persistence succeeds' {
  $r=& $stage @options
  $r.CapturedAt|Should -Be $inventory.CapturedAt
  ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($path))).CapturedAt|Should -BeExactly $inventory.CapturedAt
  Should -Invoke Update-TokenForgeApplicationMetadata -Times 1 -ParameterFilter {$Kind -eq 'Inventory'}
  if(-not $IsWindows){[int][IO.File]::GetUnixFileMode($path)|Should -Be 384}
  @(Get-ChildItem $state -Filter '*.tmp').Count|Should -Be 0
 }
 It 'retains the old snapshot and releases the writer lock if publication fails' {
  Mock Save-TokenForgeDocument -ModuleName TokenForge {throw 'synthetic snapshot failure'}
  {& $stage @options}|Should -Throw '*snapshot failure*'
  [IO.File]::ReadAllText($path)|Should -BeExactly $prior
  $lock=[IO.File]::Open((Join-Path $state '.writer.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  $lock.Dispose()
 }
}
