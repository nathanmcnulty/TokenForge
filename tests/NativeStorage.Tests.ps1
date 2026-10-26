BeforeDiscovery {$hasNative=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {
 function Invoke-StorageFixture([string[]]$Arguments,[int]$Expected=0){
  $result=& $env:TOKENFORGE_TEST_NATIVE @Arguments 2>&1
  $LASTEXITCODE|Should -Be $Expected
  ($result -join "`n")|ConvertFrom-Json
 }
}
Describe 'Linux SQLite snapshot CLI boundaries' -Skip:(-not $hasNative) {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $database=Join-Path $root scopes.sqlite;$destination=Join-Path $root snapshot.sqlite;$inputPath=Join-Path $root input.json
  [IO.File]::WriteAllText($inputPath,'{"SchemaVersion":1,"Observations":[],"RegistrationAttempts":[]}');[IO.File]::SetUnixFileMode($inputPath,[IO.UnixFileMode]384)
  $null=Invoke-StorageFixture @('evidence','import','--database',$database,'--input',$inputPath)
  $options=@('storage','snapshot','--database',$database,'--output-path',$destination,'--domain','scopes','--json')
 }
 It 'returns a byte-bound private create-new snapshot and refuses overwrite' {
  $result=Invoke-StorageFixture $options
  $result.SchemaVersion|Should -Be 1;$result.Domain|Should -Be scopes;$result.CrossStoreAtomic|Should -BeFalse
  $result.FreshAuthenticationPerformed|Should -BeFalse;$result.Sha256|Should -BeExactly (Get-FileHash $destination -Algorithm SHA256).Hash.ToLowerInvariant()
  ([int][IO.File]::GetUnixFileMode($destination) -band 511)|Should -Be 384
  (Invoke-StorageFixture $options 1).Code|Should -Be OperationFailed
  (Get-FileHash $destination -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $result.Sha256
 }
 It 'rejects duplicate or unknown flags without exposing paths' -ForEach @(@{Flag='--domain'},@{Flag='--unknown'},@{Flag='--json'}) {
  $result=Invoke-StorageFixture ($options+@($Flag,'synthetic-private')) 1
  $result.Code|Should -Be OperationFailed;($result|ConvertTo-Json -Compress)|Should -Not -Match 'synthetic-private|snapshot.sqlite';Test-Path $destination|Should -BeFalse
 }
 It 'refuses mismatched domain and pre-existing sidecars without output' {
  $options[$options.IndexOf('scopes')]='flows'
  (Invoke-StorageFixture $options 1).Code|Should -Be OperationFailed
  $options[$options.IndexOf('flows')]='scopes';[IO.File]::WriteAllText("$destination-journal",'synthetic')
  (Invoke-StorageFixture $options 1).Code|Should -Be OperationFailed
  Test-Path $destination|Should -BeFalse
 }
 It 'refuses non-private or linked source files' {
  [IO.File]::SetUnixFileMode($database,[IO.UnixFileMode]420)
  (Invoke-StorageFixture $options 1).Code|Should -Be OperationFailed
  [IO.File]::SetUnixFileMode($database,[IO.UnixFileMode]384)
  $link=Join-Path $root link.sqlite;$null=New-Item -ItemType SymbolicLink -Path $link -Target $database
  $options[$options.IndexOf($database)]=$link;(Invoke-StorageFixture $options 1).Code|Should -Be OperationFailed
 }
}
