BeforeAll {
 $validator=Join-Path $PSScriptRoot '../scripts/Test-TokenForgeReleaseAssets.ps1'
 $version='1.2.3';$commit='a'*40
 function New-ReleaseFixture([string]$Directory){
  $null=New-Item -ItemType Directory $Directory -Force
  foreach($runtime in @('linux-x64','linux-arm64','win-x64','win-arm64','osx-x64','osx-arm64')){
   $extension=if($runtime.StartsWith('win-')){'zip'}else{'tar.gz'}
   $name="TokenForge-$version-$runtime.$extension"
   $file=Join-Path $Directory $name
   [IO.File]::WriteAllBytes($file,[byte[]](1,2,3))
   @{SchemaVersion=1;Runtime=$runtime;Version=$version;SourceCommit=$commit;Archive=$name;Sha256=(Get-FileHash $file).Hash.ToLowerInvariant()}|ConvertTo-Json|Set-Content "$file.json"
  }
 }
}
Describe 'Complete release asset validation' {
 BeforeEach {$dir=Join-Path $TestDrive ([guid]::NewGuid());New-ReleaseFixture $dir}
 It 'accepts exactly six source-bound archives with their actual hashes' {
  $report=& $validator -AssetPath $dir -Version $version -SourceCommit $commit
  $report.Archives.Count|Should -Be 6
  $report.SourceCommit|Should -BeExactly $commit
  $report.Archives[0].Sha256|Should -BeExactly (Get-FileHash (Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz)).Hash.ToLowerInvariant()
 }
 It 'rejects missing architectures rather than publishing a partial release' {
  Remove-Item (Join-Path $dir TokenForge-1.2.3-win-arm64.zip)
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*exactly six*'
 }
 It 'rejects extra files including accidental private diagnostics' {
  Set-Content (Join-Path $dir private.log) 'synthetic'
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*exactly six*'
 }
 It 'rejects changed archive bytes' {
  Set-Content (Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz) 'changed'
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*does not match*'
 }
 It 'rejects receipts from another source commit' {
  {& $validator -AssetPath $dir -Version $version -SourceCommit ('b'*40)}|Should -Throw '*does not match*'
 }
 It 'rejects runtime substitution even when bytes and filenames match' {
  $file=Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz.json
  $record=Get-Content $file -Raw|ConvertFrom-Json;$record.Runtime='linux-arm64';$record|ConvertTo-Json|Set-Content $file
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*does not match*'
 }
 It 'rejects additional receipt fields rather than forwarding diagnostics' {
  $file=Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz.json
  $record=Get-Content $file -Raw|ConvertFrom-Json;$record|Add-Member NoteProperty PrivateDetail 'synthetic';$record|ConvertTo-Json|Set-Content $file
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*schema*'
 }
 It 'rejects arrays masquerading as scalar receipt fields' {
  $file=Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz.json
  $record=Get-Content $file -Raw|ConvertFrom-Json;$record.Runtime=@('linux-x64','linux-x64');$record|ConvertTo-Json|Set-Content $file
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*field types*'
 }
 It 'rejects oversized receipts before parsing' {
  Set-Content (Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz.json) ('x'*17000)
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*too large*'
 }
 It 'rejects empty archives' {
  [IO.File]::WriteAllBytes((Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz),[byte[]]::new(0))
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*size*'
 }
 It 'rejects links in the release set' -Skip:($IsWindows) {
  $file=Join-Path $dir TokenForge-1.2.3-linux-x64.tar.gz
  Move-Item $file (Join-Path $TestDrive target)
  $null=New-Item -ItemType SymbolicLink -Path $file -Target (Join-Path $TestDrive target)
  {& $validator -AssetPath $dir -Version $version -SourceCommit $commit}|Should -Throw '*Unexpected release asset*'
 }
}
