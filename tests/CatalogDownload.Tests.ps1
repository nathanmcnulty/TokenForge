BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $export="$PSScriptRoot/../scripts/Export-TokenForgeCatalogDownload.ps1"
 function Read-Download($path){
  $file=[IO.File]::OpenRead($path);$gzip=[IO.Compression.GZipStream]::new($file,[IO.Compression.CompressionMode]::Decompress);$reader=[IO.StreamReader]::new($gzip)
  try{$reader.ReadToEnd()}finally{$reader.Dispose();$gzip.Dispose();$file.Dispose()}
 }
}
Describe 'Compact public catalog downloads' {
 BeforeEach {
  $inputPath=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  $outputPath=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json.gz')
  $id='11111111-1111-1111-1111-111111111111'
  $url='https://raw.githubusercontent.com/example/catalog/main/apps.json'
  $source=[pscustomobject]@{Name='Published';Location=$url;Evidence='PublishedHint'}
  $doc=[pscustomobject]@{FetchedAt='2026-01-01T00:00:00Z';SourceSnapshots=@([pscustomobject]@{Location=$url;Sha256=('c'*64);HashKind='NormalizedJson'});Applications=@([pscustomobject]@{AppId=$id;Name='2026-01-01T00:00:00Z';Sources=@($source);PublicClient=$true;Grants=@();RedirectUris=@('https://example.test/callback')})}
  $null=Update-TokenForgeApplicationMetadata $inputPath $doc Discovery
 }
 It 'round trips the complete public document and preserves literal date-looking names' {
  $r=& $export -InputPath $inputPath -OutputPath $outputPath
  $r.Applications|Should -Be 1
  $json=Read-Download $outputPath
  [Text.Encoding]::UTF8.GetByteCount($json)|Should -Be $r.UncompressedBytes
  [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json))).ToLowerInvariant()|Should -Be $r.ContentSha256
  $json|Should -Be (ConvertTo-Json -InputObject (Get-TokenForgeApplicationMetadata $inputPath -PublicOnly) -Depth 100 -Compress)
  $json|Should -Match '2026-01-01T00:00:00Z'
  if(-not $IsWindows){[int][IO.File]::GetUnixFileMode($outputPath)|Should -Be 384}
 }
 It 'refuses private evidence before creating a download' {
  $inventory=[pscustomobject]@{CapturedAt=$doc.FetchedAt;TenantFingerprint=('a'*64);Applications=$doc.Applications}
  $null=Update-TokenForgeApplicationMetadata $inputPath $inventory Inventory
  {& $export -InputPath $inputPath -OutputPath $outputPath}|Should -Throw
  Test-Path $outputPath|Should -BeFalse
 }
 It 'rejects private run source locations and accepts legacy public source labels' {
  $catalog=Get-TokenForgeApplicationMetadata $inputPath
  $catalog.Runs[0].SourceSnapshots[0].Location='/private/account/secret-source.json'
  $catalog|ConvertTo-Json -Depth 100|Set-Content $inputPath
  {& $export -InputPath $inputPath -OutputPath $outputPath}|Should -Throw
  Test-Path $outputPath|Should -BeFalse
  foreach($label in @('LocalMicrosoftApps','LocalResources')){
   $catalog.Runs[0].SourceSnapshots[0].Location=$label
   $catalog|ConvertTo-Json -Depth 100|Set-Content $inputPath
   $null=Get-TokenForgeApplicationMetadata $inputPath -PublicOnly
  }
 }
 It 'never overwrites an existing output' {
  Set-Content $outputPath original
  {& $export -InputPath $inputPath -OutputPath $outputPath}|Should -Throw '*never overwritten*'
  (Get-Content $outputPath -Raw).Trim()|Should -Be original
 }
 It 'honors WhatIf without creating output' {
  $null=& $export -InputPath $inputPath -OutputPath $outputPath -WhatIf
  Test-Path $outputPath|Should -BeFalse
 }
 It 'reads UTF-8 BOM input and rejects invalid UTF-8' {
  $json=Get-Content $inputPath -Raw
  [IO.File]::WriteAllText($inputPath,$json,[Text.UTF8Encoding]::new($true))
  $null=Get-TokenForgeApplicationMetadata $inputPath
  [IO.File]::WriteAllBytes($inputPath,[byte[]]@(255,255))
  {Get-TokenForgeApplicationMetadata $inputPath}|Should -Throw
 }
}
