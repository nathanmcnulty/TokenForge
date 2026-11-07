BeforeAll {
 $package=$env:TOKENFORGE_TEST_LOCAL_PACKAGE
 if(-not $package){throw 'Requires the final extracted local-publication package; no download/build fallback.'}
 . (Join-Path $package scripts/TokenForgeLocalPublication.ps1)
 . (Join-Path $package scripts/TokenForgePublicHealth.ps1)
 Initialize-TokenForgeHealthRuntime (Join-Path $package tokenforge)
 $runtimePath=Join-Path $TestDrive runtime.json
 $inventory=New-TokenForgeLocalPublicationRuntimeInventory -OutputPath $runtimePath
 $doc=Read-TfLocalDocument $runtimePath 4MB
 $manifest=Read-TfLocalDocument (Join-Path $package public-health-package.json) 1MB
 $policy=@{RuntimeInventorySha256=$inventory.Sha256;PackageManifestSha256=$manifest.Sha256;SourceCommit=$manifest.Value.sourceRevision}
}
Describe 'Actual extracted publisher assets' {
 It 'verifies the complete actual package, complete PowerShell installation and loaded credential assembly' {
  $inventory.AuthorizationEstablished|Should -BeFalse
  $doc.Value.PowerShellFiles.Count|Should -BeGreaterThan 10
  {Assert-TfLocalRuntimeInventory $doc $policy}|Should -Not -Throw
 }
 It 'refuses stale package, source or runtime identity bindings' {
  foreach($field in @('PackageManifestSha256','SourceCommit','RuntimeInventorySha256')){
   $saved=$policy[$field];$policy[$field]='f'*$saved.Length
   try{{Assert-TfLocalRuntimeInventory $doc $policy}|Should -Throw}finally{$policy[$field]=$saved}
  }
 }
 It 'detects changed publisher bytes using an isolated private copy' {
  $copy=Join-Path $TestDrive tamper-package
  Copy-Item -LiteralPath $package -Destination $copy -Recurse
  try{
   . (Join-Path $copy scripts/TokenForgeLocalPublication.ps1)
   $copyInventory=New-TokenForgeLocalPublicationRuntimeInventory -OutputPath (Join-Path $TestDrive copy-runtime.json)
   $copyDoc=Read-TfLocalDocument $copyInventory.Path 4MB
   $copyPolicy=@{RuntimeInventorySha256=$copyInventory.Sha256;PackageManifestSha256=$policy.PackageManifestSha256;SourceCommit=$policy.SourceCommit}
   {Assert-TfLocalRuntimeInventory $copyDoc $copyPolicy}|Should -Not -Throw
   $path=Join-Path $copy scripts/TokenForgeLocalPublicationGit.ps1
   [IO.File]::AppendAllText($path,"`n# synthetic tamper`n")
   {Assert-TfLocalRuntimeInventory $copyDoc $copyPolicy}|Should -Throw '*package bytes*'
  }finally{. (Join-Path $package scripts/TokenForgeLocalPublication.ps1)}
  {Assert-TfLocalRuntimeInventory $doc $policy}|Should -Not -Throw
 }
 It 'detects a changed runtime file hash and omitted inventory member' {
  $key=@($doc.Value.PowerShellFiles.Keys)[0];$saved=$doc.Value.PowerShellFiles[$key]
  try{
   $doc.Value.PowerShellFiles[$key]=@{Bytes=$saved.Bytes;Sha256=('f'*64)}
   {Assert-TfLocalRuntimeInventory $doc $policy}|Should -Throw '*PowerShell bytes*'
   $doc.Value.PowerShellFiles.Remove($key)
   {Assert-TfLocalRuntimeInventory $doc $policy}|Should -Throw '*PowerShell membership*'
  }finally{$doc.Value.PowerShellFiles[$key]=$saved}
 }
}
