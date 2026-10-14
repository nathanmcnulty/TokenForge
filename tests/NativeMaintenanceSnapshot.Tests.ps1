BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native authenticated maintenance snapshot recovery' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  if(-not ('TokenForgeMaintenanceCleanupFixture' -as [type])) {
   Add-Type 'public static class TokenForgeMaintenanceCleanupFixture { public static void Delete(string path) { throw new System.IO.IOException("synthetic deletion failure"); } }'
  }
  function Write-Private([string]$Path,[byte[]]$Bytes) {
   $resolved=[TokenForge.Core.V0220.PrivateFiles]::Resolve($Path,$true)
   $file=[TokenForge.Core.V0220.PrivateFiles]::Open($resolved,$true)
   try{$file.Write($Bytes);$file.Flush($true)}finally{$file.Dispose()}
  }
  function Seal-Fixture([string]$Text) {
   $plain=[Text.Encoding]::UTF8.GetBytes($Text);$nonce=[Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
   $cipher=[byte[]]::new($plain.Length);$tag=[byte[]]::new(16)
   $aes=[Security.Cryptography.AesGcm]::new($key,16)
   try{$aes.Encrypt($nonce,$plain,$cipher,$tag,[Text.Encoding]::UTF8.GetBytes($context))}finally{$aes.Dispose();[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
   [byte[]](@(1)+$nonce+$tag+$cipher)
  }
  function Invoke-Snapshot([string]$Operation,[string[]]$Options,[int]$Exit=0) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-powershell
   foreach($argument in (@('research',$Operation)+$Options)){$start.ArgumentList.Add($argument)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Snapshot fixture timed out.'}
    $process.ExitCode|Should -Be $Exit
    $stdout=$output.GetAwaiter().GetResult();$stderr=$errors.GetAwaiter().GetResult()
    if($Exit){$stdout|Should -BeNullOrEmpty;$stderr|Should -Not -Match ([regex]::Escape($root));($stderr|ConvertFrom-Json).Code|Should -Be OperationFailed}
    else{$stderr|Should -BeNullOrEmpty;$stdout|ConvertFrom-Json}
   }finally{$process.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
  $tenant='a'*64;$principal='b'*64;$context="private-maintenance/v1/$tenant/$principal"
  $key=[Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
  $keyPath=Join-Path $root key.txt;$source=Join-Path $root snapshot.sealed;$outputPath=Join-Path $root restored.json
  Write-Private $keyPath ([Text.Encoding]::UTF8.GetBytes([Convert]::ToBase64String($key)+"`n"))
  $catalogPath=Join-Path $root applications.json
  $id='11111111-1111-1111-1111-111111111111'
  foreach($day in 1,2){
   $discovery=[pscustomobject]@{FetchedAt="2026-01-0${day}T00:00:00Z";SourceSnapshots=@();Applications=@([pscustomobject]@{AppId=$id;Name="Example$day";PublicClient=$true;RedirectUris=@('https://localhost/callback');Grants=@();Sources=@()})}
   $null=Update-TokenForgeApplicationMetadata $catalogPath $discovery Discovery
  }
  $catalog=Get-Content $catalogPath -Raw|ConvertFrom-Json -AsHashtable
  $payload=[ordered]@{
   SchemaVersion=1;Context=$context;Metadata=$catalog
   GrantHistory=@(@{FirstSeenAt='2026-01-01T02:00:00+02:00';LastSeenAt='2026-01-02T00:00:00Z';Grants=@(@{ClientId=$id;ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');PrincipalFingerprint=('c'*64);ConsentType='Principal';AppliesToCurrentPrincipal=$false;Evidence='TenantConfiguredGrant'})})
   LastRun=@{StartedAt='2026-01-03T00:00:00Z';FinishedAt='2026-01-03T01:00:00Z';Discovery='Complete';Inventory='Complete';Grants='Complete';SignIns='Forbidden';SignInFailureReason='Forbidden';SignInSince='2026-01-01T00:00:00Z';SignInUntil='2026-01-03T00:00:00Z';SignInMaxPages=20;Registration='NotRun';Status='Partial'}
  }
  $json=ConvertTo-Json -InputObject $payload -Depth 100
  $blob=Seal-Fixture $json;Write-Private $source $blob
  $options=@('--snapshot-path',$source,'--key-file',$keyPath,'--tenant-fingerprint',$tenant,'--principal-fingerprint',$principal,'--json')
 }
 AfterEach {[Security.Cryptography.CryptographicOperations]::ZeroMemory($key)}
 It 'authenticates complete history and returns only aggregate historical evidence without PowerShell' {
  $result=Invoke-Snapshot inspect-backup $options
  $result.Authenticated|Should -BeTrue;$result.FreshAuthenticationPerformed|Should -BeFalse;$result.Restored|Should -BeFalse
  $result.ApplicationCount|Should -Be 1;$result.CatalogRunCount|Should -Be 2;$result.GrantSnapshotCount|Should -Be 1
  ($result|ConvertTo-Json)|Should -Not -Match 'User.Read|Example|PrincipalFingerprint|key.txt|snapshot.sealed'
  Test-Path $outputPath|Should -BeFalse
 }
 It 'restores exact plaintext to a new private file, reports it, and preserves source/key bytes' {
  $sourceHash=(Get-FileHash $source).Hash;$keyHash=(Get-FileHash $keyPath).Hash
  $result=Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath))
  $result.Restored|Should -BeTrue
  [IO.File]::ReadAllText($outputPath)|Should -BeExactly $json
  [TokenForge.Core.V0220.PrivateFiles]::Resolve($outputPath,$false)|Should -Be $outputPath
  $report=Invoke-Snapshot report @('--maintenance-path',$outputPath,'--tenant-fingerprint',$tenant,'--principal-fingerprint',$principal,'--summary-only','--json')
  $report.ApplicationCount|Should -Be 1
  (Get-FileHash $source).Hash|Should -BeExactly $sourceHash;(Get-FileHash $keyPath).Hash|Should -BeExactly $keyHash
  @(Get-ChildItem $root -Filter '.restore-*' -Force).Count|Should -Be 0
 }
 It 'rejects <Case> before publishing plaintext' -ForEach @(@{Case='WrongKey'},@{Case='WrongContext'},@{Case='CorruptCiphertext'},@{Case='Truncated'},@{Case='Version'},@{Case='OversizedSnapshot'},@{Case='OversizedKey'},@{Case='NoncanonicalKey'}) {
  switch($Case){
   WrongKey {[IO.File]::WriteAllText($keyPath,[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))}
   WrongContext {$options=$options|ForEach-Object {if($_ -ceq $principal){'d'*64}else{$_}}}
   CorruptCiphertext {$blob[-1]=$blob[-1] -bxor 1;[IO.File]::WriteAllBytes($source,$blob)}
   Truncated {[IO.File]::WriteAllBytes($source,[byte[]](1,2))}
   Version {$blob[0]=2;[IO.File]::WriteAllBytes($source,$blob)}
   OversizedSnapshot {$file=[IO.File]::OpenWrite($source);try{$file.SetLength(134217758)}finally{$file.Dispose()}}
   OversizedKey {[IO.File]::WriteAllText($keyPath,'x'*47)}
   NoncanonicalKey {[IO.File]::WriteAllText($keyPath,' '+[Convert]::ToBase64String($key))}
  }
  $null=Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath)) 1
  Test-Path $outputPath|Should -BeFalse
 }
 It 'rejects authenticated malformed <Case> across the complete envelope before returning counts or writing' -ForEach @(@{Case='HistoricalCredential'},@{Case='CurrentCredential'},@{Case='GrantCredential'},@{Case='GrantScalarScopes'},@{Case='GrantDates'},@{Case='LastRunUnknown'},@{Case='LastRunStatus'},@{Case='LastRunDates'},@{Case='EnvelopeUnknown'},@{Case='Namespace'}) {
  switch($Case){
   HistoricalCredential {$payload.Metadata.Applications[$id].Records['Discovery///'].PreviousVersions[0].Attributes.AccessToken='fixture-secret'}
   CurrentCredential {$payload.Metadata.Applications[$id].Records['Discovery///'].Attributes.AccessToken='fixture-secret'}
   GrantCredential {$payload.GrantHistory[0].Grants[0].RefreshToken='fixture-secret'}
   GrantScalarScopes {$payload.GrantHistory[0].Grants[0].Scopes='User.Read'}
   GrantDates {$payload.GrantHistory[0].FirstSeenAt='2026-01-04T00:00:00Z'}
   LastRunUnknown {$payload.LastRun.Headers='fixture-secret'}
   LastRunStatus {$payload.LastRun.Status='Unknown'}
   LastRunDates {$payload.LastRun.StartedAt='2026-01-04T00:00:00Z'}
   EnvelopeUnknown {$payload.Password='fixture-secret'}
   Namespace {$payload.Metadata.Applications[$id].Records['Discovery///'].TenantFingerprint='d'*64}
  }
  [IO.File]::WriteAllBytes($source,(Seal-Fixture (ConvertTo-Json -InputObject $payload -Depth 100)))
  $null=Invoke-Snapshot inspect-backup $options 1
  $null=Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath)) 1
  Test-Path $outputPath|Should -BeFalse
 }
 It 'rejects duplicate envelope fields even after successful decryption' {
  [IO.File]::WriteAllBytes($source,(Seal-Fixture ($json -replace '"SchemaVersion": 1,','"SchemaVersion": 1,"SchemaVersion": 1,')))
  $null=Invoke-Snapshot inspect-backup $options 1
 }
 It 'preserves legacy schema-1 absence of a failure category without fabricating one' {
  $payload.LastRun.Remove('SignInFailureReason')
  $legacy=ConvertTo-Json -InputObject $payload -Depth 100
  [IO.File]::WriteAllBytes($source,(Seal-Fixture $legacy))
  (Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath))).Restored|Should -BeTrue
  [IO.File]::ReadAllText($outputPath)|Should -BeExactly $legacy
  ([IO.File]::ReadAllText($outputPath)|ConvertFrom-Json -AsHashtable).LastRun.ContainsKey('SignInFailureReason')|Should -BeFalse
 }
 It 'preserves an existing destination exactly' {
  Write-Private $outputPath ([Text.Encoding]::UTF8.GetBytes('existing'))
  $null=Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath)) 1
  [IO.File]::ReadAllText($outputPath)|Should -BeExactly existing
 }
 It 'rejects cancellation before publication' {
  $cancel=[Threading.CancellationTokenSource]::new();$cancel.Cancel()
  try{{[TokenForge.Core.MaintenanceSnapshot]::Restore($source,$keyPath,$tenant,$principal,$outputPath,$cancel.Token)}|Should -Throw}finally{$cancel.Dispose()}
  Test-Path $outputPath|Should -BeFalse
 }
 It 'publishes one restored file under concurrent writers and removes temporary plaintext' {
  $processes=@(1..4|ForEach-Object {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-powershell
   foreach($argument in (@('research','restore-backup')+$options+@('--output-path',$outputPath))){$start.ArgumentList.Add($argument)}
   [Diagnostics.Process]::Start($start)
  })
  $success=0
  foreach($process in $processes){
   try{
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Restore race fixture timed out.'}
    if($process.ExitCode -eq 0){($stdout.GetAwaiter().GetResult()|ConvertFrom-Json).Restored|Should -BeTrue;$success++}
    else{($stderr.GetAwaiter().GetResult()|ConvertFrom-Json).Code|Should -Be OperationFailed}
   }finally{$process.Dispose()}
  }
  $success|Should -Be 1;[IO.File]::ReadAllText($outputPath)|Should -BeExactly $json
  @(Get-ChildItem $root -Filter '.restore-*' -Force).Count|Should -Be 0
 }
 It 'surfaces cleanup failure <Published> without raw paths and distinguishes published output' -ForEach @(@{Published=$false},@{Published=$true}) {
  $method=[TokenForge.Core.MaintenanceSnapshot].GetMethod('CleanupTemporary',[Reflection.BindingFlags]'Static,NonPublic')
  $delete=[TokenForgeMaintenanceCleanupFixture].GetMethod('Delete').CreateDelegate([Action[string]])
  $parameters=[object[]]::new(3);$parameters.SetValue($outputPath,0);$parameters.SetValue([bool]$Published,1);$parameters.SetValue($delete,2)
  try{$method.Invoke($null,$parameters);throw 'Expected cleanup failure'}catch{
   $cause=$_.Exception
   while($cause -and $cause -isnot [TokenForge.Core.MaintenanceSnapshotCleanupException]){$cause=$cause.InnerException}
   $cause|Should -Not -BeNullOrEmpty;$cause.Restored|Should -Be $Published;$cause.Message|Should -Not -Match 'raw secret|restored.json'
  }
 }
 It 'rejects conflicting report input <Option> before reading a snapshot' -ForEach @(@{Option='--metadata-path'},@{Option='--flow-path'},@{Option='--state-path'},@{Option='--profile'},@{Option='--root'}) {
  $null=Invoke-Snapshot report @('--maintenance-path',$outputPath,'--tenant-fingerprint',$tenant,'--principal-fingerprint',$principal,$Option,'missing','--json') 1
 }
 It 'requires explicit namespace for a standalone maintenance report' {
  $null=Invoke-Snapshot report @('--maintenance-path',$outputPath,'--json') 1
 }
 It 'rejects duplicate key options without publishing plaintext' {
  $null=Invoke-Snapshot restore-backup ($options+@('--key-file',$keyPath,'--output-path',$outputPath)) 1
  Test-Path $outputPath|Should -BeFalse
 }
 It 'rejects an output option on read-only inspection' {
  $null=Invoke-Snapshot inspect-backup ($options+@('--output-path',$outputPath)) 1
  Test-Path $outputPath|Should -BeFalse
 }
 It 'rejects Unix <Case> input/output boundaries' -Skip:$IsWindows -ForEach @(@{Case='SharedKey'},@{Case='SharedSnapshot'},@{Case='LinkedSnapshot'},@{Case='LinkedOutput'}) {
  switch($Case){
   SharedKey {[IO.File]::SetUnixFileMode($keyPath,[IO.UnixFileMode]420)}
   SharedSnapshot {[IO.File]::SetUnixFileMode($source,[IO.UnixFileMode]420)}
   LinkedSnapshot {$link=Join-Path $root linked.sealed;$null=New-Item -ItemType SymbolicLink -Path $link -Target $source;$options=$options|ForEach-Object {if($_ -ceq $source){$link}else{$_}}}
   LinkedOutput {$null=New-Item -ItemType SymbolicLink -Path $outputPath -Target $source}
  }
  $null=Invoke-Snapshot restore-backup ($options+@('--output-path',$outputPath)) 1
  [Convert]::ToBase64String([IO.File]::ReadAllBytes($source))|Should -BeExactly ([Convert]::ToBase64String($blob))
 }
}
