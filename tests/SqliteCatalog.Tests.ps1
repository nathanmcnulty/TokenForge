BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $native=$env:TOKENFORGE_TEST_NATIVE;$id='11111111-1111-1111-1111-111111111111'
 function New-CatalogSample([string]$Date='2026-01-01T00:00:00Z',[string]$Name='Example'){
  [pscustomobject]@{FetchedAt=$Date;SourceSnapshots=@();Applications=@([pscustomobject]@{AppId=$id;Name=$Name;Ownership='PublishedMicrosoftOwner';PublicClient=$true;Foci=1;Grants=@();Sources=@([pscustomobject]@{Name='Published';Location='https://raw.githubusercontent.com/example/public/main/apps.json';Evidence='PublishedHint';AccessToken='source-secret'});RefreshToken='row-secret'})}
 }
}
Describe 'SQLite application catalog integration' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$sqlite=Join-Path $root applications.sqlite;$json=Join-Path $root applications.json
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
 }
 It 'matches JSON chronology, presence, hashes and non-ASCII projection' {
  foreach($entry in @(@('2026-01-01T00:00:00Z','Café <a> & "b" /'),@('2026-01-02T00:00:00Z','Changed'),@('2026-01-03T00:00:00Z','Café <a> & "b" /'))){
   $doc=New-CatalogSample $entry[0] $entry[1]
   $null=Update-TokenForgeApplicationMetadata $json $doc Discovery
   $null=Update-TokenForgeApplicationMetadata $sqlite $doc Discovery -NativeExecutablePath $native
  }
  $empty=New-CatalogSample '2026-01-05T00:00:00Z';$empty.Applications=@()
  foreach($path in @($json,$sqlite)){
   $null=Update-TokenForgeApplicationMetadata $path $empty Discovery -NativeExecutablePath $native
   $null=Update-TokenForgeApplicationMetadata $path (New-CatalogSample '2026-01-04T00:00:00Z' 'Stale') Discovery -NativeExecutablePath $native
  }
  $a=(Get-TokenForgeApplicationMetadata $json).Applications[$id].Records['Discovery///']
  $b=(Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native).Applications[$id].Records['Discovery///']
  $b.ContentSha256|Should -BeExactly $a.ContentSha256
  $b.Attributes.Name|Should -BeExactly $a.Attributes.Name
  $b.PresentInLatestRun|Should -BeFalse
  $b.PreviousVersions.Count|Should -Be $a.PreviousVersions.Count
  $b.PreviousVersions.Count|Should -Be 3
  $b.FirstSeenAt|Should -Be $a.FirstSeenAt
  $b.LastSeenAt|Should -Be $a.LastSeenAt
  @($b.PreviousVersions.ContentSha256) -join ','|Should -Be (@($a.PreviousVersions.ContentSha256) -join ',')
  $raw=& $native catalog export --database $sqlite
  $LASTEXITCODE|Should -Be 0
  $raw|Should -Not -Match 'source-secret|row-secret|AccessToken|RefreshToken'
  (Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native -PublicOnly).Applications.Count|Should -Be 1
 }
 It 'retains repeated equal-date transitions and imports them idempotently' {
  foreach($name in @('A','B','A','B')){$null=Update-TokenForgeApplicationMetadata $json (New-CatalogSample -Name $name) Discovery;$null=Update-TokenForgeApplicationMetadata $sqlite (New-CatalogSample -Name $name) Discovery -NativeExecutablePath $native}
  $state=Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native
  $state.Applications[$id].Records['Discovery///'].PreviousVersions.Count|Should -Be 3
  $legacy=Join-Path $root imported.sqlite
  (Import-TokenForgeApplicationMetadata $legacy $json -NativeExecutablePath $native).ImportedRuns|Should -Be 4
  (Import-TokenForgeApplicationMetadata $legacy $json -NativeExecutablePath $native).ImportedRuns|Should -Be 0
  (Get-TokenForgeApplicationMetadata $legacy -NativeExecutablePath $native).Applications[$id].Records['Discovery///'].PreviousVersions.Count|Should -Be 3
 }
 It 'keeps private namespaces independent and rejects publication even with selected current views' {
  $doc=New-CatalogSample;$null=Update-TokenForgeApplicationMetadata $sqlite $doc Discovery -NativeExecutablePath $native
  foreach($tenant in @('a','b')){$inventory=[pscustomobject]@{CapturedAt=$doc.FetchedAt;TenantFingerprint=($tenant*64);Applications=$doc.Applications};$null=Update-TokenForgeApplicationMetadata $sqlite $inventory Inventory -NativeExecutablePath $native}
  $state=Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native
  $state.Applications[$id].Records.Count|Should -Be 3
  {Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native -PublicOnly -AppId $id -CurrentOnly}|Should -Throw '*metadata cannot be read*'
  (Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native -AppId '22222222-2222-2222-2222-222222222222' -CurrentOnly).Applications.Count|Should -Be 0
 }
 It 'does not mark omitted partial observations absent' {
  $database=[pscustomobject]@{UpdatedAt='2026-01-01T00:00:00Z';Observations=@([pscustomobject]@{ClientId=$id;ResourceId='00000003-0000-0000-c000-000000000000';TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ObservedAt='2026-01-01T00:00:00Z';ScpScopes=@('User.Read')})}
  $null=Update-TokenForgeApplicationMetadata $sqlite $database ScopeObservations -NativeExecutablePath $native
  $database.UpdatedAt='2026-01-03T00:00:00Z';$database.Observations=@()
  $null=Update-TokenForgeApplicationMetadata $sqlite $database ScopeObservations -NativeExecutablePath $native
  @((Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native).Applications[$id].Records.Values)[0].PresentInLatestRun|Should -BeTrue
 }
 It 'rolls back every row of an invalid native update and protects run identities' {
  $doc=New-CatalogSample;$null=Update-TokenForgeApplicationMetadata $sqlite $doc Discovery -NativeExecutablePath $native
  $envelope=$null
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {param($Document) $script:captured=$Document;@{Updated=$true}}
  $null=Update-TokenForgeApplicationMetadata (Join-Path $root capture.sqlite) (New-CatalogSample '2026-01-02T00:00:00Z' 'Changed') Discovery -NativeExecutablePath $native
  $envelope=$script:captured
  $inputFile=Join-Path $root update.json
  $envelope|ConvertTo-Json -Depth 32|Set-Content $inputFile
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($inputFile,[IO.UnixFileMode]384)}
  $null=& $native catalog update --database $sqlite --input $inputFile
  $LASTEXITCODE|Should -Be 0
  $before=& $native catalog export --database $sqlite
  $null=& $native catalog update --database $sqlite --input $inputFile
  $LASTEXITCODE|Should -Be 0
  $envelope.Rows[0].HashInput='{}';$envelope|ConvertTo-Json -Depth 32|Set-Content $inputFile
  $null=& $native catalog update --database $sqlite --input $inputFile 2>$null
  $LASTEXITCODE|Should -Not -Be 0
  $envelope.Run.Id=[guid]::NewGuid().ToString();$envelope.Run.ApplicationRecordCount=2
  $envelope.Rows=@($envelope.Rows[0],$envelope.Rows[0]);$envelope.Rows[0].HashInput=ConvertTo-Json -InputObject ([ordered]@{Attributes=$envelope.Rows[0].Record.Attributes;Sources=$envelope.Rows[0].Record.Sources}) -Depth 32 -Compress
  $envelope.Rows[1]=@{AppId=$id;Record=@{AccessToken='injected'};HashInput='{}'}
  $envelope|ConvertTo-Json -Depth 32|Set-Content $inputFile
  $null=& $native catalog update --database $sqlite --input $inputFile 2>$null
  $LASTEXITCODE|Should -Not -Be 0
  (& $native catalog export --database $sqlite)|Should -BeExactly $before
 }
 It 'uses current catalog reads for coverage and the packaged research CLI' {
  $null=Update-TokenForgeApplicationMetadata $sqlite (New-CatalogSample) Discovery -NativeExecutablePath $native
  $null=Update-TokenForgeApplicationMetadata $sqlite (New-CatalogSample '2026-01-02T00:00:00Z' 'Changed') Discovery -NativeExecutablePath $native
  (Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native -CurrentOnly).Applications[$id].Records['Discovery///'].PreviousVersions.Count|Should -Be 0
  (Get-TokenForgeResearchCoverage -MetadataPath $sqlite -NativeExecutablePath $native -SummaryOnly).ApplicationCount|Should -Be 1
  $report=& $native research report --state-path $root --summary-only --json|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 0
  $report.ApplicationCount|Should -Be 1
 }
 It 'refreshes an existing sibling SQLite ledger without requiring an explicit metadata path' {
  $null=Update-TokenForgeApplicationMetadata $sqlite (New-CatalogSample) Discovery -NativeExecutablePath $native
  Mock Update-TokenForgeCatalog -ModuleName TokenForge {Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"}
  Mock Invoke-RestMethod -ModuleName TokenForge {@()}
  $null=Update-TokenForgeDiscovery -Path (Join-Path $root discovery.json) -NativeExecutablePath $native
  (Get-TokenForgeApplicationMetadata $sqlite -NativeExecutablePath $native).Runs.Count|Should -Be 2
  Test-Path $json|Should -BeFalse
 }

}
