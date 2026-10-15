BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $compare="$PSScriptRoot/../scripts/Compare-TokenForgePermissionIdentifiers.ps1"
}
Describe 'Public permission identifier comparison' {
 BeforeEach {
  $catalogPath=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  $permissionPath=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  $first='11111111-1111-1111-1111-111111111111';$second='22222222-2222-2222-2222-222222222222';$third='33333333-3333-3333-3333-333333333333'
  $url='https://raw.githubusercontent.com/example/catalog/main/apps.json'
  $source=[pscustomobject]@{Name='Published';Location=$url;Evidence='PublishedEntraDocs'}
  $discovery=[pscustomobject]@{FetchedAt='2026-01-01T00:00:00Z';SourceSnapshots=@([pscustomobject]@{Location=$url;Sha256=('c'*64);HashKind='NormalizedJson'});Applications=@($second,$first|ForEach-Object {[pscustomobject]@{AppId=$_;Name='2026-01-01T00:00:00Z';Sources=@($source);Grants=@();RedirectUris=@()}})}
  $null=Update-TokenForgeApplicationMetadata $catalogPath $discovery Discovery
  $delegated=[ordered]@{id=$first;value='User.Read';isAdmin=$false;isEnabled=$true;consentDescription=$null;consentDisplayName='';adminConsentDescription='';adminConsentDisplayName=''}
  $application=[ordered]@{id=$first;value='Directory.Read.All';isAdmin=$false;isEnabled=$true;consentDescription=$null;consentDisplayName=$null;allowedMemberTypes=@('Application')}
  $snapshot=[ordered]@{Format='TokenForgePublicPermissions';SchemaVersion=1;Evidence='PublicSourceDefinitions';ResourceId='00000003-0000-0000-c000-000000000000';RetrievedAt='2026-01-01T00:00:00.0000000+00:00';Source=[ordered]@{Repository='https://github.com/microsoftgraph/microsoft-graph-devx-content';Path='permissions/permissions-descriptions.json';Commit=('a'*40);RawSha256=('b'*64)};Permissions=[ordered]@{delegatedScopesList=@($delegated);applicationScopesList=@($application)}}
  $snapshot|ConvertTo-Json -Depth 16 -Compress|Set-Content $permissionPath
 }
 It 'counts unique identifiers separately from cross-kind definitions without changing either input' {
  $before=@($catalogPath,$permissionPath|ForEach-Object {(Get-FileHash $_).Hash})
  $r=& $compare -CatalogPath $catalogPath -PermissionSnapshotPath $permissionPath
  $r.Counts.MatchedIdentifiers|Should -Be 1
  $r.Counts.MatchedDefinitions|Should -Be 2
  $r.Counts.UnmatchedCatalogIdentifiers|Should -Be 1
  $r.Counts.DelegatedDefinitions|Should -Be 1
  $r.Counts.ApplicationDefinitions|Should -Be 1
  $r.PSObject.Properties.Name|Should -Not -Contain Matches
  $r.Evidence|Should -BeExactly PublicIdentifierOverlap
  $r.PermissionSnapshot.Source.Commit|Should -BeExactly ('a'*40)
  $r.Catalog.ContentSha256|Should -Match '\A[a-f0-9]{64}\z'
  $after=@($catalogPath,$permissionPath|ForEach-Object {(Get-FileHash $_).Hash})
  $after|Should -Be $before
 }
 It 'returns sorted identifiers and preserves permission kind/value pairs' {
  $delegated.id=$second;$application.id=$first
  $snapshot|ConvertTo-Json -Depth 16 -Compress|Set-Content $permissionPath
  $r=& $compare -CatalogPath $catalogPath -PermissionSnapshotPath $permissionPath -IncludeMatches
  $r.Matches.Count|Should -Be 2
  $r.Matches[0].Id|Should -BeExactly $first
  $r.Matches[0].Definitions[0].PermissionType|Should -BeExactly Application
  $r.Matches[0].Definitions[0].Value|Should -BeExactly Directory.Read.All
  $r.Matches[1].Id|Should -BeExactly $second
  $r.Matches[1].Definitions[0].PermissionType|Should -BeExactly Delegated
 }
 It 'returns an empty match array when no identifier overlaps' {
  $delegated.id=$third;$application.id=$third
  $snapshot|ConvertTo-Json -Depth 16 -Compress|Set-Content $permissionPath
  $r=& $compare -CatalogPath $catalogPath -PermissionSnapshotPath $permissionPath -IncludeMatches
  $r.Counts.MatchedIdentifiers|Should -Be 0
  $r.Counts.UnmatchedCatalogIdentifiers|Should -Be 2
  $r.Matches|Should -HaveCount 0
 }
 It 'rejects private catalog history before emitting any comparison' {
  $catalog=Get-TokenForgeApplicationMetadata $catalogPath
  $record=$catalog.Applications[$first].Records['Discovery///']
  $record.PreviousVersions=@(@{FirstSeenAt=$record.FirstSeenAt;LastSeenAt=$record.LastSeenAt;Attributes=$record.Attributes;Sources=@(@{Name='private';Location='/private/source';Evidence='PublishedEntraDocs'});ContentSha256=$record.ContentSha256})
  $catalog|ConvertTo-Json -Depth 100|Set-Content $catalogPath
  $output=[Collections.Generic.List[object]]::new()
  {& $compare -CatalogPath $catalogPath -PermissionSnapshotPath $permissionPath -IncludeMatches|ForEach-Object {$output.Add($_)}}|Should -Throw '*details suppressed*'
  $output.Count|Should -Be 0
 }
 It 'does not create missing catalog files or directories (<Extension>)' -ForEach @(@{Extension='json'},@{Extension='sqlite'}) {
  $missingRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $missing=Join-Path $missingRoot ('applications.'+$Extension)
  {& $compare -CatalogPath $missing -PermissionSnapshotPath $permissionPath}|Should -Throw '*details suppressed*'
  Test-Path $missingRoot|Should -BeFalse
 }
 It 'rejects linked catalogs' -Skip:$IsWindows {
  $link=$catalogPath+'.link';$null=New-Item -ItemType SymbolicLink -Path $link -Target $catalogPath
  {& $compare -CatalogPath $link -PermissionSnapshotPath $permissionPath}|Should -Throw '*details suppressed*'
 }
 It 'compares existing SQLite public catalogs without changing database bytes' -Skip:(-not $nativeAvailable) {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $sqlite=Join-Path $root 'applications.sqlite'
  $null=Import-TokenForgeApplicationMetadata -Path $sqlite -InputPath $catalogPath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $hash=(Get-FileHash $sqlite).Hash
  $r=& $compare -CatalogPath $sqlite -PermissionSnapshotPath $permissionPath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE -IncludeMatches
  $r.Counts.MatchedIdentifiers|Should -Be 1
  $r.Matches[0].Definitions|Should -HaveCount 2
  (Get-FileHash $sqlite).Hash|Should -BeExactly $hash
 }
 It 'rejects malformed permission provenance before returning identifiers' {
  $snapshot.Source.Commit=@(('a'*40),('b'*40))
  $snapshot|ConvertTo-Json -Depth 16 -Compress|Set-Content $permissionPath
  {& $compare -CatalogPath $catalogPath -PermissionSnapshotPath $permissionPath}|Should -Throw '*details suppressed*'
 }
}
