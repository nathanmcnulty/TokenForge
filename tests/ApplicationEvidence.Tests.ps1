BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $client='11111111-1111-1111-1111-111111111111';$resource='00000003-0000-0000-c000-000000000000'
}
Describe 'Public application evidence lookup' {
 BeforeEach {
  $path=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  $observed=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  $discovery=@{FetchedAt=[DateTimeOffset]::UtcNow.ToString('o');SourceSnapshots=@();Applications=@(@{AppId=$client;Name='Example Client';Sources=@(@{Name='Published';Location='https://raw.githubusercontent.com/example/public/main/apps.json';Evidence='PublishedHint'});Grants=@(@{ResourceId=$resource;Scopes=@('User.Read')})})}
  $null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
  $export=@{SchemaVersion=1;Disclaimer='Synthetic public export';Observations=@(@{ClientId=$client;ResourceId=$resource;ObservedAt='2020-01-01T00:00:00Z';Scopes=@('Mail.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false})}
  $export|ConvertTo-Json -Depth 10|Set-Content $observed
 }
 It 'searches names and IDs without profile or private history and includes provenance' {
  $rows=@(Find-TokenForgeApplicationEvidence $path -Name 'example' -AppId $client)
  $rows.Count|Should -Be 2
  $rows[0].Freshness|Should -Be Fresh
  $rows[0].Sources[0].Location|Should -Be 'https://raw.githubusercontent.com/example/public/main/apps.json'
  $rows[0].ContentSha256|Should -Match '^[a-f0-9]{64}$'
  $rows[0].Disclaimer|Should -Match 'do not guarantee'
  @(Find-TokenForgeApplicationEvidence $path -Name 'absent').Count|Should -Be 0
 }
 It 'keeps published scopes and anonymous observations separate with independent freshness' {
  $rows=@(Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -ResourceId $resource)
  $rows.Count|Should -Be 2
  ($rows|Where-Object EvidenceType -eq PublishedScopeHint).Freshness|Should -Be Fresh
  ($rows|Where-Object EvidenceType -eq AnonymousTenantTokenObservation).Freshness|Should -Be Stale
  @(Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -Scope User.Read,Mail.Read).Count|Should -Be 0
  @(Find-TokenForgeApplicationEvidence $path -Scope user.read).Count|Should -Be 0
  @(Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -Scope Mail.Read).Count|Should -Be 1
 }
 It 'keeps metadata-only applications searchable and preserves absent status' {
  $discovery.Applications[0].Grants=@();$null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
  $discovery.Applications=@();$null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
  $row=Find-TokenForgeApplicationEvidence $path -AppId $client
  $row.EvidenceType|Should -Be PublishedApplicationMetadata
  $row.PresentInLatestRun|Should -BeFalse
 }
 It 'does not discard anonymous observations for unknown IDs or combine different resources' {
  $unknown='22222222-2222-2222-2222-222222222222'
  $export.Observations[0].ClientId=$unknown;$export.Observations[0].ResourceId=$unknown
  $export|ConvertTo-Json -Depth 10|Set-Content $observed
  $row=Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -AppId $unknown
  $row.Name|Should -BeNullOrEmpty
  $row.ResourceId|Should -Be $unknown
  @(Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -ResourceId $resource -Scope Mail.Read).Count|Should -Be 0
 }
 It 'rejects private scope data and invalid inputs before emitting any rows' {
  foreach($field in @('TenantFingerprint','AccessToken')){
   $bad=($export|ConvertTo-Json -Depth 10|ConvertFrom-Json -AsHashtable);$bad.Observations[0][$field]='synthetic-secret'
   $bad|ConvertTo-Json -Depth 10|Set-Content $observed
   $results=[Collections.Generic.List[object]]::new()
   {Find-TokenForgeApplicationEvidence $path -ObservationPath $observed|ForEach-Object {$results.Add($_)}}|Should -Throw '*Details suppressed*'
   $results.Count|Should -Be 0
  }
  {Find-TokenForgeApplicationEvidence $path -ObservationPath (Join-Path $TestDrive missing.json)}|Should -Throw
 }
 It 'rejects mixed private metadata even when filters would exclude private records' {
  $inventory=@{CapturedAt=$discovery.FetchedAt;TenantFingerprint=('a'*64);Applications=$discovery.Applications}
  $null=Update-TokenForgeApplicationMetadata $path $inventory Inventory
  {Find-TokenForgeApplicationEvidence $path -Name absent}|Should -Throw
 }
 It 'flags future dates and retains per-source records instead of upgrading freshness' {
  $export.Observations[0].ObservedAt=[DateTimeOffset]::UtcNow.AddDays(1).ToString('o')
  $export|ConvertTo-Json -Depth 10|Set-Content $observed
  (Find-TokenForgeApplicationEvidence $path -ObservationPath $observed -Scope Mail.Read).Freshness|Should -Be FutureDated
 }
 It 'validates excluded ledger records and history before emitting any row' {
  $other='22222222-2222-2222-2222-222222222222'
  $discovery.Applications+=@{AppId=$other;Name='Other';Sources=$discovery.Applications[0].Sources;Grants=@()}
  $null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
  $discovery.Applications[1].Name='Changed';$discovery.FetchedAt=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o')
  $null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
  $original=Get-Content $path -Raw
  foreach($history in @($false,$true)){
   foreach($field in @('LastSeenAt','ContentSha256')){
    foreach($missing in @($false,$true)){
     $document=$original|ConvertFrom-Json -AsHashtable
     $record=$document.Applications[$other].Records.Values|Select-Object -First 1
     $target=if($history){$record.PreviousVersions[0]}else{$record}
     if($missing){$target.Remove($field)}else{$target[$field]=$null}
     $document|ConvertTo-Json -Depth 100|Set-Content $path
     $rows=[Collections.Generic.List[object]]::new()
     {Find-TokenForgeApplicationEvidence $path -AppId $client|ForEach-Object {$rows.Add($_)}}|Should -Throw '*Details suppressed*'
     $rows.Count|Should -Be 0
    }
   }
  }
 }
 It 'rejects public export links including linked ancestor directories' -Skip:$IsWindows {
  $directory=Join-Path $TestDrive public-link
  $null=New-Item -ItemType SymbolicLink -Path $directory -Target (Split-Path $observed -Parent)
  {Find-TokenForgeApplicationEvidence $path -ObservationPath (Join-Path $directory (Split-Path $observed -Leaf))}|Should -Throw '*Details suppressed*'
  $link=Join-Path $TestDrive export-link.json
  $null=New-Item -ItemType SymbolicLink -Path $link -Target $observed
  {Find-TokenForgeApplicationEvidence $path -ObservationPath $link}|Should -Throw '*Details suppressed*'
 }
 It 'is read-only and rejects malformed exports without partial output' {
  $before=(Get-FileHash $path).Hash
  $null=Find-TokenForgeApplicationEvidence $path -ObservationPath $observed
  (Get-FileHash $path).Hash|Should -Be $before
  foreach($invalid in @(
   '{"SchemaVersion":1,"Observations":[],"observations":[]}',
   '{"SchemaVersion":2,"Observations":[]}',
   '{"SchemaVersion":true,"Observations":[]}',
   '{"SchemaVersion":1,"Observations":[],"Disclaimer":{"AccessToken":"synthetic-secret"}}',
   '{"SchemaVersion":1,"Observations":{}}'
  )){
   [IO.File]::WriteAllText($observed,$invalid)
   {Find-TokenForgeApplicationEvidence $path -ObservationPath $observed}|Should -Throw '*Details suppressed*'
  }
  $export.Observations[0].SignatureValidated=$true
  $export|ConvertTo-Json -Depth 10|Set-Content $observed
  {Find-TokenForgeApplicationEvidence $path -ObservationPath $observed}|Should -Throw
 }

}
