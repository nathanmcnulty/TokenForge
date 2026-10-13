BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 $id='11111111-1111-1111-1111-111111111111'
 function New-ClaimsDiscovery([string]$OtherName='Other',[string]$Date='2026-01-01T00:00:00Z') {
  $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
  $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
  $apps=@([pscustomobject]@{AppId=$id;AppDisplayName=$OtherName;AppOwnerOrganizationId='72f988bf-86f1-41af-91ab-2d7cd011db47';Source='Learn'},[pscustomobject]@{AppId=$id;AppDisplayName='Third';AppOwnerOrganizationId='33333333-3333-3333-3333-333333333333';Source='GitHub'})
  $result=Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps $apps -MicrosoftAppsSource 'https://raw.githubusercontent.com/example/public/main/apps.json'
  $result.FetchedAt=$Date
  $result
 }
}
Describe 'Source-attributed discovery metadata' {
 It 'preserves literal names while downloading and reading raw source datasets' {
  $scopeName='2026-01-01T00:00:00+02:00';$otherName='2025-12-31T22:00:00+00:00'
  $data=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content "$PSScriptRoot/fixtures/catalog.json" -Raw))
  $data.apps[$id].name=$scopeName
  $rawScopes=ConvertTo-Json -InputObject $data -Depth 32 -Compress
  $rawApps=ConvertTo-Json -InputObject @(@{AppId=$id;AppDisplayName=$otherName;AppOwnerOrganizationId='72f988bf-86f1-41af-91ab-2d7cd011db47';Source='Graph'}) -Compress
  Mock Invoke-WebRequest -ModuleName TokenForge {param($Uri)
   @{Content=$(if($Uri.AbsolutePath.EndsWith('/scopes.json')){$rawScopes}elseif($Uri.AbsolutePath.EndsWith('/apps.json')){$rawApps}else{'[]'})}
  }
  $path=Join-Path $TestDrive source-discovery.json
  $metadata=Join-Path $TestDrive source-applications.json
  $doc=Update-TokenForgeDiscovery -Path $path -MetadataPath $metadata -ScopesUri 'https://raw.githubusercontent.com/example/public/main/scopes.json' -MicrosoftAppsUri 'https://raw.githubusercontent.com/example/public/main/apps.json' -ResourcesUri 'https://raw.githubusercontent.com/example/public/main/resources.json'
  $app=@($doc.Applications|Where-Object AppId -eq $id)[0]
  $app.Name|Should -BeExactly $scopeName
  @($app.SourceClaims.Name)|Should -Contain $scopeName
  @($app.SourceClaims.Name)|Should -Contain $otherName
  @((Get-TokenForgeApplicationMetadata $metadata -PublicOnly).Applications[$id].Records['Discovery///'].Attributes.SourceClaims.Name)|Should -Contain $otherName
  Should -Invoke Invoke-WebRequest -ModuleName TokenForge -Exactly -Times 3
 }
 It 'skips and counts zero-ID catalog placeholders without failing discovery' {
  $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
  $placeholder=$catalog.Applications[0]|Select-Object *
  $placeholder.ClientId=[guid]::Empty.ToString();$catalog.Applications+=@($placeholder)
  $doc=Get-TokenForgeDiscovery -Catalog $catalog
  $doc.InvalidSourceRecordCount|Should -Be 1
  @($doc.Applications.AppId)|Should -Not -Contain ([guid]::Empty.ToString())
  $doc.Applications.Count|Should -Be 3
 }
 It 'retains alternative names and nonselected owners without changing selected ownership' {
  $doc=New-ClaimsDiscovery
  $app=@($doc.Applications|Where-Object AppId -eq $id)[0]
  $doc.SchemaVersion|Should -Be 2
  $app.Name|Should -BeExactly 'Fixture public client'
  $app.OwnerTenantId|Should -BeExactly '72f988bf-86f1-41af-91ab-2d7cd011db47'
  $app.Ownership|Should -BeExactly 'PublishedMicrosoftOwner'
  @($app.SourceClaims.Name)|Should -Contain 'Other'
  @($app.SourceClaims|Where-Object {$_.Contains('OwnerTenantId')}|ForEach-Object OwnerTenantId)|Should -Contain '33333333-3333-3333-3333-333333333333'
  @($app.MetadataConflicts.Field)|Should -Contain 'Name'
  @($app.MetadataConflicts.Field)|Should -Contain 'OwnerTenantId'
  $resource=@($doc.Applications|Where-Object AppId -eq '00000003-0000-0000-c000-000000000000')[0]
  @($resource.SourceClaims.IdentifierUris)|Should -Contain 'https://graph.microsoft.com'
  @($resource.MetadataConflicts|ForEach-Object Field)|Should -Not -Contain 'Name'
 }
 It 'adds history when an alternative changes and excludes date-only observations from the content hash' {
  $path=Join-Path $TestDrive changes.json
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery) Discovery
  $first=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///']
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery -Date '2026-01-02T00:00:00Z') Discovery
  $same=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///']
  $same.ContentSha256|Should -BeExactly $first.ContentSha256
  $same.PreviousVersions.Count|Should -Be 0
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery -OtherName 'Changed alternative' -Date '2026-01-03T00:00:00Z') Discovery
  $changed=(Get-TokenForgeApplicationMetadata $path -PublicOnly).Applications[$id].Records['Discovery///']
  $changed.Attributes.Name|Should -BeExactly $first.Attributes.Name
  $changed.ContentSha256|Should -Not -Be $first.ContentSha256
  $changed.PreviousVersions.Count|Should -Be 1
  @($changed.PreviousVersions[0].Attributes.SourceClaims.Name)|Should -Contain 'Other'
 }
 It 'keeps claim-bearing content stable when contributing rows are reordered or repeated' {
  $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
  $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
  $rows=@([pscustomobject]@{AppId=$id;AppDisplayName='Alpha';AppOwnerOrganizationId='72f988bf-86f1-41af-91ab-2d7cd011db47';Source='Learn'},[pscustomobject]@{AppId=$id;AppDisplayName='Beta';AppOwnerOrganizationId='33333333-3333-3333-3333-333333333333';Source='GitHub'})
  $path=Join-Path $TestDrive reordered.json
  $first=Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps $rows
  $first.FetchedAt='2026-01-01T00:00:00Z';$null=Update-TokenForgeApplicationMetadata $path $first Discovery
  $hash=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///'].ContentSha256
  $second=Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps @($rows[1],$rows[0],$rows[1])
  $second.FetchedAt='2026-01-02T00:00:00Z';$null=Update-TokenForgeApplicationMetadata $path $second Discovery
  $read=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///']
  $read.ContentSha256|Should -BeExactly $hash
  $read.PreviousVersions.Count|Should -Be 0
 }
 It 'reads v1 JSON without rewriting it and preserves its record hash on a claim-free refresh' {
  $path=Join-Path $TestDrive legacy.json
  $doc=New-ClaimsDiscovery
  foreach($app in $doc.Applications){$app.PSObject.Properties.Remove('SourceClaims');$app.PSObject.Properties.Remove('MetadataConflicts')}
  $null=Update-TokenForgeApplicationMetadata $path $doc Discovery
  $legacy=Get-TokenForgeApplicationMetadata $path;$legacy.SchemaVersion=1
  ConvertTo-Json -InputObject $legacy -Depth 100|Set-Content $path
  $before=(Get-FileHash $path).Hash
  $read=Get-TokenForgeApplicationMetadata $path
  $read.SchemaVersion|Should -Be 1
  (Get-FileHash $path).Hash|Should -BeExactly $before
  $hash=$read.Applications[$id].Records['Discovery///'].ContentSha256
  $doc.FetchedAt='2026-01-02T00:00:00Z';$null=Update-TokenForgeApplicationMetadata $path $doc Discovery
  $updated=Get-TokenForgeApplicationMetadata $path
  $updated.SchemaVersion|Should -Be 2
  $updated.Applications[$id].Records['Discovery///'].ContentSha256|Should -BeExactly $hash
  $updated.Applications[$id].Records['Discovery///'].PreviousVersions.Count|Should -Be 0
 }
 It 'rejects unknown nested fields, forged conflicts and private locations in historical public claims' {
  $path=Join-Path $TestDrive historical.json
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery) Discovery
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery -OtherName 'Changed' -Date '2026-01-02T00:00:00Z') Discovery
  $saved=Get-Content $path -Raw
  foreach($mode in @('Credential','Conflict','PrivateSource')){
   $doc=[TokenForge.Core.DiscoverySourceClaims]::ReadCatalog($saved)
   $attrs=$doc.Applications[$id].Records['Discovery///'].PreviousVersions[0].Attributes
   if($mode -eq 'Credential'){$attrs.SourceClaims[0].Add('AccessToken','synthetic')}
   elseif($mode -eq 'Conflict'){$attrs.MetadataConflicts=@()}
   else{$attrs.SourceClaims[0].Location='LocalPrivateSource';$normalized=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata((ConvertTo-Json -InputObject $attrs.SourceClaims -Depth 32 -Compress),$id);$attrs.SourceClaims=$normalized.SourceClaims;$attrs.MetadataConflicts=$normalized.MetadataConflicts}
   ConvertTo-Json -InputObject $doc -Depth 100|Set-Content $path
   {Get-TokenForgeApplicationMetadata $path -PublicOnly -CurrentOnly}|Should -Throw '*metadata cannot be read*'
  }
 }
 It 'preserves date-looking claims and rejects a v1 envelope containing v2 attributes' {
  $path=Join-Path $TestDrive literal.json
  $name='2026-01-01T00:00:00+02:00'
  $null=Update-TokenForgeApplicationMetadata $path (New-ClaimsDiscovery -OtherName $name) Discovery
  $read=Get-TokenForgeApplicationMetadata $path
  @($read.Applications[$id].Records['Discovery///'].Attributes.SourceClaims.Name)|Should -Contain $name
  $read.SchemaVersion=1
  ConvertTo-Json -InputObject $read -Depth 100|Set-Content $path
  {Get-TokenForgeApplicationMetadata $path}|Should -Throw '*metadata cannot be read*'
 }
 It 'freezes and rereads v2 weekly discovery without normalizing literal text' {
  $doc=New-ClaimsDiscovery -OtherName '2026-01-01T00:00:00+02:00'
  $public=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $doc -Depth 100))
  $state=New-TfCiState $public -ChunkSize 2
  $read=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $state -Depth 100))
  {Assert-TfCiState $read}|Should -Not -Throw
  $read.PlanId|Should -BeExactly $state.PlanId
  $other=New-ClaimsDiscovery -OtherName '2025-12-31T22:00:00+00:00'
  $other.FetchedAt=$doc.FetchedAt
  $otherPublic=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $other -Depth 100))
  (Get-TfCiHash @{Discovery=$otherPublic})|Should -Not -Be (Get-TfCiHash @{Discovery=$public})
 }
 It 'rejects private claim locations independently of otherwise public provenance in frozen recipes' {
  $doc=New-ClaimsDiscovery
  $public=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $doc -Depth 100))
  $app=@($public.Applications|Where-Object AppId -eq $id)[0]
  $app.SourceClaims[0].Location='LocalPrivateSource'
  $claims=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata((ConvertTo-Json -InputObject $app.SourceClaims -Depth 32 -Compress),$id)
  $app.SourceClaims=$claims.SourceClaims;$app.MetadataConflicts=$claims.MetadataConflicts
  {New-TfCiState $public}|Should -Throw
 }
}
