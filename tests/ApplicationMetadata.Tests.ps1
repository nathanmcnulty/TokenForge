BeforeAll {
    Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
    $id='11111111-1111-1111-1111-111111111111'
    function New-MetadataDiscovery([string]$Date='2026-01-01T00:00:00Z',[string]$Name='Example') {
        [pscustomobject]@{FetchedAt=$Date;SourceSnapshots=@([pscustomobject]@{Location='https://example.test/apps';Sha256=('c'*64);HashKind='NormalizedJson';AccessToken='secret-snapshot'});Applications=@([pscustomobject]@{AppId=$id;Name=$Name;Sources=@([pscustomobject]@{Name='Published';Location='https://example.test/apps';Evidence='PublishedHint'});PublicClient=$true;Grants=@();RefreshToken='secret-refresh'})}
    }
}
Describe 'Persistent application metadata' {
    BeforeEach {$path=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')}
    It 'updates every run without duplicating unchanged versions or persisting credentials' {
        $doc=New-MetadataDiscovery
        $null=Update-TokenForgeApplicationMetadata $path $doc Discovery
        $null=Update-TokenForgeApplicationMetadata $path $doc Discovery
        $state=Get-TokenForgeApplicationMetadata $path
        $state.Runs.Count|Should -Be 2
        $record=$state.Applications[$id].Records['Discovery///']
        $record.Attributes.PublicClient|Should -BeTrue
        $record.Sources[0].Location|Should -Be 'https://example.test/apps'
        $record.PreviousVersions.Count|Should -Be 0
        (Get-Content $path -Raw)|Should -Not -Match 'secret-refresh|secret-snapshot|AccessToken|RefreshToken'
        if(-not $IsWindows){[int][IO.File]::GetUnixFileMode($path)|Should -Be 384}
    }
    It 'retains missing IDs and records changes without accepting stale presence' {
        $null=Update-TokenForgeApplicationMetadata $path (New-MetadataDiscovery) Discovery
        $null=Update-TokenForgeApplicationMetadata $path (New-MetadataDiscovery '2026-01-02T00:00:00Z' 'Changed') Discovery
        $empty=New-MetadataDiscovery '2026-01-04T00:00:00Z';$empty.Applications=@()
        $null=Update-TokenForgeApplicationMetadata $path $empty Discovery
        $null=Update-TokenForgeApplicationMetadata $path (New-MetadataDiscovery '2026-01-03T00:00:00Z' 'Older') Discovery
        $record=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///']
        $record.PresentInLatestRun|Should -BeFalse
        $record.Attributes.Name|Should -Be 'Older'
        $record.PreviousVersions.Count|Should -Be 2
        $record.PreviousVersions[1].FirstSeenAt|Should -Be '2026-01-02T00:00:00.0000000+00:00'
        $null=Update-TokenForgeApplicationMetadata $path (New-MetadataDiscovery '2026-01-05T00:00:00Z') Discovery
        (Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///'].PresentInLatestRun|Should -BeTrue
    }
    It 'keeps tenants and account resource observations independent' {
        $doc=New-MetadataDiscovery
        foreach($tenant in @('a','b')){
            $inventory=[pscustomobject]@{CapturedAt=$doc.FetchedAt;TenantFingerprint=($tenant*64);Applications=$doc.Applications}
            $null=Update-TokenForgeApplicationMetadata $path $inventory Inventory
        }
        $db=[pscustomobject]@{UpdatedAt=$doc.FetchedAt;Observations=@([pscustomobject]@{ClientId=$id;ResourceId='00000003-0000-0000-c000-000000000000';TenantFingerprint=('a'*64);PrincipalFingerprint=('d'*64);ObservedAt=$doc.FetchedAt;ScpScopes=@('User.Read');AccessToken='secret-scope'})}
        $null=Update-TokenForgeApplicationMetadata $path $db ScopeObservations
        $state=Get-TokenForgeApplicationMetadata $path
        $state.Applications.Count|Should -Be 1
        $state.Applications[$id].Records.Count|Should -Be 3
        (Get-Content $path -Raw)|Should -Not -Match 'secret-scope'
    }
    It 'fails without changing existing metadata on invalid IDs, incomplete logs or overlapping writers' {
        $doc=New-MetadataDiscovery;$null=Update-TokenForgeApplicationMetadata $path $doc Discovery
        $before=Get-Content $path -Raw
        $bad=New-MetadataDiscovery;$bad.Applications[0].AppId='invalid'
        {Update-TokenForgeApplicationMetadata $path $bad Discovery}|Should -Throw '*application ID*'
        $logs=[pscustomobject]@{CapturedAt=$doc.FetchedAt;TenantFingerprint=('a'*64);Enumeration='Incomplete';Applications=@()}
        {Update-TokenForgeApplicationMetadata $path $logs SignIns}|Should -Throw '*Incomplete*'
        $lock=[IO.File]::Open("$path.lock",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try{{Update-TokenForgeApplicationMetadata $path $doc Discovery}|Should -Throw '*already in use*'}finally{$lock.Dispose()}
        (Get-Content $path -Raw)|Should -BeExactly $before
    }
    It 'automatically updates the sibling catalog on every public discovery refresh' {
        Mock Update-TokenForgeCatalog -ModuleName TokenForge {Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"}
        Mock Invoke-RestMethod -ModuleName TokenForge { @() }
        $discoveryPath=Join-Path $TestDrive 'automatic/discovery.json'
        $null=Update-TokenForgeDiscovery -Path $discoveryPath
        $null=Update-TokenForgeDiscovery -Path $discoveryPath
        $state=Get-TokenForgeApplicationMetadata (Join-Path $TestDrive 'automatic/applications.json')
        $state.Runs.Count|Should -Be 2
        $state.Applications.Count|Should -Be 3
    }
}
Describe 'Metadata nested projection and chronology' {
    It 'drops nested credential fields and supports dictionary provenance' {
        $doc=New-MetadataDiscovery
        $doc.Applications[0].Grants=@(@{ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');AccessToken='nested-secret'})
        $doc.Applications[0].Sources=@(@{Name='Dictionary';Location='https://example.test/dictionary';Evidence='Published'})
        $path=Join-Path $TestDrive 'nested.json'
        $null=Update-TokenForgeApplicationMetadata $path $doc Discovery
        $record=(Get-TokenForgeApplicationMetadata $path).Applications[$id].Records['Discovery///']
        $record.Sources[0].Location|Should -Be 'https://example.test/dictionary'
        $record.Attributes.Grants[0].Scopes|Should -Contain 'User.Read'
        (Get-Content $path -Raw)|Should -Not -Match 'nested-secret|AccessToken'
    }
    It 'preserves scope changes when the input database is reverse chronological' {
        $rows=@(foreach($day in @(3,2,1)){[pscustomobject]@{ClientId=$id;ResourceId='00000003-0000-0000-c000-000000000000';TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ObservedAt="2026-01-0${day}T00:00:00Z";ScpScopes=@("Scope$day")}})
        $path=Join-Path $TestDrive 'chronology.json'
        $db=[pscustomobject]@{UpdatedAt='2026-01-03T00:00:00Z';Observations=$rows}
        $null=Update-TokenForgeApplicationMetadata $path $db ScopeObservations
        $record=@((Get-TokenForgeApplicationMetadata $path).Applications[$id].Records.Values)[0]
        $record.PreviousVersions.Count|Should -Be 2
        $record.Attributes.ScpScopes|Should -Contain 'Scope3'
        $null=Update-TokenForgeApplicationMetadata $path $db ScopeObservations
        @((Get-TokenForgeApplicationMetadata $path).Applications[$id].Records.Values)[0].PreviousVersions.Count|Should -Be 2
    }
}
Describe 'Public CI publication guard' {
    It 'accepts a public discovery catalog and rejects mixed private origins before modification' {
        $path=Join-Path $TestDrive 'public.json'
        $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
        $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
        $discovery=Get-TokenForgeDiscovery -Catalog $catalog
        $null=Update-TokenForgeApplicationMetadata $path $discovery Discovery
        {Get-TokenForgeApplicationMetadata $path -PublicOnly}|Should -Not -Throw
        $private=[pscustomobject]@{CapturedAt=$discovery.FetchedAt;TenantFingerprint=('a'*64);Applications=$discovery.Applications}
        $null=Update-TokenForgeApplicationMetadata $path $private Inventory
        {Get-TokenForgeApplicationMetadata $path -PublicOnly}|Should -Throw '*cannot be read*'
    }
    It 'rejects unexpected historical fields in an otherwise public catalog' {
        $path=Join-Path $TestDrive 'extra.json'
        $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
        $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
        $null=Update-TokenForgeApplicationMetadata $path (Get-TokenForgeDiscovery -Catalog $catalog) Discovery
        $doc=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
        $doc.Runs[0].AccessToken='synthetic-secret'
        $doc|ConvertTo-Json -Depth 100|Set-Content $path
        {Get-TokenForgeApplicationMetadata $path -PublicOnly}|Should -Throw '*cannot be read*'
    }
}
Describe 'Public scalar schema boundaries' {
    It 'rejects nested objects inside public attribute names and history scalar fields' {
        $path=Join-Path $TestDrive 'scalar.json'
        $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
        $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
        $null=Update-TokenForgeApplicationMetadata $path (Get-TokenForgeDiscovery -Catalog $catalog) Discovery
        $original=Get-Content $path -Raw
        foreach($field in @('Name','ContentSha256')){
            $doc=$original|ConvertFrom-Json -AsHashtable
            $record=@($doc.Applications.Values)[0].Records['Discovery///']
            if($field -eq 'Name'){$record.Attributes.Name=@{AccessToken='nested-secret'}}else{$record.ContentSha256=@{AccessToken='nested-secret'}}
            $doc|ConvertTo-Json -Depth 100|Set-Content $path
            {Get-TokenForgeApplicationMetadata $path -PublicOnly}|Should -Throw '*cannot be read*'
        }
    }
}
Describe 'Collected metadata value types' {
    It 'does not serialize a credential object disguised as an allowed attribute' {
        $path=Join-Path $TestDrive 'credential-object.json'
        $doc=New-MetadataDiscovery
        $doc.Applications[0].Name=@{AccessToken='synthetic-secret'}
        {Update-TokenForgeApplicationMetadata $path $doc Discovery}|Should -Throw '*unsupported value type*'
        Test-Path $path|Should -BeFalse
    }
}
Describe 'Metadata date fidelity' {
    It 'preserves UTC DateTime source values regardless of host timezone' {
        $doc=New-MetadataDiscovery
        $doc.FetchedAt=[datetime]::new(2026,1,1,0,0,0,[DateTimeKind]::Utc)
        $path=Join-Path $TestDrive 'typed-date.json'
        $null=Update-TokenForgeApplicationMetadata $path $doc Discovery
        $date=[DateTimeOffset](Get-TokenForgeApplicationMetadata $path).Applications[$id].FirstSeenAt
        $date.UtcDateTime|Should -Be $doc.FetchedAt
    }
}
