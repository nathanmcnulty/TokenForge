BeforeAll {
    $repo=Split-Path $PSScriptRoot -Parent
    $native=$env:TOKENFORGE_TEST_NATIVE
    if(-not $native){throw 'Adapter tests require the existing reviewed Linux package.'}
    . "$repo/scripts/TokenForgePublicHealth.ps1"
    Initialize-TokenForgeHealthRuntime $native
    function New-AdapterRow([string]$Id='11111111-aaaa-4aaa-8aaa-111111111111',[string]$Source='EntraDocs') {
        [ordered]@{AppId=$Id;AppDisplayName='Synthetic documentation candidate';AppOwnerOrganizationId='';Source=$Source}
    }
    function Convert-AdapterRows($Rows) {ConvertTo-TokenForgeHealthMicrosoftApps @($Rows) ('a'*64)}
    function Invoke-AdapterCollection($Rows,[string]$Previous) {
        $fixtures=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($fixtures)
        Copy-Item "$repo/tests/fixtures/public-health/*" $fixtures
        ConvertTo-Json -InputObject @($Rows) -Depth 10|Set-Content (Join-Path $fixtures microsoftApps.json) -Encoding utf8NoBOM
        $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $options=@{OutputPath=$out;NativeExecutablePath=$native;SourceRevision=('a'*40);FixturePath=$fixtures}
        if($Previous){$options.PreviousExchangePath=$Previous}
        $result=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @options|ConvertFrom-Json
        [pscustomobject]@{Path=$out;Result=$result;Exchange=Read-TokenForgeHealthExchange $out;RawPath=(Join-Path $fixtures microsoftApps.json)}
    }
    function Save-AdapterExchange($Exchange) {
        foreach($file in Get-ChildItem $Exchange.Path){[IO.File]::SetUnixFileMode($file.FullName,[IO.UnixFileMode]384)}
        $Exchange.Exchange.Health|ConvertTo-Json -Depth 20|Set-Content (Join-Path $Exchange.Path health.json) -Encoding utf8NoBOM
        $m=$Exchange.Exchange.Manifest
        $b=[IO.File]::ReadAllBytes((Join-Path $Exchange.Path health.json));$m.files['health.json'].bytes=$b.Length;$m.files['health.json'].sha256=Get-TokenForgeHealthHash $b
        $m|ConvertTo-Json -Depth 20|Set-Content (Join-Path $Exchange.Path manifest.json) -Encoding utf8NoBOM
    }
}
Describe 'Bounded MicrosoftApps consumer adaptation' {
    It 'normalizes case and surrounding whitespace without mutating source rows' {
        $row=New-AdapterRow (' 11111111-AAAA-4AAA-8AAA-111111111111'+[char]0x00a0)
        $r=Convert-AdapterRows @($row)
        $r.Records.Count|Should -Be 1
        $r.Records[0].AppId|Should -BeExactly '11111111-aaaa-4aaa-8aaa-111111111111'
        $r.Records[0].Source|Should -BeExactly EntraDocs
        $r.Accounting.normalizedRecordCount|Should -Be 1
        $null=Assert-TokenForgeHealthSource microsoftApps $r.Records
        $row.AppId|Should -BeExactly (' 11111111-AAAA-4AAA-8AAA-111111111111'+[char]0x00a0)
    }
    It 'quarantines malformed documentation identities without repairing them (<Case>)' -ForEach @(
        @{Case='corrupt suffix';Id=('11111111-aaaa-4aaa-8aaa-111111111111'+[char]0x00c2+[char]0x00a0)},
        @{Case='braces';Id='{11111111-aaaa-4aaa-8aaa-111111111111}'},
        @{Case='compact';Id='11111111aaaa4aaa8aaa111111111111'},@{Case='empty';Id=''}
    ) {
        $row=New-AdapterRow $Id
        $r=Convert-AdapterRows @($row,(New-AdapterRow '22222222-aaaa-4aaa-8aaa-222222222222'))
        $r.Accounting.rawRecordCount|Should -Be 2
        $r.Accounting.admittedRecordCount|Should -Be 1
        $r.Accounting.quarantinedRecordCount|Should -Be 1
        $r.Accounting.quarantine[0].index|Should -Be 0
        $r.Accounting.quarantine[0].recordSha256|Should -BeExactly (Get-TokenForgeHealthHash ([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $row -Compress))))
        $r.Records[0].AppId|Should -BeExactly '22222222-aaaa-4aaa-8aaa-222222222222'
        ($r.Accounting|ConvertTo-Json -Depth 10)|Should -Not -Match 'Synthetic documentation|AppDisplayName|AppOwnerOrganizationId'
    }
    It 'keeps canonical validation and non-documentation identities strict' {
        $row=New-AdapterRow ('11111111-aaaa-4aaa-8aaa-111111111111'+[char]0x00c2+[char]0x00a0)
        {Assert-TokenForgeHealthSource microsoftApps @($row)}|Should -Throw
        $row.Source='Graph';{Convert-AdapterRows @($row)}|Should -Throw
        $row.Source='entRAdocs';{Convert-AdapterRows @($row)}|Should -Throw
    }
    It 'validates all fields even on excluded records (<Case>)' -ForEach @(
        @{Case='unknown field'},@{Case='unsafe name'},@{Case='unsafe source'},@{Case='bad owner'},
        @{Case='null ID'},@{Case='numeric ID'},@{Case='array ID'},@{Case='oversized ID'},@{Case='credential ID'},@{Case='control ID'}
    ) {
        $row=New-AdapterRow 'malformed'
        switch($Case){
            'unknown field' {$row.Extra='ignored?'}
            'unsafe name' {$row.AppDisplayName='Bearer synthetic'}
            'unsafe source' {$row.Source='Bearer synthetic'}
            'bad owner' {$row.AppOwnerOrganizationId='bad'}
            'null ID' {$row.AppId=$null}
            'numeric ID' {$row.AppId=1}
            'array ID' {$row.AppId=@('bad')}
            'oversized ID' {$row.AppId='x'*129}
            'credential ID' {$row.AppId='access_token'}
            'control ID' {$row.AppId="bad`n"}
        }
        {Convert-AdapterRows @((New-AdapterRow),$row)}|Should -Throw
    }
    It 'accounts for zero placeholders separately and rejects normalized duplicates' {
        $r=Convert-AdapterRows @((New-AdapterRow),(New-AdapterRow '00000000-0000-0000-0000-000000000000' 'Graph'))
        $r.Accounting.rawRecordCount|Should -Be 2
        $r.Accounting.admittedRecordCount|Should -Be 1
        $r.Accounting.zeroIdPlaceholderCount|Should -Be 1
        {Convert-AdapterRows @((New-AdapterRow),(New-AdapterRow ' 11111111-AAAA-4AAA-8AAA-111111111111 '))}|Should -Throw '*Duplicate*'
        {Convert-AdapterRows @((New-AdapterRow '00000000-0000-0000-0000-000000000000'),(New-AdapterRow '00000000-0000-0000-0000-000000000000'))}|Should -Throw '*Duplicate*'
    }
    It 'bounds quarantine without silent truncation and preserves empty-array shape' {
        $rows=@(1..128|ForEach-Object {New-AdapterRow "malformed-$_"})
        $r=Convert-AdapterRows $rows
        $r.Accounting.quarantinedRecordCount|Should -Be 128
        $r.Records.Count|Should -Be 0
        {Convert-AdapterRows @($rows+(New-AdapterRow 'overflow'))}|Should -Throw '*quarantine limit*'
        (Convert-AdapterRows @()).Accounting.rawRecordCount|Should -Be 0
        {ConvertTo-TokenForgeHealthMicrosoftApps $null ('a'*64)}|Should -Throw
        {ConvertTo-TokenForgeHealthMicrosoftApps ([object[]]::new(10001)) ('a'*64)}|Should -Throw
    }
    It 'fits the final health limit at the quarantine cap and refuses overflow with prior bytes intact' {
        $rows=@(1..128|ForEach-Object {New-AdapterRow "malformed-$_"})
        $first=Invoke-AdapterCollection $rows
        $first.Result.CollectionComplete|Should -BeTrue
        (Get-Item (Join-Path $first.Path health.json)).Length|Should -BeLessThan 65536
        @($first.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0].adaptation.quarantinedRecordCount|Should -Be 128
        $second=Invoke-AdapterCollection @($rows+(New-AdapterRow 'overflow')) $first.Path
        $second.Result.CollectionComplete|Should -BeFalse
        $s=@($second.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0]
        $s.status|Should -BeExactly Invalid
        $s.attempts|Should -Be 1
        $s.adaptation|Should -BeNullOrEmpty
        (Get-FileHash $second.Exchange.MetadataPath).Hash|Should -BeExactly (Get-FileHash $first.Exchange.MetadataPath).Hash
    }
    It 'does not hide unsafe fields in a zero-ID placeholder (<Field>)' -ForEach @(@{Field='owner'},@{Field='name'}) {
        $row=New-AdapterRow '00000000-0000-0000-0000-000000000000'
        if($Field -eq 'owner'){$row.AppOwnerOrganizationId='bad'}else{$row.AppDisplayName='Bearer synthetic'}
        {Convert-AdapterRows @($row)}|Should -Throw
    }
    It 'emits a complete nonempty exchange bound to raw source bytes with descriptive claims only' {
        $r=Invoke-AdapterCollection @((New-AdapterRow 'malformed'),(New-AdapterRow ' 22222222-AAAA-4AAA-8AAA-222222222222 '))
        $r.Result.CollectionComplete|Should -BeTrue
        $r.Result.CandidateCount|Should -BeGreaterThan 0
        $r.Result.Requests|Should -Be 0
        $r.Exchange.Health.schemaVersion|Should -Be 2
        $s=@($r.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0]
        $s.adaptation.inputSha256|Should -BeExactly (Get-FileHash $r.RawPath).Hash.ToLowerInvariant()
        $s.candidateCount|Should -Be 2
        $s.adaptation.admittedRecordCount|Should -Be 1
        $s.adaptation.quarantinedRecordCount|Should -Be 1
        $s.adaptation.normalizedRecordCount|Should -Be 1
        $app=$r.Exchange.Ledger.Applications['22222222-aaaa-4aaa-8aaa-222222222222'].Records['Discovery///']
        $app.Attributes.Ownership|Should -BeExactly Unverified
        $app.Sources.Evidence|Should -Contain PublishedEntraDocs
        @($r.Exchange.Ledger.Runs[-1].SourceSnapshots|Where-Object Location -CEQ $s.uri)[0].Sha256|Should -BeExactly $s.sha256
    }
    It 'preserves previous bytes/date and clears accounting on source projection rejection' {
        $first=Invoke-AdapterCollection @((New-AdapterRow))
        $row=New-AdapterRow;$row.Source='Graph'+[char]0x0085
        $second=Invoke-AdapterCollection @($row) $first.Path
        $second.Result.CollectionComplete|Should -BeFalse
        $s=@($second.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0]
        $s.status|Should -BeExactly Invalid
        $s.adaptation|Should -BeNullOrEmpty
        $s.sha256|Should -BeExactly @($first.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0].sha256
        (Get-FileHash $second.Exchange.MetadataPath).Hash|Should -BeExactly (Get-FileHash $first.Exchange.MetadataPath).Hash
        $second.Exchange.Health.lastCompleteAt|Should -BeExactly $first.Exchange.Health.lastCompleteAt
    }
    It 'rejects accounting tampering even after exchange hashes are updated (<Case>)' -ForEach @(
        @{Case='raw count'},@{Case='input hash'},@{Case='reason'},@{Case='index'},@{Case='extra field'},@{Case='missing report'},@{Case='array policy'},@{Case='array reason'}
    ) {
        $r=Invoke-AdapterCollection @((New-AdapterRow 'malformed'),(New-AdapterRow))
        $s=@($r.Exchange.Health.sources|Where-Object name -CEQ microsoftApps)[0]
        switch($Case){
            'raw count' {$s.adaptation.rawRecordCount++}
            'input hash' {$s.adaptation.inputSha256='b'*64}
            'reason' {$s.adaptation.quarantine[0].reason='Ignored'}
            'index' {$s.adaptation.quarantine[0].index=2}
            'extra field' {$s.adaptation.Extra='private'}
            'missing report' {$s.adaptation=$null}
            'array policy' {$s.adaptation.policy=@('MicrosoftAppsEntraDocsV1')}
            'array reason' {$s.adaptation.quarantine[0].reason=@('ApplicationIdentity')}
        }
        Save-AdapterExchange $r
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw
    }
    It 'reads old schema-1 exchanges but refuses unversioned adaptation fields' {
        $r=Invoke-AdapterCollection @((New-AdapterRow))
        $r.Exchange.Health.schemaVersion=1
        {Save-AdapterExchange $r;Read-TokenForgeHealthExchange $r.Path}|Should -Throw
        foreach($s in $r.Exchange.Health.sources){$s.Remove('adaptation')}
        Save-AdapterExchange $r
        (Read-TokenForgeHealthExchange $r.Path).Health.schemaVersion|Should -Be 1
    }
}
