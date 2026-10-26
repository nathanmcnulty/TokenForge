BeforeAll {
    $repo=Split-Path $PSScriptRoot -Parent
    $native=$env:TOKENFORGE_TEST_NATIVE
    if(-not $native){throw 'Diagnostics require the pinned existing Linux package.'}
    . "$repo/scripts/TokenForgePublicHealth.ps1"
    Initialize-TokenForgeHealthRuntime $native
    function New-DiagnosticRow {
        @{AppId='11111111-1111-1111-1111-111111111111';AppDisplayName='Synthetic public app';AppOwnerOrganizationId=$null;Source='Graph'}
    }
    function Invoke-DiagnosticFixture {
        param([byte[]]$Bytes)
        $inputFile=Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.json')
        [IO.File]::WriteAllBytes($inputFile,$Bytes)
        $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $raw=& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $inputFile -NativeExecutablePath $native -OutputPath $out
        [pscustomobject]@{Raw=$raw;Result=($raw|ConvertFrom-Json -AsHashtable);Path=$out;Input=$inputFile}
    }
    function Invoke-RowDiagnostic($Rows){Invoke-DiagnosticFixture ([Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject @($Rows) -Depth 10 -Compress)))}
}
Describe 'Offline bounded MicrosoftApps diagnostic' {
    It 'accepts valid source claims with fixed output, no exchange and private immutable result' {
        $r=Invoke-RowDiagnostic @((New-DiagnosticRow))
        $r.Result.status|Should -BeExactly Success
        $r.Result.reasonCode|Should -BeExactly Accepted
        $r.Result.networkRequests|Should -Be 0
        $r.Result.exchangeEmitted|Should -BeFalse
        $r.Result.importPerformed|Should -BeFalse
        $r.Result.historicalTrialBytes|Should -BeFalse
        $r.Result.projectionAttempted|Should -BeTrue
        [int][IO.File]::GetUnixFileMode($r.Path)|Should -Be 448
        [int][IO.File]::GetUnixFileMode((Join-Path $r.Path diagnostic.json))|Should -Be 256
        @(Get-ChildItem $r.Path).Name|Should -BeExactly diagnostic.json
        $r.Result.inputSha256|Should -BeExactly (Get-FileHash $r.Input).Hash.ToLowerInvariant()
    }
    It 'distinguishes bounded parse failures and source shape' -ForEach @(
        @{Bytes=[byte[]]@(255);Code='Utf8'},
        @{Bytes=[Text.Encoding]::UTF8.GetBytes('[{');Code='JsonSyntax'},
        @{Bytes=[Text.Encoding]::UTF8.GetBytes('[{"x":1,"x":2}]');Code='JsonStructure'},
        @{Bytes=[Text.Encoding]::UTF8.GetBytes('null');Code='SourceShape'},
        @{Bytes=[Text.Encoding]::UTF8.GetBytes('{}');Code='SourceShape'},
        @{Bytes=[Text.Encoding]::UTF8.GetBytes('[null]');Code='SourceShape'}
    ) {
        $r=Invoke-DiagnosticFixture $Bytes
        $r.Result.status|Should -BeExactly Invalid
        $r.Result.reasonCode|Should -BeExactly $Code
        $r.Result.projectionAttempted|Should -BeFalse
    }
    It 'reports a malformed published ID without normalizing, repairing or emitting its value' -ForEach @(
        @{Suffix=' '},@{Suffix=([string][char]0x00c2+[char]0x00a0)}
    ) {
        $row=New-DiagnosticRow;$row.AppId+=$Suffix
        $r=Invoke-RowDiagnostic @($row)
        $r.Result.reasonCode|Should -BeExactly ApplicationIdentity
        $r.Result.recordIndex|Should -Be 0
        $r.Raw|Should -Not -Match '11111111|Synthetic public app'
    }
    It 'classifies strict owner, text, unknown-field and duplicate failures without revealing input' -ForEach @(
        @{Case='Owner';Code='OwnerIdentity'},@{Case='Text';Code='PublicText'},
        @{Case='Field';Code='SourceShape'},@{Case='Duplicate';Code='DuplicateIdentity'}
    ) {
        $row=New-DiagnosticRow;$rows=@($row)
        switch($Case){
            Owner {$row.AppOwnerOrganizationId='synthetic-secret-owner'}
            Text {$row.AppDisplayName='Bearer synthetic-secret-value'}
            Field {$row.Extra='synthetic-secret-field'}
            Duplicate {$rows+=New-DiagnosticRow}
        }
        $r=Invoke-RowDiagnostic $rows
        $r.Result.status|Should -BeExactly Invalid
        $r.Result.reasonCode|Should -BeExactly $Code
        $r.Raw|Should -Not -Match 'synthetic-secret|Bearer|Extra|11111111'
    }
    It 'preserves published case, absent owners, zero placeholders and distinct source claims' {
        $row=New-DiagnosticRow;$row.AppId='22222222-AAAA-4AAA-8AAA-222222222222';$row.AppOwnerOrganizationId=''
        $other=New-DiagnosticRow;$other.AppId=$row.AppId;$other.Source='Other'
        $zero=New-DiagnosticRow;$zero.AppId='00000000-0000-0000-0000-000000000000'
        (Invoke-RowDiagnostic @($row,$other,$zero)).Result.status|Should -BeExactly Success
    }
    It 'distinguishes successful shape validation from projection rejection' {
        $row=New-DiagnosticRow;$row.Source='Graph'+[char]0x0085
        $r=Invoke-RowDiagnostic @($row)
        $r.Result.status|Should -BeExactly Invalid
        $r.Result.reasonCode|Should -BeExactly SourceProjection
        $r.Result.projectionAttempted|Should -BeTrue
        $r.Raw|Should -Not -Match ([string][char]0x0085)
    }
    It 'refuses oversized input, existing output and linked input before source acceptance' {
        $p=Join-Path $TestDrive big.json;[IO.File]::WriteAllBytes($p,[byte[]]::new(8388609))
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $p -NativeExecutablePath $native -OutputPath (Join-Path $TestDrive big-output)}|Should -Throw '*byte limit*'
        $r=Invoke-RowDiagnostic @((New-DiagnosticRow))
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $r.Input -NativeExecutablePath $native -OutputPath $r.Path}|Should -Throw '*new public health output*'
        $link=Join-Path $TestDrive linked.json;$null=New-Item -ItemType SymbolicLink -Path $link -Target $r.Input
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $link -NativeExecutablePath $native -OutputPath (Join-Path $TestDrive linked-output)}|Should -Throw '*Linked*'
    }
    It 'keeps storage failures fatal and does not classify programmer failures as input' {
        $missing=Join-Path $TestDrive absent-input.json;$out=Join-Path $TestDrive absent-input-output
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $missing -NativeExecutablePath $native -OutputPath $out}|Should -Throw
        Test-Path $out|Should -BeFalse
        $r=Invoke-RowDiagnostic @((New-DiagnosticRow))
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $r.Input -NativeExecutablePath $native -OutputPath (Join-Path $TestDrive 'missing-parent/output')}|Should -Throw
        (Test-TokenForgeHealthInputFailure ([NullReferenceException]::new('synthetic programmer failure')))|Should -BeFalse
    }
    It 'fails visibly on projection staging I/O and removes only its own unfinished output' {
        $r=Invoke-RowDiagnostic @((New-DiagnosticRow))
        $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $sentinel=Join-Path $TestDrive sibling-sentinel.txt;[IO.File]::WriteAllText($sentinel,'preserve')
        Mock Set-Content {throw [IO.IOException]::new('synthetic staging storage failure')} -ParameterFilter {$LiteralPath -like '*/catalog.tmp'}
        {& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $r.Input -NativeExecutablePath $native -OutputPath $out}|Should -Throw '*synthetic staging storage failure*'
        Test-Path $out|Should -BeFalse
        Test-Path $r.Input|Should -BeTrue
        [IO.File]::ReadAllText($sentinel)|Should -BeExactly preserve
    }
    It 'explains a refusal while the collector preserves successful sources and incomplete evidence' -ForEach @(@{Previous=$false},@{Previous=$true}) {
        $fixtures=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($fixtures)
        Copy-Item "$repo/tests/fixtures/public-health/*" $fixtures
        $first=$null
        if($Previous){
            $first=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
            $null=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" -OutputPath $first -NativeExecutablePath $native -SourceRevision ('a'*40) -FixturePath $fixtures
        }
        $row=New-DiagnosticRow;$row.AppId+=([string][char]0x00c2+[char]0x00a0)
        $p=Join-Path $fixtures microsoftApps.json
        ConvertTo-Json -InputObject @($row) -Depth 10|Set-Content -LiteralPath $p -Encoding utf8NoBOM
        $diagnostic=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $d=& "$repo/scripts/Test-TokenForgeMicrosoftAppsInput.ps1" -InputPath $p -NativeExecutablePath $native -OutputPath $diagnostic|ConvertFrom-Json
        $d.reasonCode|Should -BeExactly ApplicationIdentity
        $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $options=@{OutputPath=$out;NativeExecutablePath=$native;SourceRevision=('a'*40);FixturePath=$fixtures}
        if($first){$options.PreviousExchangePath=$first}
        $r=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @options|ConvertFrom-Json
        $e=Read-TokenForgeHealthExchange $out
        $r.CollectionComplete|Should -BeFalse
        @($e.Health.sources|Where-Object name -CEQ microsoftApps)[0].status|Should -BeExactly Invalid
        @($e.Health.sources|Where-Object name -CEQ microsoftApps)[0].attempts|Should -Be 1
        @($e.Health.sources|Where-Object name -CEQ roadtools)[0].status|Should -BeExactly Success
        @($e.Health.sources|Where-Object name -CEQ resources)[0].status|Should -BeExactly Success
        foreach($name in @('roadtools','resources')){
            $source=@($e.Health.sources|Where-Object name -CEQ $name)[0]
            $source.attempts|Should -Be 1
            $source.lastSuccessAt|Should -BeExactly $e.Health.collectedAt
            $source.sha256|Should -BeExactly (Get-FileHash (Join-Path $fixtures ($name+'.json'))).Hash.ToLowerInvariant()
            $source.candidateCount|Should -Be $(if($name -ceq 'roadtools'){2}else{1})
        }
        $invalid=@($e.Health.sources|Where-Object name -CEQ microsoftApps)[0]
        $invalid.changed|Should -BeFalse
        if($first){
            $old=Read-TokenForgeHealthExchange $first
            $oldSource=@($old.Health.sources|Where-Object name -CEQ microsoftApps)[0]
            $invalid.lastSuccessAt|Should -BeExactly $oldSource.lastSuccessAt
            $invalid.sha256|Should -BeExactly $oldSource.sha256
            $invalid.candidateCount|Should -Be $oldSource.candidateCount
            (Get-FileHash $e.MetadataPath).Hash|Should -BeExactly (Get-FileHash (Join-Path $first metadata.json)).Hash
            $e.Health.lastCompleteAt|Should -BeExactly $old.Health.lastCompleteAt
        }else{
            $invalid.lastSuccessAt|Should -BeNullOrEmpty;$invalid.sha256|Should -BeNullOrEmpty;$invalid.candidateCount|Should -Be 0
            $e.Ledger.Applications.Count|Should -Be 0;$e.Ledger.Origins.Count|Should -Be 0;$e.Ledger.Runs.Count|Should -Be 0
            $e.Health.candidateCount|Should -Be 0;$e.Health.conflictCount|Should -Be 0;$e.Health.lastCompleteAt|Should -BeNullOrEmpty
        }
    }
}
