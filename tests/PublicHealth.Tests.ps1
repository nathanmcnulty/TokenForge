BeforeAll {
    $repo=Split-Path $PSScriptRoot -Parent
    $native=$env:TOKENFORGE_TEST_NATIVE
    if(-not $native){throw 'PublicHealth tests require the existing reviewed Linux package.'}
    . "$repo/scripts/TokenForgePublicHealth.ps1"
    Initialize-TokenForgeHealthRuntime $native
    $revision='91f858f8b7b70722223f4baa225a6cfc2ac340b6'
    function New-HealthFixtures {
        $p=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null=New-Item -ItemType Directory $p
        Copy-Item "$repo/tests/fixtures/public-health/*" $p
        return $p
    }
    function Invoke-FixtureCollection([string]$Fixtures,[string]$Previous) {
        $p=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $options=@{OutputPath=$p;NativeExecutablePath=$native;SourceRevision=$revision;FixturePath=$Fixtures}
        if($Previous){$options.PreviousExchangePath=$Previous}
        $result=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @options|ConvertFrom-Json
        [pscustomobject]@{Path=$p;Result=$result;Exchange=Read-TokenForgeHealthExchange $p}
    }
    function Write-HealthFixture([string]$Path,$Value){ConvertTo-Json -InputObject $Value -Depth 100|Set-Content -LiteralPath $Path -Encoding utf8NoBOM}
    function Update-HealthManifest([string]$Path){
        $m=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes((Join-Path $Path manifest.json)))
        foreach($n in $m.files.Keys){$b=[IO.File]::ReadAllBytes((Join-Path $Path $n));$m.files[$n].sha256=Get-TokenForgeHealthHash $b;$m.files[$n].bytes=$b.Length}
        Write-HealthFixture (Join-Path $Path manifest.json) $m
    }
}
Describe 'Public metadata health entry point' {
    It 'collects fixed synthetic sources, validates claims/conflicts and emits exactly three immutable files' {
        $r=Invoke-FixtureCollection (New-HealthFixtures)
        $r.Result.CollectionComplete|Should -BeTrue
        $r.Result.Requests|Should -Be 0
        $r.Exchange.Health.candidateCount|Should -Be 3
        $r.Exchange.Health.conflictCount|Should -Be 1
        @(Get-ChildItem $r.Path).Count|Should -Be 3
        $r.Exchange.Manifest.context|Should -BeNullOrEmpty
        foreach($file in Get-ChildItem $r.Path){[int][IO.File]::GetUnixFileMode($file.FullName)|Should -Be 256}
        {& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" -OutputPath $r.Path -NativeExecutablePath $native -SourceRevision $revision -FixturePath (New-HealthFixtures)}|Should -Throw '*immutable*'
    }
    It 'preserves complete catalog bytes and original dates when one source is unavailable' {
        $fixtures=New-HealthFixtures;$first=Invoke-FixtureCollection $fixtures
        Remove-Item (Join-Path $fixtures resources.json)
        $second=Invoke-FixtureCollection $fixtures $first.Path
        $second.Result.CollectionComplete|Should -BeFalse
        $second.Exchange.Health.lastCompleteAt|Should -BeExactly $first.Exchange.Health.lastCompleteAt
        (Get-FileHash $second.Exchange.MetadataPath).Hash|Should -BeExactly (Get-FileHash $first.Exchange.MetadataPath).Hash
        $source=@($second.Exchange.Health.sources|Where-Object name -EQ resources)[0]
        $source.status|Should -BeExactly Unavailable;$source.attempts|Should -Be 2
        $source.lastSuccessAt|Should -BeExactly $first.Exchange.Health.collectedAt
    }
    It 'retains successful source retrieval dates separately from the complete catalog date' {
        $fixtures=New-HealthFixtures;$first=Invoke-FixtureCollection $fixtures
        Remove-Item (Join-Path $fixtures resources.json)
        $second=Invoke-FixtureCollection $fixtures $first.Path
        $second.Exchange.Health.sources[0].lastSuccessAt|Should -BeExactly $second.Exchange.Health.collectedAt
        $second.Exchange.Ledger.Origins['Discovery///'].LastObservedAt|Should -BeExactly $first.Exchange.Health.collectedAt
    }
    It 'does not invent an authoritative empty snapshot when initial collection is partial' {
        $fixtures=New-HealthFixtures;Remove-Item (Join-Path $fixtures resources.json)
        $r=Invoke-FixtureCollection $fixtures
        $r.Exchange.Health.complete|Should -BeFalse
        $r.Exchange.Health.lastCompleteAt|Should -BeNullOrEmpty
        $r.Exchange.Ledger.Origins.Count|Should -Be 0
    }
    It 'keeps explicit absence and history after a subsequent complete-empty collection' {
        $fixtures=New-HealthFixtures;$first=Invoke-FixtureCollection $fixtures
        Write-HealthFixture (Join-Path $fixtures roadtools.json) @{apps=@{};resourceidentifiers=@{}}
        Write-HealthFixture (Join-Path $fixtures microsoftApps.json) @()
        Write-HealthFixture (Join-Path $fixtures resources.json) @()
        $second=Invoke-FixtureCollection $fixtures $first.Path
        $second.Exchange.Health.complete|Should -BeTrue
        $second.Exchange.Health.candidateCount|Should -Be 0
        $second.Exchange.Ledger.Applications.Count|Should -Be 3
        foreach($app in $second.Exchange.Ledger.Applications.Values){$app.Records['Discovery///'].PresentInLatestRun|Should -BeFalse}
    }
    It 'rejects whole malformed documents without retry or overwriting last-success facts' -ForEach @(
        @{Payload='[{"resourceId":"bad","displayName":"Bad"}]'},
        @{Payload='[{"resourceId":"00000003-0000-0000-c000-000000000000","displayName":"Bad","AccessToken":"secret"}]'},
        @{Payload='[{"resourceId":"00000003-0000-0000-c000-000000000000","displayName":"Bearer secret"}]'},
        @{Payload='{"duplicate":1,"duplicate":2}'},
        @{Payload='[null]'},
        @{Payload='null'}
    ) {
        $fixtures=New-HealthFixtures;$first=Invoke-FixtureCollection $fixtures
        Set-Content -LiteralPath (Join-Path $fixtures resources.json) -Value $Payload
        $r=Invoke-FixtureCollection $fixtures $first.Path
        $source=@($r.Exchange.Health.sources|Where-Object name -EQ resources)[0]
        $source.status|Should -BeExactly Invalid;$source.attempts|Should -Be 1
        (Get-FileHash $r.Exchange.MetadataPath).Hash|Should -BeExactly (Get-FileHash $first.Exchange.MetadataPath).Hash
    }
    It 'refuses an oversized source before parsing' {
        $fixtures=New-HealthFixtures;[IO.File]::WriteAllBytes((Join-Path $fixtures resources.json),[byte[]]::new(8388609))
        $r=Invoke-FixtureCollection $fixtures
        $r.Exchange.Health.complete|Should -BeFalse
        @($r.Exchange.Health.sources|Where-Object name -EQ resources)[0].attempts|Should -Be 2
    }
    It 'accepts known complete ROADtools optional fields but rejects schema drift' {
        $fixtures=New-HealthFixtures;$p=Join-Path $fixtures roadtools.json
        $data=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes($p))
        $data.apps.Values|ForEach-Object {$_.Add('preferred_interactive_redirurl',$null);$_.Add('result','ok')}
        Write-HealthFixture $p $data
        (Invoke-FixtureCollection $fixtures).Result.CollectionComplete|Should -BeTrue
        $data.apps.Values|Select-Object -First 1|ForEach-Object {$_.Add('unknown',$true)}
        Write-HealthFixture $p $data
        (Invoke-FixtureCollection $fixtures).Result.CollectionComplete|Should -BeFalse
    }
    It 'refuses a fixture claiming hosted identity' {
        $fixtures=New-HealthFixtures;$context=Join-Path $TestDrive context.json
        Write-HealthFixture $context @{repository='owner/repo';repositoryId='1';workflowId='2';runId='3';attempt='1';event='workflow_dispatch';headSha=$revision;headBranch='main'}
        {& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" -OutputPath (Join-Path $TestDrive refused) -NativeExecutablePath $native -SourceRevision $revision -FixturePath $fixtures -ContextPath $context}|Should -Throw '*provenance*'
    }
}
Describe 'Complete exchange validation and bounded transport' {
    BeforeEach {
        $r=Invoke-FixtureCollection (New-HealthFixtures)
        foreach($f in Get-ChildItem $r.Path){[IO.File]::SetUnixFileMode($f.FullName,[IO.UnixFileMode]384)}
    }
    It 'refuses hash mismatch and unexpected file before import' {
        Add-Content -LiteralPath $r.Exchange.MetadataPath -Value ' '
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw '*mismatch*'
        Set-Content -LiteralPath (Join-Path $r.Path extra.ps1) 'throw 1'
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw '*files*'
    }
    It 'refuses health count drift even when payload hashes match' {
        $health=$r.Exchange.Health;$health.candidateCount=99
        Write-HealthFixture (Join-Path $r.Path health.json) $health;Update-HealthManifest $r.Path
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw '*counts*'
    }
    It 'refuses wrong-source history even if its public host is normally valid' {
        $ledger=$r.Exchange.Ledger;$ledger.Runs[0].SourceSnapshots[0].Location='https://raw.githubusercontent.com/evil/repo/main/apps.json'
        Write-HealthFixture $r.Exchange.MetadataPath $ledger;Update-HealthManifest $r.Path
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw
    }
    It 'refuses symlink files and linked ancestors' {
        Remove-Item -LiteralPath (Join-Path $r.Path health.json)
        $null=New-Item -ItemType SymbolicLink -Path (Join-Path $r.Path health.json) -Target $r.Exchange.MetadataPath
        {Read-TokenForgeHealthExchange $r.Path}|Should -Throw '*Linked*'
    }
    It 'refuses unapproved requests before dispatch' -ForEach @(
        @{Uri='http://raw.githubusercontent.com/source'},@{Uri='https://evil.invalid/source'},@{Uri='https://raw.githubusercontent.com:444/source'},@{Uri='https://user@raw.githubusercontent.com/source'},@{Uri='https://raw.githubusercontent.com/source#fragment'}
    ) {
        $b=New-TokenForgeHealthBudget
        {Invoke-TokenForgeHealthGet -Uri $Uri -MaxBytes 100 -Budget $b -AllowedHosts @('raw.githubusercontent.com')}|Should -Throw
        $b.Requests|Should -Be 0
    }
    It 'refuses an exhausted request budget without an extra request' {
        $b=New-TokenForgeHealthBudget -MaxRequests 1;$b.Requests=1
        {Invoke-TokenForgeHealthGet -Uri 'https://raw.githubusercontent.com/source' -MaxBytes 100 -Budget $b -AllowedHosts @('raw.githubusercontent.com')}|Should -Throw
        $b.Requests|Should -Be 1
    }
}
Describe 'Quarantined public contributions' {
    It 'validates descriptive claims and reports conflicts without importing or authenticating' {
        $p=Join-Path $TestDrive claims.json
        $claims=@(
            @{SourceName='ContributorA';Location='https://raw.githubusercontent.com/example/a/main/apps.json';Evidence='Submitted';Name='One'},
            @{SourceName='ContributorB';Location='https://raw.githubusercontent.com/example/b/main/apps.json';Evidence='Submitted';Name='Two'}
        )
        Write-HealthFixture $p @{appId='11111111-1111-1111-1111-111111111111';claims=$claims}
        $result=& "$repo/scripts/Test-TokenForgePublicContribution.ps1" -InputPath $p -NativeExecutablePath $native|ConvertFrom-Json
        $result.status|Should -BeExactly Quarantined;$result.metadataConflicts.Count|Should -Be 1
        $result.catalogImported|Should -BeFalse;$result.proofStillNeeded|Should -Contain TokenIssuance
    }
    It 'refuses hostile submitted URLs/fields and does not follow evidence URLs' {
        $p=Join-Path $TestDrive claims.json
        Write-HealthFixture $p @{appId='11111111-1111-1111-1111-111111111111';claims=@(@{SourceName='Bad';Location='https://127.0.0.1/';Evidence='Submitted';Name='Bad'})}
        {& "$repo/scripts/Test-TokenForgePublicContribution.ps1" -InputPath $p -NativeExecutablePath $native}|Should -Throw
    }
}
