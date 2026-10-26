BeforeAll {
    $repo=Split-Path $PSScriptRoot -Parent
    $native=$env:TOKENFORGE_TEST_NATIVE
    if(-not $native){throw 'Independent finishing review requires the exact rebuilt package.'}
    . "$repo/scripts/TokenForgePublicHealth.ps1"
    Initialize-TokenForgeHealthRuntime $native
    function New-ReviewCollection($Fixtures,$Previous) {
        $output=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $options=@{OutputPath=$output;NativeExecutablePath=$native;SourceRevision=('a'*40);FixturePath=$Fixtures}
        if($Previous){$options.PreviousExchangePath=$Previous}
        $null=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @options
        [pscustomobject]@{Path=$output;Exchange=Read-TokenForgeHealthExchange $output}
    }
}
Describe 'Independent finishing review: combined projector contract' {
    It 'retains exact prior bytes and dates when individually accepted sources exceed combined claim count' {
        $fixtures=Join-Path $TestDrive fixtures
        $null=New-Item -ItemType Directory $fixtures
        Copy-Item "$repo/tests/fixtures/public-health/*" $fixtures
        $previous=New-ReviewCollection $fixtures
        # MicrosoftApps contributes 255 valid distinct claims; ROADtools adds
        # one and resources adds one for the same application. Each source is
        # independently valid, while the 257-claim aggregate exceeds 256.
        $apps=@(1..255|ForEach-Object {@{AppId='11111111-1111-1111-1111-111111111111';AppDisplayName='Fixture';AppOwnerOrganizationId=$null;Source=('Source{0:D3}' -f $_)}})
        ConvertTo-Json -InputObject $apps -Depth 100|Set-Content (Join-Path $fixtures microsoftApps.json) -Encoding utf8NoBOM
        ConvertTo-Json -InputObject @(@{resourceId='11111111-1111-1111-1111-111111111111';displayName='Fixture resource'}) -Depth 100|Set-Content (Join-Path $fixtures resources.json) -Encoding utf8NoBOM
        $current=New-ReviewCollection $fixtures $previous.Path
        $current.Exchange.Health.complete|Should -BeFalse
        (Get-FileHash $current.Exchange.MetadataPath).Hash|Should -BeExactly (Get-FileHash $previous.Exchange.MetadataPath).Hash
        $current.Exchange.Health.lastCompleteAt|Should -BeExactly $previous.Exchange.Health.lastCompleteAt
        foreach($source in $current.Exchange.Health.sources){
            $old=@($previous.Exchange.Health.sources|Where-Object name -CEQ $source.name)[0]
            $source.status|Should -BeExactly Invalid
            $source.lastSuccessAt|Should -BeExactly $old.lastSuccessAt
            $source.sha256|Should -BeExactly $old.sha256
            $source.changed|Should -BeFalse
        }
    }
}
