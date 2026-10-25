BeforeAll {
    $repo=Split-Path $PSScriptRoot -Parent
    $native=$env:TOKENFORGE_TEST_NATIVE
    if(-not $native){throw 'Package provenance tests require the reviewed Linux package.'}
    . "$repo/scripts/TokenForgePublicHealth.ps1"
    Initialize-TokenForgeHealthRuntime $native
    $head=(& git -C $repo rev-parse HEAD).Trim()
    function Write-PackageReceipt([string]$Path,$Value){ConvertTo-Json -InputObject $Value -Depth 30|Set-Content -LiteralPath $Path -Encoding utf8NoBOM}
    function New-PackageBuildFixture {
        $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $package=Join-Path $root build
        $dllDir=Join-Path $package src/TokenForge/lib/net8.0
        $null=[IO.Directory]::CreateDirectory($dllDir,[IO.UnixFileMode]448)
        Copy-Item -LiteralPath $native -Destination (Join-Path $package tokenforge)
        Copy-Item -LiteralPath (Join-Path (Split-Path $native -Parent) src/TokenForge/lib/net8.0/TokenForge.Credentials.dll) -Destination $dllDir
        $inputs=[ordered]@{}
        foreach($p in @(& git -C $repo ls-files -- global.json native src/TokenForge/Core scripts/Build-TokenForgeNative.ps1 scripts/Build-TokenForgeCredentials.ps1 scripts/Copy-TokenForgePackageSource.ps1)){$inputs[$p]=(Get-FileHash -LiteralPath (Join-Path $repo $p)).Hash.ToLowerInvariant()}
        $files=[ordered]@{}
        foreach($f in Get-ChildItem -LiteralPath $package -Recurse -File){$files[[IO.Path]::GetRelativePath($package,$f.FullName)]=(Get-FileHash -LiteralPath $f.FullName).Hash.ToLowerInvariant()}
        $receipt=@{schemaVersion=1;kind='TokenForgePublicHealthExactLinuxBuild';sourceRevision=$head;runtime='linux-x64';sdk='10.0.401';nativeInputs=$inputs;files=$files}
        $path=Join-Path $root receipt.json;Write-PackageReceipt $path $receipt
        return @{Root=$root;Package=$package;Receipt=$receipt;ReceiptPath=$path;Output=(Join-Path $root output)}
    }
    function Invoke-PackageFixture($Fixture){& "$repo/scripts/New-TokenForgePublicHealthPackage.ps1" -RebuiltPackagePath $Fixture.Package -BuildReceiptPath $Fixture.ReceiptPath -OutputPath $Fixture.Output -SourceRevision $head}
}
Describe 'Rebuilt public health package source custody' {
    It 'assembles reviewed binaries only when complete input and payload hashes match owning HEAD' {
        $f=New-PackageBuildFixture
        $result=Invoke-PackageFixture $f|ConvertFrom-Json -AsHashtable
        $result.nativeBuild|Should -BeExactly RebuiltExactSource
        $result.nativeSource|Should -BeExactly $head
        $result.buildReceiptSha256|Should -BeExactly (Get-FileHash $f.ReceiptPath).Hash.ToLowerInvariant()
        $result.published|Should -BeFalse
        $manifest=Get-Content (Join-Path $f.Output linux-x64/public-health-package.json) -Raw|ConvertFrom-Json -AsHashtable
        $manifest.nativeInputsVerified|Should -Be $f.Receipt.nativeInputs.Count
        $manifest.files.tokenforge.sha256|Should -BeExactly $f.Receipt.files.tokenforge
        $manifest.operationalPublication|Should -BeFalse
    }
    It 'refuses a stale build source label before creating output' {
        $f=New-PackageBuildFixture;$f.Receipt.sourceRevision='0'*40;Write-PackageReceipt $f.ReceiptPath $f.Receipt
        {Invoke-PackageFixture $f}|Should -Throw '*receipt identity*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses an omitted native input rather than accepting a caller-selected subset' {
        $f=New-PackageBuildFixture;$f.Receipt.nativeInputs.Remove('native/TokenForge.Core/ApplicationCatalogStore.cs');Write-PackageReceipt $f.ReceiptPath $f.Receipt
        {Invoke-PackageFixture $f}|Should -Throw '*inventory is incomplete*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses a stale native input hash even when binaries match the fixed pins' {
        $f=New-PackageBuildFixture;$f.Receipt.nativeInputs['native/TokenForge.Core/ApplicationCatalogStore.cs']='0'*64;Write-PackageReceipt $f.ReceiptPath $f.Receipt
        {Invoke-PackageFixture $f}|Should -Throw '*inputs differ*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses a modified compiled payload even if source inputs match' {
        $f=New-PackageBuildFixture
        [IO.File]::AppendAllText((Join-Path $f.Package tokenforge),'modified')
        {Invoke-PackageFixture $f}|Should -Throw '*bytes changed*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses an unrecorded extra file before copying any payload' {
        $f=New-PackageBuildFixture
        [IO.File]::WriteAllText((Join-Path $f.Package extra.txt),'unrecorded')
        {Invoke-PackageFixture $f}|Should -Throw '*inventory differs*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses receipt-authorized extra data outside the tracked source layout' {
        $f=New-PackageBuildFixture
        $path=Join-Path $f.Package private.json
        [IO.File]::WriteAllText($path,'private-data')
        $f.Receipt.files['private.json']=(Get-FileHash $path).Hash.ToLowerInvariant();Write-PackageReceipt $f.ReceiptPath $f.Receipt
        {Invoke-PackageFixture $f}|Should -Throw '*not a tracked source artifact*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses symlink payloads even when their bytes match' {
        $f=New-PackageBuildFixture
        $path=Join-Path $f.Package tokenforge
        Remove-Item -LiteralPath $path
        $null=[IO.File]::CreateSymbolicLink($path,$native)
        {Invoke-PackageFixture $f}|Should -Throw '*Linked*'
        Test-Path $f.Output|Should -BeFalse
    }
    It 'refuses the historical baseline once native compilation inputs changed' {
        $base=$env:TOKENFORGE_TEST_BASE_PACKAGE
        if(-not $base){throw 'Package provenance tests require the historical accepted baseline.'}
        $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        {& "$repo/scripts/New-TokenForgePublicHealthPackage.ps1" -BasePackagePath $base -OutputPath $out -SourceRevision $head}|Should -Throw '*rebuild and review required*'
        Test-Path $out|Should -BeFalse
    }
}
