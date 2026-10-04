function Get-TokenForgeDiscovery {
    <# .SYNOPSIS
    Aggregate app and resource candidates with per-source evidence, not asserted tenant consent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [object[]]$MicrosoftApps = @(),
        [object[]]$Resources = @(),
        [object[]]$AdditionalApplications = @(),
        [string]$MicrosoftAppsSource = 'LocalMicrosoftApps',
        [string]$ResourcesSource = 'LocalResources'
    )
    $map = @{}
    foreach ($app in $Catalog.Applications) {
        $map[$app.ClientId] = [pscustomobject]@{
            AppId = $app.ClientId; Name = $app.Name; OwnerTenantId = $null; Ownership = 'Unverified'
            Sources = @([pscustomobject]@{ Name = 'ROADtoolsScopes'; Location = $Catalog.Source; Evidence = 'PublishedMetadata' })
            PublicClient = $app.PublicClient; Foci = $app.Foci; RedirectUris = @($app.RedirectUris)
            PreferredRedirectUri = $app.PreferredRedirectUri; Grants = @($app.Grants)
            IsResourceCandidate = $false; IdentifierUris = @()
        }
    }
    $rows = @()
    # API IDs from scope edges are candidates even when a separate resource list omits them.
    $resourceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($app in $Catalog.Applications) {
        foreach ($grant in $app.Grants) { $null = $resourceIds.Add([string]$grant.ResourceId) }
    }
    foreach ($id in $Catalog.ResourceIdentifiers.Values) { $null = $resourceIds.Add([string]$id) }
    foreach ($id in @($resourceIds | Sort-Object)) {
        $rows += [pscustomobject]@{ Id = $id; Name = $id; Owner = $null; Source = $Catalog.Source; Evidence = 'PublishedResource'; Resource = $true }
    }
    foreach ($row in $MicrosoftApps) {
        $rows += [pscustomobject]@{ Id = $row.AppId; Name = $row.AppDisplayName; Owner = $row.AppOwnerOrganizationId; Source = $MicrosoftAppsSource; Evidence = "Published$($row.Source)"; Resource = $false }
    }
    foreach ($row in $Resources) {
        $rows += [pscustomobject]@{ Id = $row.resourceId; Name = $row.displayName; Owner = $null; Source = $ResourcesSource; Evidence = 'PublishedResource'; Resource = $true }
    }
    foreach ($row in $AdditionalApplications) {
        $rows += [pscustomobject]@{ Id = $row.AppId; Name = $row.Name; Owner = $row.OwnerTenantId; Source = 'AdditionalApplications'; Evidence = 'CallerProvided'; Resource = $false }
    }
    $invalidRecordCount = 0
    foreach ($row in $rows) {
        $id = [guid]::Empty
        if (-not [guid]::TryParse([string]$row.Id,[ref]$id) -or $id -eq [guid]::Empty) { $invalidRecordCount++; continue }
        $key = $id.ToString()
        if (-not $map.ContainsKey($key)) {
            $map[$key] = [pscustomobject]@{ AppId = $key; Name = [string]$row.Name; OwnerTenantId = $null; Ownership = 'Unverified'; Sources = @(); PublicClient = $null; Foci = $null; RedirectUris = @(); PreferredRedirectUri = ''; Grants = @(); IsResourceCandidate = $false; IdentifierUris = @() }
        }
        $candidate = $map[$key]
        if ($candidate.Name -eq $key -and $row.Name) { $candidate.Name = [string]$row.Name }
        $candidate.Sources += [pscustomobject]@{ Name = $row.Source; Location = $row.Source; Evidence = $row.Evidence }
        if ($row.Owner -in $script:MicrosoftOwnerTenants) { $candidate.OwnerTenantId = [string]$row.Owner; $candidate.Ownership = 'PublishedMicrosoftOwner' }
        if ($row.Resource) { $candidate.IsResourceCandidate = $true }
    }
    foreach ($uri in $Catalog.ResourceIdentifiers.Keys) {
        $id = [string]$Catalog.ResourceIdentifiers[$uri]
        if ($map.ContainsKey($id)) { $map[$id].IdentifierUris += $uri; $map[$id].IsResourceCandidate = $true }
    }
    [pscustomobject]@{
        SchemaVersion = 1; FetchedAt = [DateTimeOffset]::UtcNow.ToString('o')
        Sources = @($Catalog.Source,$MicrosoftAppsSource,$ResourcesSource)
        CatalogContentSha256 = $Catalog.ContentSha256; InvalidSourceRecordCount = $invalidRecordCount
        SourceSnapshots = @([pscustomobject]@{ Location = $Catalog.Source; Sha256 = $Catalog.ContentSha256; HashKind = 'CatalogSnapshot' }, [pscustomobject]@{ Location = $MicrosoftAppsSource; Sha256 = Get-TokenForgeFingerprint -Value (ConvertTo-Json -InputObject @($MicrosoftApps) -Depth 100 -Compress); HashKind = 'NormalizedJson' }, [pscustomobject]@{ Location = $ResourcesSource; Sha256 = Get-TokenForgeFingerprint -Value (ConvertTo-Json -InputObject @($Resources) -Depth 100 -Compress); HashKind = 'NormalizedJson' })
        Applications = @($map.Values | Sort-Object AppId)
    }
}

function Update-TokenForgeDiscovery {
    <# .SYNOPSIS
    Fetch current ROADtools scope data, Microsoft app-name data, and EntraScopes resource candidates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$MetadataPath,
        [uri]$ScopesUri = $script:CatalogUrl,
        [uri]$MicrosoftAppsUri = 'https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json',
        [uri]$ResourcesUri = 'https://raw.githubusercontent.com/f-bader/entrascopes.com/main/resources.json'
    )
    foreach ($uri in @($ScopesUri,$MicrosoftAppsUri,$ResourcesUri)) {
        if ($uri.Scheme -ne 'https' -or $uri.UserInfo) { throw 'Discovery sources must use HTTPS without user information.' }
    }
    $catalogPath = [IO.Path]::GetTempFileName()
    try {
        $catalog = Update-TokenForgeCatalog -SourceUri $ScopesUri -Path $catalogPath
        $apps = Invoke-RestMethod -Uri $MicrosoftAppsUri -TimeoutSec 30 -ErrorAction Stop
        $resources = Invoke-RestMethod -Uri $ResourcesUri -TimeoutSec 30 -ErrorAction Stop
        $discovery = Get-TokenForgeDiscovery -Catalog $catalog -MicrosoftApps $apps -Resources $resources -MicrosoftAppsSource $MicrosoftAppsUri.AbsoluteUri -ResourcesSource $ResourcesUri.AbsoluteUri
        if(-not $MetadataPath){$MetadataPath=Join-Path (Split-Path ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)) -Parent) 'applications.json'}
        $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $discovery -Kind Discovery
        Save-TokenForgeDocument -Document $discovery -Path $Path
        $discovery
    } finally { Remove-Item -LiteralPath $catalogPath -Force -ErrorAction SilentlyContinue }
}

function Save-TokenForgeDocument {
    param([Parameter(Mandatory)]$Document, [Parameter(Mandatory)][string]$Path)
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $directory = Split-Path $fullPath -Parent
    $null = New-Item -ItemType Directory -Path $directory -Force
    $temporary = Join-Path $directory ([guid]::NewGuid().ToString() + '.tmp')
    try {
        $options=[IO.FileStreamOptions]::new()
        $options.Mode=[IO.FileMode]::CreateNew; $options.Access=[IO.FileAccess]::Write; $options.Share=[IO.FileShare]::None
        if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
        $stream=[IO.FileStream]::new($temporary,$options)
        $writer=[IO.StreamWriter]::new($stream,[Text.UTF8Encoding]::new($false))
        try{$writer.Write((ConvertTo-Json -InputObject $Document -Depth 100));$writer.Flush();$stream.Flush($true)}finally{$writer.Dispose()}
        Move-Item -LiteralPath $temporary -Destination $fullPath -Force
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}
