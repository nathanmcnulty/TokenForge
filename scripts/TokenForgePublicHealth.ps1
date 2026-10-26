# Shared bounded public-data contract. No authentication or operational adapters.
Set-StrictMode -Version Latest
$script:HealthSources=[ordered]@{
    roadtools='https://raw.githubusercontent.com/dirkjanm/ROADtools/master/roadtx/roadtools/roadtx/firstpartyscopes.json'
    microsoftApps='https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json'
    resources='https://raw.githubusercontent.com/f-bader/entrascopes.com/main/resources.json'
}
$script:HealthLimits=@{SourceBytes=8388608;SourceRecords=10000;CatalogRecords=30000;MetadataBytes=67108864;HealthBytes=65536;ManifestBytes=16384}

function Initialize-TokenForgeHealthRuntime {
    param([Parameter(Mandatory)][string]$NativeExecutablePath)
    if($PSVersionTable.PSVersion.ToString() -cne '7.6.7' -or -not $IsLinux -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64'){throw 'Public health currently requires reviewed PowerShell 7.6.7 on Linux x64.'}
    $exe=[IO.Path]::GetFullPath($NativeExecutablePath)
    $dll=Join-Path (Split-Path $exe -Parent) 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll'
    foreach($entry in @(@($exe,'42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e'),@($dll,'a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52'))){
        Assert-TokenForgeHealthPath $entry[0]
        if((Get-FileHash -LiteralPath $entry[0] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry[1]){throw 'Public health requires the reviewed matching Linux package.'}
    }
    if(-not ('TokenForge.Core.CredentialRuntime' -as [type])){Add-Type -Path $dll}
    Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -ErrorAction Stop
}

function Assert-TokenForgeHealthPath {
    param([string]$Path,[switch]$Directory)
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if([bool]$item.PSIsContainer -ne [bool]$Directory){throw 'Unexpected public health path type.'}
    $cursor=$item
    while($null -ne $cursor){
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked public health paths are refused.'}
        $cursor=if($cursor -is [IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}
    }
}

function New-TokenForgeHealthPrivateDirectory {
    param([string]$Path)
    $full=[IO.Path]::GetFullPath($Path)
    if(Test-Path -LiteralPath $full){throw 'Choose a new public health output directory.'}
    Assert-TokenForgeHealthPath (Split-Path $full -Parent) -Directory
    $null=[IO.Directory]::CreateDirectory($full,[IO.UnixFileMode]448)
    return $full
}

function Get-TokenForgeHealthHash { param([byte[]]$Bytes) [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function Read-TokenForgeHealthBytes {
    param([string]$Path,[int]$MaxBytes)
    Assert-TokenForgeHealthPath $Path
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{
        if($stream.Length -gt $MaxBytes){throw 'Public health input exceeds its byte limit.'}
        $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
        if($stream.ReadByte() -ne -1){throw 'Public health input changed during reading.'}
        return ,$bytes
    }finally{$stream.Dispose()}
}
function Read-TokenForgeHealthJson {
    param([byte[]]$Bytes)
    return ,([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([Text.UTF8Encoding]::new($false,$true).GetString($Bytes)))
}
function Assert-TokenForgeHealthKeys {
    param($Value,[string[]]$Keys)
    if($Value -isnot [Collections.IDictionary] -or @($Value.Keys).Count -ne $Keys.Count){throw [IO.InvalidDataException]::new('Unexpected public health schema.')}
    foreach($key in $Value.Keys){if($key -cnotin $Keys){throw [IO.InvalidDataException]::new('Unexpected public health schema field.')}}
}
function Assert-TokenForgeHealthDate {
    param($Value,[switch]$Nullable)
    if($Nullable -and $null -eq $Value){return}
    $date=[DateTimeOffset]::MinValue
    if($Value -isnot [string] -or $Value -cnotmatch '^\d{4}-\d\d-\d\dT.*(?:Z|\+00:00)$' -or -not [DateTimeOffset]::TryParse($Value,[ref]$date) -or $date -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw [IO.InvalidDataException]::new('Invalid public health date.')}
}
function Assert-TokenForgeHealthText {
    param($Value,[int]$Maximum=4096,[switch]$Nullable)
    if($Nullable -and $null -eq $Value){return}
    if($Value -isnot [string] -or $Value.Length -gt $Maximum -or $Value -match '[\x00-\x1f\x7f]' -or $Value -match '(?i)(?:bearer\s|eyJ[A-Za-z0-9_-]{16}|-----BEGIN .*PRIVATE KEY|access_token|refresh_token|client_secret|ESTSAUTH|[?&](?:code|token|assertion|sig|key|password)=|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})'){throw [IO.InvalidDataException]::new('Unsafe public metadata text.')}
}
function Assert-TokenForgeHealthGuid {
    param($Value,[switch]$AllowEmpty)
    $g=[guid]::Empty
    if($Value -isnot [string] -or -not [guid]::TryParse($Value,[ref]$g) -or (-not $AllowEmpty -and $g -eq [guid]::Empty) -or $g.ToString() -cne $Value){throw [IO.InvalidDataException]::new('Invalid public metadata ID.')}
}
function Assert-TokenForgeHealthPublishedGuid {
    param($Value,[switch]$AllowEmpty)
    # Published GUID case is descriptive spelling, not a new identity. Refuse
    # whitespace, braces and malformed suffixes instead of repairing them.
    if($Value -isnot [string] -or $Value -cnotmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'){throw [IO.InvalidDataException]::new('Invalid published metadata ID.')}
    Assert-TokenForgeHealthGuid ($Value.ToLowerInvariant()) -AllowEmpty:$AllowEmpty
}
function Assert-TokenForgeHealthCount {
    param($Value,[int]$Maximum)
    if($Value -isnot [long] -and $Value -isnot [int] -or $Value -lt 0 -or $Value -gt $Maximum){throw [IO.InvalidDataException]::new('Invalid public health count.')}
}

function Assert-TokenForgeHealthSource {
    param([string]$Name,$Data)
    if($Name -ceq 'roadtools'){
        Assert-TokenForgeHealthKeys $Data @('apps','resourceidentifiers')
        if($Data.apps -isnot [Collections.IDictionary] -or $Data.resourceidentifiers -isnot [Collections.IDictionary]){throw [IO.InvalidDataException]::new('Invalid catalog source.')}
        Assert-TokenForgeHealthCount $Data.apps.Count $script:HealthLimits.SourceRecords
        Assert-TokenForgeHealthCount $Data.resourceidentifiers.Count $script:HealthLimits.SourceRecords
        $appIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($id in $Data.apps.Keys){
            if(-not $appIds.Add($id)){throw [IO.InvalidDataException]::new('Conflicting normalized application IDs.')}
            Assert-TokenForgeHealthPublishedGuid $id -AllowEmpty;$app=$Data.apps[$id]
            if($app -isnot [Collections.IDictionary]){throw [IO.InvalidDataException]::new('Invalid catalog application shape.')}
            # Two extra ROADtools fields are validated but do not become authority.
            $optional=@('preferred_interactive_redirurl','result')|Where-Object {$app.Contains($_)}
            Assert-TokenForgeHealthKeys $app (@('name','public_client','foci','redirect_uris','preferred_noninteractive_redirurl','scopes')+@($optional))
            if($app.Contains('preferred_interactive_redirurl')){Assert-TokenForgeHealthText $app.preferred_interactive_redirurl -Nullable}
            if($app.Contains('result')){Assert-TokenForgeHealthText $app.result -Maximum 128}
            Assert-TokenForgeHealthText $app.name
            if($app.public_client -isnot [bool] -or $app.foci -isnot [bool] -or $app.redirect_uris -isnot [array] -or $app.redirect_uris.Count -gt 256 -or $app.scopes -isnot [Collections.IDictionary] -or $app.scopes.Count -gt 4096){throw [IO.InvalidDataException]::new('Invalid catalog application.')}
            Assert-TokenForgeHealthText $app.preferred_noninteractive_redirurl -Nullable
            foreach($uri in $app.redirect_uris){Assert-TokenForgeHealthText $uri}
            $resourceIds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach($resource in $app.scopes.Keys){
                if(-not $resourceIds.Add($resource)){throw [IO.InvalidDataException]::new('Conflicting normalized resource IDs.')}
                Assert-TokenForgeHealthPublishedGuid $resource;$scopes=$app.scopes[$resource]
                if($scopes -isnot [array] -or $scopes.Count -gt 1000){throw [IO.InvalidDataException]::new('Invalid catalog scopes.')}
                foreach($scope in $scopes){if($scope -isnot [string] -or $scope.Length -gt 256 -or $scope -cnotmatch '^[A-Za-z0-9_.-]+$'){throw [IO.InvalidDataException]::new('Invalid catalog scope.')}}
            }
        }
        foreach($uri in $Data.resourceidentifiers.Keys){Assert-TokenForgeHealthText $uri;Assert-TokenForgeHealthPublishedGuid $Data.resourceidentifiers[$uri]}
        return $Data.apps.Count
    }
    if($Name -cnotin @('microsoftApps','resources') -or $Data -isnot [array] -or $Data.Count -gt $script:HealthLimits.SourceRecords){throw [IO.InvalidDataException]::new('Invalid metadata source array.')}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $Data){
        if($Name -ceq 'microsoftApps'){
            Assert-TokenForgeHealthKeys $row @('AppId','AppDisplayName','AppOwnerOrganizationId','Source')
            Assert-TokenForgeHealthPublishedGuid $row.AppId -AllowEmpty
            if($null -ne $row.AppOwnerOrganizationId){if($row.AppOwnerOrganizationId -isnot [string]){throw [IO.InvalidDataException]::new('Invalid public owner hint.')};if($row.AppOwnerOrganizationId.Length -gt 0){Assert-TokenForgeHealthPublishedGuid $row.AppOwnerOrganizationId}}
            Assert-TokenForgeHealthText $row.AppDisplayName;Assert-TokenForgeHealthText $row.Source -Maximum 128
            # Different published source claims for one ID are legitimate conflicts.
            $key=$row.AppId.ToLowerInvariant()+'/'+$row.Source
        }else{
            Assert-TokenForgeHealthKeys $row @('resourceId','displayName')
            Assert-TokenForgeHealthPublishedGuid $row.resourceId;Assert-TokenForgeHealthText $row.displayName;$key=$row.resourceId.ToLowerInvariant()
        }
        if(-not $seen.Add($key)){throw [IO.InvalidDataException]::new('Duplicate public source identity.')}
    }
    return $Data.Count
}

function New-TokenForgeHealthBudget {
    param([ValidateRange(0.01,600)][double]$MaxSeconds=600,[ValidateRange(1,10)][int]$MaxRequests=6)
    [pscustomobject]@{Timer=[Diagnostics.Stopwatch]::StartNew();MaxSeconds=$MaxSeconds;MaxRequests=$MaxRequests;Requests=0}
}
function Assert-TokenForgeHealthBudget { param($Budget) if($Budget.Timer.Elapsed.TotalSeconds -ge $Budget.MaxSeconds){throw 'Public health deadline reached.'} }
function Invoke-TokenForgeHealthGet {
    param([Parameter(Mandatory)][uri]$Uri,[Parameter(Mandatory)][int]$MaxBytes,[double]$TimeoutSeconds=30,[hashtable]$Headers=@{},[Parameter(Mandatory)]$Budget,[Parameter(Mandatory)][string[]]$AllowedHosts)
    Assert-TokenForgeHealthBudget $Budget
    if($Uri.Scheme -cne 'https' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $Uri.Fragment -or $Uri.DnsSafeHost -cnotin $AllowedHosts -or $MaxBytes -lt 1 -or $MaxBytes -gt 100663296 -or $TimeoutSeconds -le 0 -or $TimeoutSeconds -gt 30 -or $Budget.Requests -ge $Budget.MaxRequests){throw 'Public health request refused.'}
    $Budget.Requests++ # Charged before dispatch, never refunded.
    $cancel=[Threading.CancellationTokenSource]::new();$cancel.CancelAfter([TimeSpan]::FromSeconds([Math]::Min($TimeoutSeconds,$Budget.MaxSeconds-$Budget.Timer.Elapsed.TotalSeconds)))
    $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.MaxResponseHeadersLength=16;$handler.UseCookies=$false;$handler.UseProxy=$false;$handler.UseDefaultCredentials=$false
    $client=[Net.Http.HttpClient]::new($handler);$request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$Uri);$response=$null;$stream=$null
    try{
        $request.Headers.Add('User-Agent','TokenForge-PublicHealth/1.0');$request.Headers.Add('Accept-Encoding','identity')
        foreach($key in $Headers.Keys){if($key -cnotin @('Accept','X-GitHub-Api-Version','Authorization') -or $Uri.Host -cne 'api.github.com'){throw 'Public health header refused.'};$request.Headers.Add($key,[string]$Headers[$key])}
        $response=$client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
        if($response.Content.Headers.ContentEncoding.Count -or $response.Content.Headers.ContentLength -gt $MaxBytes){throw 'Public health response limit exceeded.'}
        $headerBytes=0;$headerCount=0;foreach($header in @($response.Headers)+@($response.Content.Headers)){$headerCount++;$value=$header.Value -join ',';if($value.Length -gt 4096){throw 'Public health header value exceeded.'};$headerBytes+=$header.Key.Length+$value.Length}
        if($headerBytes -gt 16384 -or $headerCount -gt 64){throw 'Public health headers exceeded.'}
        $stream=$response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult();$output=[IO.MemoryStream]::new();$buffer=[byte[]]::new(32768)
        try{
            while(($n=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){if($output.Length+$n -gt $MaxBytes){throw 'Public health response limit exceeded.'};$output.Write($buffer,0,$n)}
            Assert-TokenForgeHealthBudget $Budget
            [pscustomobject]@{StatusCode=[int]$response.StatusCode;Bytes=$output.ToArray();Headers=@{Location=if($response.Headers.Location){$response.Headers.Location.OriginalString}else{$null};ContentType=[string]$response.Content.Headers.ContentType}}
        }finally{$output.Dispose()}
    }catch{throw 'Public health GET failed or exceeded its limits; details suppressed.'}
    finally{if($stream){$stream.Dispose()};if($response){$response.Dispose()};$request.Dispose();$client.Dispose();$handler.Dispose();$cancel.Dispose()}
}

function Assert-TokenForgeHealthContext {
    param($Context,[string]$Revision)
    if($null -eq $Context){return}
    Assert-TokenForgeHealthKeys $Context @('repository','repositoryId','workflowId','runId','attempt','event','headSha','headBranch')
    if($Context.repository -isnot [string] -or $Context.repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $Context.event -cnotin @('workflow_dispatch','schedule') -or $Context.headSha -cne $Revision -or $Context.headBranch -isnot [string] -or $Context.headBranch -cnotmatch '^[A-Za-z0-9_./-]{1,200}$'){throw 'Invalid public health run context.'}
    foreach($key in @('repositoryId','workflowId','runId','attempt')){if($Context[$key] -isnot [string] -or $Context[$key] -cnotmatch '^[1-9][0-9]{0,19}$'){throw 'Invalid public health run identity.'}}
}

function Read-TokenForgeHealthExchange {
    param([Parameter(Mandatory)][string]$Path)
    Assert-TokenForgeHealthPath $Path -Directory
    $actual=@(Get-ChildItem -LiteralPath $Path -Force)
    if($actual.Count -ne 3 -or @($actual|Where-Object {$_.PSIsContainer -or $_.Name -cnotin @('manifest.json','health.json','metadata.json')}).Count){throw 'Unexpected public exchange files.'}
    $manifest=Read-TokenForgeHealthJson (Read-TokenForgeHealthBytes (Join-Path $Path manifest.json) $script:HealthLimits.ManifestBytes)
    Assert-TokenForgeHealthKeys $manifest @('schemaVersion','kind','collectedAt','sourceRevision','context','files')
    if($manifest.schemaVersion -ne 1 -or $manifest.kind -cne 'TokenForgePublicHealthExchange' -or $manifest.sourceRevision -isnot [string] -or $manifest.sourceRevision -cnotmatch '^[0-9a-f]{40}$'){throw 'Unsupported public health exchange.'}
    Assert-TokenForgeHealthDate $manifest.collectedAt;Assert-TokenForgeHealthContext $manifest.context $manifest.sourceRevision
    Assert-TokenForgeHealthKeys $manifest.files @('health.json','metadata.json')
    foreach($name in $manifest.files.Keys){
        $entry=$manifest.files[$name];Assert-TokenForgeHealthKeys $entry @('sha256','bytes')
        $limit=if($name -ceq 'health.json'){$script:HealthLimits.HealthBytes}else{$script:HealthLimits.MetadataBytes}
        Assert-TokenForgeHealthCount $entry.bytes $limit
        $bytes=Read-TokenForgeHealthBytes (Join-Path $Path $name) $limit
        if($entry.sha256 -isnot [string] -or $entry.sha256 -cnotmatch '^[a-f0-9]{64}$' -or $entry.bytes -ne $bytes.Length -or $entry.sha256 -cne (Get-TokenForgeHealthHash $bytes)){throw 'Public exchange hash/size mismatch.'}
    }
    $health=Read-TokenForgeHealthJson (Read-TokenForgeHealthBytes (Join-Path $Path health.json) $script:HealthLimits.HealthBytes)
    Assert-TokenForgeHealthKeys $health @('schemaVersion','kind','collectedAt','lastCompleteAt','complete','candidateCount','conflictCount','sources')
    if($health.schemaVersion -ne 1 -or $health.kind -cne 'TokenForgePublicHealth' -or $health.collectedAt -cne $manifest.collectedAt -or $health.complete -isnot [bool] -or $health.sources -isnot [array] -or $health.sources.Count -ne 3){throw 'Invalid health summary.'}
    Assert-TokenForgeHealthDate $health.lastCompleteAt -Nullable
    if($health.lastCompleteAt -and [DateTimeOffset]$health.lastCompleteAt -gt [DateTimeOffset]$health.collectedAt){throw 'Future complete health snapshot.'}
    foreach($field in @('candidateCount','conflictCount')){Assert-TokenForgeHealthCount $health[$field] $script:HealthLimits.CatalogRecords}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($source in $health.sources){
        Assert-TokenForgeHealthKeys $source @('name','uri','status','attempts','lastSuccessAt','sha256','candidateCount','changed')
        if($source.name -cnotin @($script:HealthSources.Keys) -or -not $seen.Add($source.name) -or $source.uri -cne $script:HealthSources[$source.name] -or $source.status -cnotin @('Success','Unavailable','Invalid') -or $source.changed -isnot [bool]){throw 'Invalid health source.'}
        Assert-TokenForgeHealthCount $source.attempts 2;Assert-TokenForgeHealthCount $source.candidateCount $script:HealthLimits.SourceRecords;Assert-TokenForgeHealthDate $source.lastSuccessAt -Nullable
        if($null -ne $source.sha256 -and ($source.sha256 -isnot [string] -or $source.sha256 -cnotmatch '^[a-f0-9]{64}$')){throw 'Invalid source hash.'}
        if($source.status -ceq 'Success' -and ($source.lastSuccessAt -cne $health.collectedAt -or -not $source.sha256 -or $source.attempts -lt 1)){throw 'Invalid successful source observation.'}
        if($source.lastSuccessAt -and [DateTimeOffset]$source.lastSuccessAt -gt [DateTimeOffset]$health.collectedAt){throw 'Future source observation.'}
    }
    if($health.complete -ne (@($health.sources|Where-Object status -CNE Success).Count -eq 0) -or $health.complete -and $health.lastCompleteAt -cne $health.collectedAt){throw 'Inconsistent collection completeness.'}
    $metadataPath=Join-Path $Path metadata.json
    $ledger=Get-TokenForgeApplicationMetadata -Path $metadataPath -PublicOnly
    [TokenForge.Core.ApplicationCatalogPolicy]::ValidateDocument([Text.UTF8Encoding]::new($false,$true).GetString((Read-TokenForgeHealthBytes $metadataPath $script:HealthLimits.MetadataBytes)))
    Assert-TokenForgeHealthCount $ledger.Applications.Count $script:HealthLimits.CatalogRecords
    $present=0;$conflicts=0
    foreach($app in $ledger.Applications.Values){
        foreach($record in $app.Records.Values){
            if($record.PresentInLatestRun){$present++;if($record.Attributes.MetadataConflicts.Count -gt 0){$conflicts++}}
            foreach($payload in @($record)+@($record.PreviousVersions)){
                foreach($source in $payload.Sources){if($source.Location -cnotin @($script:HealthSources.Values)){throw 'Unapproved metadata source location.'}}
                if($payload.Attributes.Contains('SourceClaims')){foreach($claim in $payload.Attributes.SourceClaims){if($claim.Location -cnotin @($script:HealthSources.Values)){throw 'Unapproved public source claim.'}}}
            }
        }
    }
    if($present -ne $health.candidateCount -or $conflicts -ne $health.conflictCount){throw 'Public health catalog counts disagree.'}
    if($ledger.Origins.Count -gt 0){
        $origin=$ledger.Origins['Discovery///']
        if(-not $health.lastCompleteAt -or $origin.LastObservedAt -cne $health.lastCompleteAt){throw 'Public health catalog date disagrees.'}
    }elseif($health.lastCompleteAt){throw 'Missing complete public catalog origin.'}
    foreach($run in $ledger.Runs){
        foreach($snapshot in $run.SourceSnapshots){if($snapshot.Location -cnotin @($script:HealthSources.Values)){throw 'Unapproved public source snapshot.'}}
    }
    if($health.complete){
        $latest=@($ledger.Runs|Where-Object {$_.Id -ceq $ledger.Origins['Discovery///'].LastRunId})
        if($latest.Count -ne 1 -or $latest[0].SourceSnapshots.Count -ne 3){throw 'Incomplete source hash bindings.'}
        foreach($source in $health.sources){
            $snapshot=@($latest[0].SourceSnapshots|Where-Object {$_.Location -ceq $source.uri})
            if($snapshot.Count -ne 1 -or $snapshot[0].HashKind -cne 'RawPublicSource' -or $snapshot[0].Sha256 -cne $source.sha256){throw 'Public source hash binding disagrees.'}
        }
    }
    # Validate every historical scalar too. The complete public-only validator is
    # necessary but does not itself reject credential-looking free text.
    $walk={param($v) if($v -is [Collections.IDictionary]){foreach($key in $v.Keys){& $walk $v[$key]}}elseif($v -is [array]){foreach($item in $v){& $walk $item}}elseif($v -is [string]){Assert-TokenForgeHealthText $v}}
    & $walk $ledger
    [pscustomobject]@{Manifest=$manifest;Health=$health;MetadataPath=$metadataPath;Ledger=$ledger}
}

# Only contract failures from public input may become an incomplete exchange.
# I/O, programmer and runtime failures remain fatal and never masquerade as health.
function Test-TokenForgeHealthInputFailure {
    param([Exception]$Exception)
    $cause=$Exception
    while($cause -is [Management.Automation.MethodInvocationException] -and $cause.InnerException){$cause=$cause.InnerException}
    return ($cause -is [IO.InvalidDataException] -or $cause -is [Text.Json.JsonException] -or $cause -is [Text.DecoderFallbackException] -or
        ($cause.GetType() -eq [InvalidOperationException] -and $cause.Message -ceq 'Discovery source claims are invalid.'))
}

function Invoke-TokenForgeHealthProjection {
    param($Data,[string]$CatalogPath,[string]$Now)
    $roadtools=if($Data.ContainsKey('roadtools')){$Data.roadtools}else{@{apps=@{};resourceidentifiers=@{}}}
    # Storage operations are deliberately outside the recognized-input catch.
    @{SchemaVersion=1;Source=$script:HealthSources.roadtools;FetchedAt=$Now;Data=$roadtools}|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $CatalogPath -Encoding utf8NoBOM
    try{
        $catalog=Get-TokenForgeCatalog $CatalogPath
        try{
            $options=@{Catalog=$catalog;MicrosoftAppsSource=$script:HealthSources.microsoftApps;ResourcesSource=$script:HealthSources.resources}
            if($Data.ContainsKey('microsoftApps')){$options.MicrosoftApps=$Data.microsoftApps}
            if($Data.ContainsKey('resources')){$options.Resources=$Data.resources}
            $discovery=Get-TokenForgeDiscovery @options
            $ignored=@($roadtools.apps.Keys|Where-Object {$_ -eq '00000000-0000-0000-0000-000000000000'}).Count
            if($Data.ContainsKey('microsoftApps')){$ignored+=@($Data.microsoftApps|Where-Object {$_.AppId -eq '00000000-0000-0000-0000-000000000000'}).Count}
            if($discovery.InvalidSourceRecordCount -ne $ignored -or $discovery.Applications.Count -gt $script:HealthLimits.CatalogRecords){throw [IO.InvalidDataException]::new('Invalid complete source projection.')}
            return [pscustomobject]@{Valid=$true;Discovery=$discovery}
        }catch{if(-not (Test-TokenForgeHealthInputFailure $_.Exception)){throw};return [pscustomobject]@{Valid=$false;Discovery=$null}}
    }finally{Remove-Item -LiteralPath $CatalogPath}
}
