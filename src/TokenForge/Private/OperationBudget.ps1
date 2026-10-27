# One serial-run budget covers preflight and collection. Counters contain no request data.
$script:OperationBudget=$null

function New-TokenForgeOperationBudget {
    param(
        [ValidateRange(0,1000000)][int]$MaxIssuanceAttempts=30,
        [ValidateRange(0,1000000)][int]$MaxBootstrapAttempts=1,
        [ValidateRange(0,1000000)][int]$MaxBootstrapRequests=20,
        [ValidateRange(0,1000000)][int]$MaxInventoryRequests=100,
        [ValidateRange(0,1000000)][int]$MaxInventoryPages=50,
        [ValidateRange(0,1000000)][int]$MaxSourceRequests=3,
        [ValidateRange(0,1000000)][int]$MaxTotalRequests=300,
        [ValidateRange(0,3)][int]$MaxTransientRetries=3,
        [ValidateRange(0.001,604800)][double]$MaxSeconds=900,
        [ValidateRange(0.001,30)][double]$TransportTimeoutSeconds=30,
        [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None,
        [string]$LedgerPath,
        [Nullable[DateTimeOffset]]$SessionExpiresAt,
        [string]$StopFilePath
    )
    [pscustomobject]@{
        SchemaVersion=1;StartedAt=[DateTimeOffset]::UtcNow.ToString('o');Timer=[Diagnostics.Stopwatch]::StartNew()
        MaxSeconds=$MaxSeconds;TransportTimeoutSeconds=$TransportTimeoutSeconds;CancellationToken=$CancellationToken;SessionExpiresAt=$SessionExpiresAt;StopFilePath=$StopFilePath
        Limits=[ordered]@{IssuanceAttempts=$MaxIssuanceAttempts;BootstrapAttempts=$MaxBootstrapAttempts;BootstrapRequests=$MaxBootstrapRequests;InventoryRequests=$MaxInventoryRequests;InventoryPages=$MaxInventoryPages;SourceRequests=$MaxSourceRequests;TotalRequests=$MaxTotalRequests;TransientRetries=$MaxTransientRetries}
        Counts=[ordered]@{IssuanceAttempts=0;IssuanceRetries=0;BootstrapAttempts=0;BootstrapRequests=0;InventoryRequests=0;InventoryPages=0;SourceRequests=0;IdentityRequests=0;TotalRequests=0;RequestRetries=0;PreflightRequests=0;InFlightOverruns=0;ReservedUnknownRequests=0}
        Cancelled=$false;StopReason=$null;Preflight=$true;IdentityCategory='Identity';LastRequestOverrun=$false
        # Per-operation retry counters are local only and never exported.
        RetryCounts=@{};LedgerPath=$LedgerPath;PendingRequest=$false;LastRequest=$null;BootstrapIntentPath=$null;BootstrapIntent=$null;GenericRecoveryCount=0
    }
}

function Stop-TokenForgeOperationBudget {
    param($Budget,[ValidateSet('DeadlineReached','Cancelled','SessionExpired','IssuanceAttempts','BootstrapAttempts','BootstrapRequests','InventoryRequests','InventoryPages','SourceRequests','TotalRequests','TransientRetries')][string]$Reason)
    $Budget.StopReason=$Reason
    Save-TokenForgeBudgetLedger $Budget
    $exception=[InvalidOperationException]::new("Discovery operation budget stopped ($Reason).")
    $exception.Data['TokenForgeBudgetReason']=$Reason
    throw [Management.Automation.ErrorRecord]::new($exception,'TokenForge.BudgetReached',[Management.Automation.ErrorCategory]::LimitsExceeded,$null)
}

function Assert-TokenForgeOperationBudget {
    param($Budget=$script:OperationBudget)
    if($null -eq $Budget){return}
    if($Budget.StopReason){Stop-TokenForgeOperationBudget $Budget $Budget.StopReason}
    if($Budget.StopFilePath -and (Test-Path -LiteralPath (Resolve-TokenForgeVaultPath $Budget.StopFilePath))){Stop-TokenForgeOperationBudget $Budget Cancelled}
    if($Budget.SessionExpiresAt -and [DateTimeOffset]::UtcNow -ge $Budget.SessionExpiresAt){Stop-TokenForgeOperationBudget $Budget SessionExpired}
    if($Budget.Cancelled -or $Budget.CancellationToken.IsCancellationRequested){Stop-TokenForgeOperationBudget $Budget Cancelled}
    if($Budget.Timer.Elapsed.TotalSeconds -ge $Budget.MaxSeconds){Stop-TokenForgeOperationBudget $Budget DeadlineReached}
}

function Start-TokenForgeBudgetIssuance {
    param($Budget=$script:OperationBudget,[ValidateSet('Issuance','Bootstrap')][string]$Kind='Issuance',[switch]$Retry,[string]$OperationId)
    if($null -eq $Budget){return}
    Assert-TokenForgeOperationBudget $Budget
    if($Budget.Counts.IssuanceAttempts -ge $Budget.Limits.IssuanceAttempts){Stop-TokenForgeOperationBudget $Budget IssuanceAttempts}
    if($Kind -eq 'Bootstrap' -and $Budget.Counts.BootstrapAttempts -ge $Budget.Limits.BootstrapAttempts){Stop-TokenForgeOperationBudget $Budget BootstrapAttempts}
    if($Retry){
        if(-not $OperationId -or $OperationId.Length -gt 256 -or $OperationId -cnotmatch '^[A-Za-z0-9_.:-]+$'){throw 'An issuance retry requires a safe operation identifier.'}
        $key='issuance:'+ $OperationId
        $used=if($Budget.RetryCounts.ContainsKey($key)){[int]$Budget.RetryCounts[$key]}else{0}
        if($used -ge $Budget.Limits.TransientRetries){Stop-TokenForgeOperationBudget $Budget TransientRetries}
        $Budget.RetryCounts[$key]=$used+1
        $Budget.Counts.IssuanceRetries++
    }
    $Budget.Counts.IssuanceAttempts++
    if($Kind -eq 'Bootstrap'){$Budget.Counts.BootstrapAttempts++}
    Save-TokenForgeBudgetLedger $Budget
}

function Start-TokenForgeBudgetRequest {
    param($Budget=$script:OperationBudget,[ValidateSet('Identity','Bootstrap','Inventory','Source')][string]$Category='Identity',[switch]$Retry)
    if($null -eq $Budget){return}
    Assert-TokenForgeOperationBudget $Budget
    if($Budget.Counts.TotalRequests -ge $Budget.Limits.TotalRequests){Stop-TokenForgeOperationBudget $Budget TotalRequests}
    $counter=$Category+'Requests'
    if($Category -ne 'Identity' -and $Budget.Counts[$counter] -ge $Budget.Limits[$counter]){Stop-TokenForgeOperationBudget $Budget $counter}
    # Reserve before dispatch, including transport failures and recognized retries.
    $Budget.Counts.TotalRequests++;$Budget.Counts[$counter]++
    if($Retry){$Budget.Counts.RequestRetries++}
    if($Budget.Preflight){$Budget.Counts.PreflightRequests++}
    $Budget.PendingRequest=$true
    $Budget.LastRequest=[ordered]@{Sequence=$Budget.Counts.TotalRequests;Category=$Category;Retry=[bool]$Retry;StartedAt=[DateTimeOffset]::UtcNow.ToString('o');EndedAt=$null}
    # A failed intent write prevents dispatch. A crash leaves the reserved count and pending flag.
    if($Category -eq 'Bootstrap' -and $Budget.BootstrapIntent){$Budget.BootstrapIntent.RequestCount++;Save-TokenForgeDocument -Path $Budget.BootstrapIntentPath -Document $Budget.BootstrapIntent}
    Save-TokenForgeBudgetLedger $Budget
}

function Start-TokenForgeBudgetPage {
    param($Budget=$script:OperationBudget)
    if($null -eq $Budget){return}
    Assert-TokenForgeOperationBudget $Budget
    if($Budget.Counts.InventoryPages -ge $Budget.Limits.InventoryPages){Stop-TokenForgeOperationBudget $Budget InventoryPages}
    $Budget.Counts.InventoryPages++
}

function New-TokenForgeBudgetCancellation {
    param($Budget=$script:OperationBudget)
    Assert-TokenForgeOperationBudget $Budget
    $source=if($Budget){[Threading.CancellationTokenSource]::CreateLinkedTokenSource($Budget.CancellationToken)}else{[Threading.CancellationTokenSource]::new()}
    $seconds=if($Budget){[Math]::Min($Budget.TransportTimeoutSeconds,($Budget.MaxSeconds-$Budget.Timer.Elapsed.TotalSeconds))}else{30}
    if($Budget -and $Budget.SessionExpiresAt){$seconds=[Math]::Min($seconds,($Budget.SessionExpiresAt-[DateTimeOffset]::UtcNow).TotalSeconds)}
    # Cancellation is scheduled at the remaining deadline, never rounded to a whole second.
    $source.CancelAfter([TimeSpan]::FromSeconds([Math]::Max(0.001,$seconds)))
    return $source
}

function Complete-TokenForgeBudgetRequest {
    param($Budget=$script:OperationBudget,[bool]$OutcomeKnown=$true)
    if($null -eq $Budget){return}
    if($Budget.Timer.Elapsed.TotalSeconds -gt $Budget.MaxSeconds){$Budget.Counts.InFlightOverruns++;$Budget.LastRequestOverrun=$true}
    $Budget.PendingRequest=-not $OutcomeKnown
    if($Budget.LastRequest -and $OutcomeKnown){$Budget.LastRequest.EndedAt=[DateTimeOffset]::UtcNow.ToString('o')}
    Save-TokenForgeBudgetLedger $Budget
    Assert-TokenForgeOperationBudget $Budget
}

function Wait-TokenForgeOperationBudget {
    param([double]$Seconds,$Budget=$script:OperationBudget)
    if($Seconds -lt 0 -or $Seconds -gt 300){throw 'Invalid bounded retry delay.'}
    Assert-TokenForgeOperationBudget $Budget
    if($Budget -and $Budget.Timer.Elapsed.TotalSeconds+$Seconds -ge $Budget.MaxSeconds){Stop-TokenForgeOperationBudget $Budget DeadlineReached}
    if($Budget -and $Budget.SessionExpiresAt -and [DateTimeOffset]::UtcNow.AddSeconds($Seconds) -ge $Budget.SessionExpiresAt){Stop-TokenForgeOperationBudget $Budget SessionExpired}
    # Short waits keep cancellation cooperative even during Retry-After/backoff.
    $remaining=$Seconds
    while($remaining -gt 0){
        Assert-TokenForgeOperationBudget $Budget
        $part=[Math]::Min(0.1,$remaining)
        Start-Sleep -Milliseconds ([int][Math]::Ceiling($part*1000))
        $remaining-=$part
    }
    Assert-TokenForgeOperationBudget $Budget
}

function Get-TokenForgeOperationBudgetSummary {
    param($Budget=$script:OperationBudget)
    if($null -eq $Budget){return $null}
    $counts=[ordered]@{};foreach($key in $Budget.Counts.Keys){$counts[$key]=$Budget.Counts[$key]}
    [pscustomobject]@{SchemaVersion=1;Scope='CurrentInvocationIncludingPreflight';StartedAt=$Budget.StartedAt;MaxSeconds=$Budget.MaxSeconds;TransportTimeoutSeconds=$Budget.TransportTimeoutSeconds;ElapsedSeconds=[Math]::Round($Budget.Timer.Elapsed.TotalSeconds,3);OverrunSeconds=[Math]::Round([Math]::Max(0.0,($Budget.Timer.Elapsed.TotalSeconds-$Budget.MaxSeconds)),3);StopReason=$Budget.StopReason;Limits=$Budget.Limits;Counts=$counts}
}

function Save-TokenForgeBudgetLedger {
    param($Budget)
    if(-not $Budget.LedgerPath){return}
    $path=Resolve-TokenForgeVaultPath -Path $Budget.LedgerPath -CreateDirectory
    Save-TokenForgeDocument -Path $path -Document ([ordered]@{SchemaVersion=1;Kind='TokenForgeOperationBudgetIntent';Budget=(Get-TokenForgeOperationBudgetSummary $Budget);PendingRequest=$Budget.PendingRequest;LastRequest=$Budget.LastRequest;ExactlyOnceGuaranteed=$false;RecoveryCount=$Budget.GenericRecoveryCount;RecoveryAuthorized=$false})
}

function Invoke-TokenForgeBudgetIdentityHttp {
    param([Net.Http.HttpClient]$Client,[uri]$Uri,[hashtable]$Form,[string]$Origin,$Budget)
    Start-TokenForgeBudgetRequest -Budget $Budget -Category $Budget.IdentityCategory
    $cancellation=New-TokenForgeBudgetCancellation $Budget
    $pairs=$null;$outcomeKnown=$false
    try{
        if($null -ne $Form){$pairs=[Collections.Generic.Dictionary[string,string]]::new();foreach($key in $Form.Keys){$pairs.Add($key,[string]$Form[$key])}}
        $result=[TokenForge.Core.V0180.OAuthTransport]::Send($Client,$Uri,$pairs,$(if($Origin){$Origin}else{$null}),$cancellation.Token)
        $outcomeKnown=$true
        $result
    }finally{
        if($pairs){$pairs.Clear()};$cancellation.Dispose()
        Complete-TokenForgeBudgetRequest -Budget $Budget -OutcomeKnown $outcomeKnown
    }
}

function Invoke-TokenForgeBudgetSource {
    param([Parameter(Mandatory)][uri]$Uri,$Budget=$script:OperationBudget)
    if(-not $Budget){return Invoke-WebRequest -Uri $Uri -TimeoutSec 30 -ErrorAction Stop}
    if($Uri.Scheme -ne 'https' -or $Uri.UserInfo -or $Uri.Fragment){throw 'Source must be HTTPS without user information or fragment.'}
    Start-TokenForgeBudgetRequest -Budget $Budget -Category Source
    $cancel=New-TokenForgeBudgetCancellation $Budget
    $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false
    $client=[Net.Http.HttpClient]::new($handler);$client.MaxResponseContentBufferSize=134217728
    $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$Uri);$response=$null
    try{
        try{$response=$client.SendAsync($request,$cancel.Token).GetAwaiter().GetResult()}catch{Assert-TokenForgeOperationBudget $Budget;throw 'Public source transport failed; details suppressed.'}
        if(-not $response.IsSuccessStatusCode){throw "Public source request failed (HTTP $([int]$response.StatusCode)); details suppressed."}
        [pscustomobject]@{Content=$response.Content.ReadAsStringAsync($cancel.Token).GetAwaiter().GetResult()}
    }finally{if($response){$response.Dispose()};$request.Dispose();$client.Dispose();$handler.Dispose();$cancel.Dispose();Complete-TokenForgeBudgetRequest -Budget $Budget -OutcomeKnown ($null -ne $response)}
}

function Throw-TokenForgeCollectorState {
    param([ValidateSet('SessionPaused','InFlightUnknown','RecoveryExhausted','AccountMismatch','TransientExhausted','RequestBlocked','Failed')][string]$State)
    throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new("Discovery stopped ($State); inspect saved evidence before continuing."),('TokenForge.'+$State),[Management.Automation.ErrorCategory]::InvalidOperation,$null)
}

function Start-TokenForgeBootstrapIntent {
    param([string]$Path,$Budget,[switch]$RecoverUnknown,[switch]$ResumePaused)
    $path=Resolve-TokenForgeVaultPath -Path $Path -CreateDirectory
    $recoveries=0;$unknownRequests=0
    if(Test-Path -LiteralPath $path){
        $stream=$null;$json=$null
        try{
            $stream=[IO.File]::OpenRead($path)
            if($stream.Length -lt 1 -or $stream.Length -gt 16384){throw 'Invalid bootstrap intent size.'}
            $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
            if($stream.ReadByte() -ne -1){throw 'Bootstrap intent changed during read.'}
            $json=[Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
            $names=@($json.RootElement.EnumerateObject()|ForEach-Object Name)
            $expected=@('SchemaVersion','Kind','State','RecoveryCount','RequestCount','StartedAt','CompletedAt')
            if($names.Count -ne $expected.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @(Compare-Object $names $expected).Count){throw 'Invalid bootstrap intent fields.'}
            $old=ConvertFrom-Json -InputObject $json.RootElement.GetRawText() -AsHashtable
            if($old.SchemaVersion -isnot [long] -and $old.SchemaVersion -isnot [int]){throw 'Invalid bootstrap version.'}
            if($old.SchemaVersion -ne 1 -or $old.Kind -cne 'TokenForgeBootstrapIntent' -or $old.State -cnotin @('Started','Completed','SessionPaused','RequestBlocked','TransientFailure','Failed','AccountMismatch')){throw 'Invalid bootstrap intent state.'}
            foreach($field in @('RecoveryCount','RequestCount')){if(($old[$field] -isnot [int] -and $old[$field] -isnot [long]) -or $old[$field] -lt 0){throw 'Invalid bootstrap counters.'}}
            if($old.RecoveryCount -gt 1 -or $old.RequestCount -gt 1000000){throw 'Invalid bootstrap counters.'}
            $parsed=[DateTimeOffset]::MinValue
            $startedText=$json.RootElement.GetProperty('StartedAt').GetString()
            if(-not [DateTimeOffset]::TryParseExact($startedText,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid bootstrap timestamp.'}
            $startedAt=$parsed
            if($old.RecoveryCount -ge 1 -and $old.State -ne 'Completed'){Throw-TokenForgeCollectorState RecoveryExhausted}
            if($old.State -eq 'SessionPaused' -and -not $ResumePaused){Throw-TokenForgeCollectorState SessionPaused}
            if($old.State -eq 'AccountMismatch'){Throw-TokenForgeCollectorState AccountMismatch}
            if($old.State -eq 'Started'){
                if($null -ne $old.CompletedAt){throw 'Invalid pending bootstrap intent.'}
                if(-not $RecoverUnknown){Throw-TokenForgeCollectorState InFlightUnknown}
                if($old.RecoveryCount -ge 1){Throw-TokenForgeCollectorState RecoveryExhausted}
                $recoveries=1;$unknownRequests=[int]$old.RequestCount
            }elseif($null -eq $old.CompletedAt -or -not [DateTimeOffset]::TryParseExact($json.RootElement.GetProperty('CompletedAt').GetString(),'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed -lt $startedAt -or $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid completed bootstrap intent.'}
        }catch{if($_.FullyQualifiedErrorId -match '^TokenForge\.'){throw};Throw-TokenForgeCollectorState Failed}finally{if($json){$json.Dispose()};if($stream){$stream.Dispose()}}
    }
    if($recoveries){
        # Charge the uncertain prior issuance and its reserved HTTP exchanges in this envelope.
        Start-TokenForgeBudgetIssuance -Budget $Budget -Kind Bootstrap
        if($Budget.Counts.TotalRequests+$unknownRequests -gt $Budget.Limits.TotalRequests){Stop-TokenForgeOperationBudget $Budget TotalRequests}
        if($Budget.Counts.BootstrapRequests+$unknownRequests -gt $Budget.Limits.BootstrapRequests){Stop-TokenForgeOperationBudget $Budget BootstrapRequests}
        $Budget.Counts.TotalRequests+=$unknownRequests;$Budget.Counts.BootstrapRequests+=$unknownRequests
        if($Budget.Preflight){$Budget.Counts.PreflightRequests+=$unknownRequests}
        $Budget.Counts.ReservedUnknownRequests+=$unknownRequests
    }
    Start-TokenForgeBudgetIssuance -Budget $Budget -Kind Bootstrap -Retry:([bool]$recoveries) -OperationId bootstrap
    $Budget.BootstrapIntentPath=$path
    $Budget.BootstrapIntent=[ordered]@{SchemaVersion=1;Kind='TokenForgeBootstrapIntent';State='Started';RecoveryCount=$recoveries;RequestCount=$unknownRequests;StartedAt=[DateTimeOffset]::UtcNow.ToString('o');CompletedAt=$null}
    Save-TokenForgeDocument -Path $path -Document $Budget.BootstrapIntent
    $Budget.IdentityCategory='Bootstrap'
}

function Complete-TokenForgeBootstrapIntent {
    param($Budget,[ValidateSet('Completed','SessionPaused','RequestBlocked','TransientFailure','Failed','AccountMismatch')][string]$State='Completed')
    if(-not $Budget.BootstrapIntent){return}
    $Budget.BootstrapIntent.State=$State;$Budget.BootstrapIntent.CompletedAt=[DateTimeOffset]::UtcNow.ToString('o')
    Save-TokenForgeDocument -Path $Budget.BootstrapIntentPath -Document $Budget.BootstrapIntent
}

function Get-TokenForgeCollectorStopSummary {
    param([Management.Automation.ErrorRecord]$ErrorRecord,[string]$Stage,$Budget)
    $id=$ErrorRecord.FullyQualifiedErrorId.Split(',')[0]
    $reason=switch -CaseSensitive ($id){
        'TokenForge.SessionPaused' {'SessionPaused'}
        'TokenForge.InFlightUnknown' {'InFlightUnknown'}
        'TokenForge.RecoveryExhausted' {'RecoveryExhausted'}
        'TokenForge.AccountMismatch' {'AccountMismatch'}
        'TokenForge.TransientIdentity' {if($ErrorRecord.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ResourceUnavailable){'TransientExhausted'}else{'Failed'}}
        'TokenForge.TransientExhausted' {'TransientExhausted'}
        'TokenForge.RequestBlocked' {'RequestBlocked'}
        'TokenForge.Failed' {'Failed'}
        'TokenForge.BudgetReached' {'BudgetReached'}
        default {if($Stage -eq 'Authorization'){(Get-TokenForgeProbeFailure $ErrorRecord).Status}else{'Failed'}}
    }
    if($Budget -and $Budget.PendingRequest -and $Budget.LastRequest -and $Budget.LastRequest.Category -in @('Source','Inventory')){$reason='InFlightUnknown'}
    if($Budget -and $Budget.StopReason){$reason='BudgetReached'}
    $status=if($reason -eq 'SessionPaused'){'Paused'}elseif($reason -in @('InFlightUnknown','RecoveryExhausted')){'InFlightUnknown'}elseif($reason -eq 'TransientFailure'){'TransientExhausted'}else{$reason}
    [pscustomobject]@{SchemaVersion=1;Status=$status;Reason=if($reason -eq 'TransientFailure'){'TransientExhausted'}else{$reason};Stage=$Stage;CheckpointsRetained=$true;CredentialOutput=$false;OperationBudget=(Get-TokenForgeOperationBudgetSummary $Budget)}
}

function Assert-TokenForgePendingRequestRecovery {
    param([string]$StatePath,$Budget,[switch]$RecoverUnknown)
    $files=@(Get-ChildItem -LiteralPath $StatePath -Filter 'budget-intent-*.json' -File -ErrorAction Stop)
    if($files.Count -gt 1000){Throw-TokenForgeCollectorState Failed}
    foreach($file in $files){
        $stream=$null;$json=$null
        try{
            $path=Resolve-TokenForgeVaultPath -Path $file.FullName
            $stream=[IO.File]::OpenRead($path)
            if($stream.Length -lt 1 -or $stream.Length -gt 16384){throw 'Invalid budget intent size.'}
            $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
            if($stream.ReadByte() -ne -1){throw 'Budget intent changed during read.'}
            $json=[Text.Json.JsonDocument]::Parse([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
            $expected=@('SchemaVersion','Kind','Budget','PendingRequest','LastRequest','ExactlyOnceGuaranteed','RecoveryCount','RecoveryAuthorized')
            $names=@($json.RootElement.EnumerateObject()|ForEach-Object Name)
            if($names.Count -ne $expected.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @(Compare-Object $names $expected).Count){throw 'Invalid budget intent fields.'}
            $old=ConvertFrom-Json -InputObject $json.RootElement.GetRawText() -AsHashtable
            if(($old.SchemaVersion -isnot [long] -and $old.SchemaVersion -isnot [int]) -or $old.SchemaVersion -ne 1 -or $old.Kind -cne 'TokenForgeOperationBudgetIntent' -or $old.ExactlyOnceGuaranteed -isnot [bool] -or $old.ExactlyOnceGuaranteed -or $old.PendingRequest -isnot [bool] -or $old.RecoveryAuthorized -isnot [bool] -or ($old.RecoveryCount -isnot [int] -and $old.RecoveryCount -isnot [long]) -or $old.RecoveryCount -notin @(0,1)){throw 'Invalid budget intent contract.'}
            $expectedSummary=@('SchemaVersion','Scope','StartedAt','MaxSeconds','TransportTimeoutSeconds','ElapsedSeconds','OverrunSeconds','StopReason','Limits','Counts')
            $names=@($json.RootElement.GetProperty('Budget').EnumerateObject()|ForEach-Object Name)
            if($names.Count -ne $expectedSummary.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @(Compare-Object $names $expectedSummary).Count){throw 'Invalid budget summary fields.'}
            if($old.Budget.SchemaVersion -ne 1 -or $old.Budget.Scope -cne 'CurrentInvocationIncludingPreflight'){throw 'Invalid budget summary contract.'}
            foreach($field in @('MaxSeconds','TransportTimeoutSeconds','ElapsedSeconds','OverrunSeconds')){
                $value=$old.Budget[$field]
                if(($value -isnot [double] -and $value -isnot [decimal] -and $value -isnot [int] -and $value -isnot [long]) -or [double]::IsNaN([double]$value) -or [double]::IsInfinity([double]$value) -or $value -lt 0 -or $value -gt 31536000){throw 'Invalid budget timing value.'}
            }
            if($old.Budget.MaxSeconds -le 0 -or $old.Budget.MaxSeconds -gt 604800 -or $old.Budget.TransportTimeoutSeconds -le 0 -or $old.Budget.TransportTimeoutSeconds -gt 30){throw 'Invalid budget timing limits.'}
            if($null -ne $old.Budget.StopReason -and $old.Budget.StopReason -cnotin @('DeadlineReached','Cancelled','SessionExpired','IssuanceAttempts','BootstrapAttempts','BootstrapRequests','InventoryRequests','InventoryPages','SourceRequests','TotalRequests','TransientRetries')){throw 'Invalid budget stop reason.'}
            if($old.RecoveryAuthorized -and ($old.RecoveryCount -ne 1 -or -not $old.PendingRequest)){throw 'Invalid recovery authorization.'}
            foreach($section in @('Counts','Limits')){
                $expectedKeys=if($section -eq 'Counts'){@($Budget.Counts.Keys)}else{@($Budget.Limits.Keys)}
                $names=@($json.RootElement.GetProperty('Budget').GetProperty($section).EnumerateObject()|ForEach-Object Name)
                if($names.Count -ne $expectedKeys.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @(Compare-Object $names $expectedKeys).Count){throw 'Invalid budget counter fields.'}
                foreach($name in $names){$value=$old.Budget[$section][$name];if(($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt 1000000){throw 'Invalid budget counters.'}}
            }
            $parsed=[DateTimeOffset]::MinValue
            if(-not [DateTimeOffset]::TryParseExact($json.RootElement.GetProperty('Budget').GetProperty('StartedAt').GetString(),'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid budget intent timestamp.'}
            if($null -ne $old.LastRequest){
                $expectedRequest=@('Sequence','Category','Retry','StartedAt','EndedAt')
                $names=@($json.RootElement.GetProperty('LastRequest').EnumerateObject()|ForEach-Object Name)
                if($names.Count -ne $expectedRequest.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count -or @(Compare-Object $names $expectedRequest).Count){throw 'Invalid request intent fields.'}
                if(($old.LastRequest.Sequence -isnot [int] -and $old.LastRequest.Sequence -isnot [long]) -or $old.LastRequest.Sequence -lt 1 -or $old.LastRequest.Sequence -ne $old.Budget.Counts.TotalRequests -or $old.LastRequest.Category -cnotin @('Bootstrap','Identity','Source','Inventory') -or $old.LastRequest.Retry -isnot [bool]){throw 'Invalid request intent.'}
                if(-not [DateTimeOffset]::TryParseExact($json.RootElement.GetProperty('LastRequest').GetProperty('StartedAt').GetString(),'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid request timestamp.'}
                $requestStartedAt=$parsed
                $endedElement=$json.RootElement.GetProperty('LastRequest').GetProperty('EndedAt')
                if($old.PendingRequest){
                    if($endedElement.ValueKind -ne [Text.Json.JsonValueKind]::Null){throw 'Pending request has an end timestamp.'}
                }elseif($endedElement.ValueKind -ne [Text.Json.JsonValueKind]::String -or -not [DateTimeOffset]::TryParseExact($endedElement.GetString(),'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed -lt $requestStartedAt -or $parsed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid request end timestamp.'}
            }elseif($old.PendingRequest){throw 'Missing pending request intent.'}
            if($old.RecoveryAuthorized){
                if($null -eq $old.LastRequest -or $old.LastRequest.Category -notin @('Source','Inventory')){throw 'Invalid recovery category.'}
                # Conservative per-state cap: retain a consumed generic recovery even if the
                # authorized run stopped before its first network request or new receipt write.
                $Budget.GenericRecoveryCount=1
                Save-TokenForgeBudgetLedger $Budget
                continue
            }
            if(-not $old.PendingRequest -or $old.LastRequest.Category -notin @('Source','Inventory')){continue}
            if($old.RecoveryCount -ge 1){Throw-TokenForgeCollectorState RecoveryExhausted}
            if(-not $RecoverUnknown){Throw-TokenForgeCollectorState InFlightUnknown}
            Assert-TokenForgeOperationBudget $Budget
            $counter=$old.LastRequest.Category+'Requests'
            if($Budget.Counts.TotalRequests -ge $Budget.Limits.TotalRequests){Stop-TokenForgeOperationBudget $Budget TotalRequests}
            if($Budget.Counts[$counter] -ge $Budget.Limits[$counter]){Stop-TokenForgeOperationBudget $Budget $counter}
            if($old.LastRequest.Category -eq 'Inventory'){Start-TokenForgeBudgetPage $Budget}
            $Budget.Counts.TotalRequests++;$Budget.Counts[$counter]++;$Budget.Counts.ReservedUnknownRequests++
            if($Budget.Preflight){$Budget.Counts.PreflightRequests++}
            $Budget.GenericRecoveryCount=1
            $old.RecoveryCount=1;$old.RecoveryAuthorized=$true
            # Preserve exact timestamp text across PowerShell's automatic JSON date conversion.
            $old.Budget.StartedAt=$json.RootElement.GetProperty('Budget').GetProperty('StartedAt').GetString()
            $old.LastRequest.StartedAt=$json.RootElement.GetProperty('LastRequest').GetProperty('StartedAt').GetString()
            $old.LastRequest.EndedAt=if($json.RootElement.GetProperty('LastRequest').GetProperty('EndedAt').ValueKind -eq [Text.Json.JsonValueKind]::Null){$null}else{$json.RootElement.GetProperty('LastRequest').GetProperty('EndedAt').GetString()}
            # Preserve the unknown remote outcome while recording its one authorized replay.
            # The caller retains its discovery lock; Windows needs this reader closed before replacement.
            $stream.Dispose();$stream=$null
            Save-TokenForgeDocument -Path $path -Document $old
            Save-TokenForgeBudgetLedger $Budget
        }catch{if($_.FullyQualifiedErrorId -match '^TokenForge\.'){throw};Throw-TokenForgeCollectorState Failed}finally{if($json){$json.Dispose()};if($stream){$stream.Dispose()}}
    }
}
