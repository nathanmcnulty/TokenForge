Set-StrictMode -Version Latest

function Get-AppAddabilityValue {
    param($Object,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return $Object[$Name] }
    $property=$Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-AppAddabilityStatus {
    param($Observation)
    $value=Get-AppAddabilityValue $Observation 'StatusCode'
    if ($null -eq $value) { return 0 }
    try { return [int]$value } catch { return 0 }
}

function Get-AppAddabilityErrorCode {
    param($Observation)
    return [string](Get-AppAddabilityValue $Observation 'ErrorCode')
}

function Test-AppAddabilityNotFound {
    param($Observation)
    $code=Get-AppAddabilityErrorCode $Observation
    return ((Get-AppAddabilityStatus $Observation) -eq 404 -and $code -in @('Request_ResourceNotFound','ResourceNotFound'))
}

function Get-AppAddabilityPrincipalCheck {
    param([Parameter(Mandatory)][string]$AppId,[Parameter(Mandatory)][guid]$TenantId,$Observation)
    if ((Get-AppAddabilityStatus $Observation) -ne 200) { return [pscustomobject]@{Ok=$false;Reason='Graph did not return HTTP 200 for the exact service principal lookup.';Principal=$null} }
    $body=Get-AppAddabilityValue $Observation 'Body'
    if ($null -eq $body) { return [pscustomobject]@{Ok=$false;Reason='Graph returned no service principal body.';Principal=$null} }
    $actualAppId=[guid]::Empty
    if (-not [guid]::TryParse([string](Get-AppAddabilityValue $body 'appId'),[ref]$actualAppId) -or $actualAppId -ne ([guid]$AppId)) {
        return [pscustomobject]@{Ok=$false;Reason='Returned AppId did not match the requested AppId.';Principal=$body}
    }
    if ([string](Get-AppAddabilityValue $body 'servicePrincipalType') -cne 'Application') {
        return [pscustomobject]@{Ok=$false;Reason='Returned servicePrincipalType was not Application.';Principal=$body}
    }
    $owner=[guid]::Empty
    if (-not [guid]::TryParse([string](Get-AppAddabilityValue $body 'appOwnerOrganizationId'),[ref]$owner) -or $owner -eq [guid]::Empty -or $owner -eq $TenantId) {
        return [pscustomobject]@{Ok=$false;Reason='Recorded owner was missing, invalid, or inside the lab tenant.';Principal=$body}
    }
    $objectId=[guid]::Empty
    if (-not [guid]::TryParse([string](Get-AppAddabilityValue $body 'id'),[ref]$objectId) -or $objectId -eq [guid]::Empty) {
        return [pscustomobject]@{Ok=$false;Reason='Returned service principal object ID was missing or invalid.';Principal=$body}
    }
    return [pscustomobject]@{Ok=$true;Reason=$null;Principal=$body}
}

function Test-AppAddabilityAmbiguousWrite {
    param($CreateAttempt)
    $status=Get-AppAddabilityStatus $CreateAttempt
    $code=Get-AppAddabilityErrorCode $CreateAttempt
    $message=[string](Get-AppAddabilityValue $CreateAttempt 'ErrorMessage')
    $outcome=[string](Get-AppAddabilityValue $CreateAttempt 'TransportOutcome')
    if ($outcome -in @('Timeout','TransportError','SdkInvocationError') -or $status -eq 408 -or $message -match '(?i)timed?\s*out|timeout|connection reset') { return $true }
    if ($code -match '(?i)already.?exists|resource.?conflict' -or $message -match '(?i)already exists|already been created|duplicate') { return $true }
    return $false
}

function Test-AppAddabilityExplicitAppRejection {
    param($CreateAttempt,[Parameter(Mandatory)][string]$AppId)
    $status=Get-AppAddabilityStatus $CreateAttempt
    if ($status -notin @(400,404,422)) { return $false }
    $code=Get-AppAddabilityErrorCode $CreateAttempt
    $message=[string](Get-AppAddabilityValue $CreateAttempt 'ErrorMessage')
    if ($code -in @('Authorization_RequestDenied','InvalidAuthenticationToken','Authentication_MissingOrMalformed')) { return $false }
    $mentionsApp=($message -match '(?i)\b(application|appId)\b' -or $message -match [regex]::Escape($AppId))
    $specificReject=$message -match '(?i)\b(single[- ]tenant|not multi[- ]tenant|cannot be added to (?:another|the|this) tenant|not available for (?:another|the|this) tenant|cannot be instantiated in (?:another|the|this) tenant)\b'
    return ($mentionsApp -and $specificReject)
}

function Get-AppAddabilityRetryAfterUtc {
    param($Observation,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
    $value=if ($Observation -is [string] -or $Observation -is [ValueType]) { $Observation } else { Get-AppAddabilityValue $Observation 'RetryAfter' }
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { return $null }
    $seconds=0.0
    if ([double]::TryParse([string]$value,[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$seconds)) {
        if ($seconds -lt 0) { return $null }
        return $Now.ToUniversalTime().AddSeconds($seconds).ToString('o')
    }
    $date=[DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse([string]$value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal,[ref]$date)) {
        if ($date -lt $Now) { return $Now.ToUniversalTime().ToString('o') }
        return $date.ToUniversalTime().ToString('o')
    }
    return $null
}

function Get-AppAddabilityHeaderValue {
    param($Headers,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $Headers) { return $null }
    if ($Headers -is [Collections.IDictionary]) {
        foreach ($key in $Headers.Keys) {
            if ([string]$key -ieq $Name) {
                $value=$Headers[$key]
                if ($value -is [string]) { return $value }
                if ($value -is [Collections.IEnumerable]) { return [string](@($value)[0]) }
                return [string]$value
            }
        }
    }
    try {
        $values=$Headers.GetValues($Name)
        if ($values) { return [string](@($values)[0]) }
    } catch {}
    try {
        $value=$Headers[$Name]
        if ($value -is [string]) { return $value }
        if ($value -is [Collections.IEnumerable]) { return [string](@($value)[0]) }
        if ($null -ne $value) { return [string]$value
        }
    } catch {}
    return $null
}

function Get-AppAddabilityHttpMetadata {
    param($Body,$ResponseHeaders,$ErrorRecord,[int]$StatusCode=0)
    $status=$StatusCode
    $errorCode=[string](Get-AppAddabilityValue (Get-AppAddabilityValue $Body 'error') 'code')
    $requestId=Get-AppAddabilityHeaderValue $ResponseHeaders 'request-id'
    $clientRequestId=Get-AppAddabilityHeaderValue $ResponseHeaders 'client-request-id'
    $retryAfter=Get-AppAddabilityHeaderValue $ResponseHeaders 'Retry-After'

    if ($ErrorRecord) {
        $details=[string](Get-AppAddabilityValue $ErrorRecord 'ErrorDetails')
        if (-not $errorCode -and $details) {
            try { $errorCode=[string](Get-AppAddabilityValue (Get-AppAddabilityValue ($details | ConvertFrom-Json -ErrorAction Stop) 'error') 'code') } catch {}
        }
        $exception=if ($ErrorRecord -is [Exception]) { $ErrorRecord } else { Get-AppAddabilityValue $ErrorRecord 'Exception' }
        for ($depth=0;$null -ne $exception -and $depth -lt 5;$depth++) {
            $response=Get-AppAddabilityValue $exception 'Response'
            if ($response) {
                if (-not $status) { try { $status=[int](Get-AppAddabilityValue $response 'StatusCode') } catch {} }
                $responseHeadersFromException=Get-AppAddabilityValue $response 'Headers'
                if (-not $requestId) { $requestId=Get-AppAddabilityHeaderValue $responseHeadersFromException 'request-id' }
                if (-not $clientRequestId) { $clientRequestId=Get-AppAddabilityHeaderValue $responseHeadersFromException 'client-request-id' }
                if (-not $retryAfter) { $retryAfter=Get-AppAddabilityHeaderValue $responseHeadersFromException 'Retry-After' }
                $content=Get-AppAddabilityValue $response 'Content'
                if (-not $retryAfter -and $content) { $retryAfter=Get-AppAddabilityHeaderValue (Get-AppAddabilityValue $content 'Headers') 'Retry-After' }
                break
            }
            $exception=Get-AppAddabilityValue $exception 'InnerException'
        }
        if (-not $status) {
            try { $status=[int](Get-AppAddabilityValue $ErrorRecord.Exception 'StatusCode') } catch {}
        }
    }

    return [pscustomobject]@{
        StatusCode=$status
        ErrorCode=$errorCode
        RequestId=$requestId
        ClientRequestId=$clientRequestId
        RetryAfterUtc=(Get-AppAddabilityRetryAfterUtc $retryAfter)
    }
}

function Get-AppAddabilityTransportOutcome {
    param($ErrorRecord,[int]$StatusCode=0)
    if ($StatusCode -ge 400) { return 'HttpFailure' }
    if (-not $ErrorRecord) { return $null }
    $exception=if ($ErrorRecord -is [Exception]) { $ErrorRecord } else { Get-AppAddabilityValue $ErrorRecord 'Exception' }
    if (-not $exception) { return 'SdkInvocationError' }
    $type=[string]$exception.GetType().FullName
    $message=[string]$exception.Message
    if ($type -match '(?i)Timeout|TaskCanceled|OperationCanceled' -or $message -match '(?i)timed?\s*out|timeout|operation was canceled|task was canceled') { return 'Timeout' }
    if ($type -match '(?i)ParameterBinding|UriFormat|ArgumentException|FormatException|InvalidDataException|InvalidOperationException') { return 'LocalInvocationError' }
    if ($type -match '(?i)HttpRequestException|SocketException|WebException|IOException') { return 'TransportError' }
    return 'SdkInvocationError'
}

function New-AppAddabilityDiagnostic {
    param(
        [Parameter(Mandatory)][string]$FailureStage,
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$RequestMethod,
        [Parameter(Mandatory)][string]$Operation,
        [string]$TransportOutcome,
        [int]$GraphStatusCode=0,
        [string]$GraphErrorCode,
        [string]$RequestId,
        [string]$ClientRequestId,
        [string]$RetryAfterUtc,
        $ErrorRecord
    )
    $exceptionType=$null;$errorCategory=$null
    $exception=if ($ErrorRecord -is [Exception]) { $ErrorRecord } else { Get-AppAddabilityValue $ErrorRecord 'Exception' }
    if ($exception) {
        $candidate=[string]$exception.GetType().FullName
        if ($candidate -match '^[A-Za-z_][A-Za-z0-9_.+`]{0,254}$') { $exceptionType=$candidate }
        try { $errorCategory=[string](Get-AppAddabilityValue (Get-AppAddabilityValue $ErrorRecord 'CategoryInfo') 'Category') } catch {}
        if ($errorCategory -notmatch '^[A-Za-z]+$') { $errorCategory=$null }
    }
    if ($GraphErrorCode -notmatch '^[A-Za-z0-9_.-]{1,128}$') { $GraphErrorCode=$null }
    foreach ($name in @('RequestId','ClientRequestId')) {
        $value=[string](Get-Variable -Name $name -ValueOnly)
        if ($value -and $value -notmatch '^[A-Za-z0-9._-]{1,128}$') { Set-Variable -Name $name -Value $null }
    }
    if ($GraphStatusCode -lt 100 -or $GraphStatusCode -gt 599) { $GraphStatusCode=$null }
    if ($RetryAfterUtc) {
        $parsed=[DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse($RetryAfterUtc,[ref]$parsed)) { $RetryAfterUtc=$null }
        else { $RetryAfterUtc=$parsed.ToUniversalTime().ToString('o') }
    }
    return [pscustomobject][ordered]@{
        FailureStage=$FailureStage
        RequestMethod=$RequestMethod
        Operation=$Operation
        TransportOutcome=$TransportOutcome
        ExceptionType=$exceptionType
        ErrorCategory=$errorCategory
        GraphStatusCode=$GraphStatusCode
        GraphErrorCode=$GraphErrorCode
        RequestId=$RequestId
        ClientRequestId=$ClientRequestId
        RetryAfterUtc=$RetryAfterUtc
    }
}

function New-AppAddabilityFailedObservation {
    param($ErrorRecord,[Parameter(Mandatory)][ValidateSet('GET','POST')][string]$RequestMethod,[Parameter(Mandatory)][string]$Operation,[Parameter(Mandatory)][string]$FailureStage)
    $metadata=Get-AppAddabilityHttpMetadata $null $null $ErrorRecord
    $transport=Get-AppAddabilityTransportOutcome $ErrorRecord $metadata.StatusCode
    $diagnostic=New-AppAddabilityDiagnostic -FailureStage $FailureStage -RequestMethod $RequestMethod -Operation $Operation -TransportOutcome $transport -GraphStatusCode $metadata.StatusCode -GraphErrorCode $metadata.ErrorCode -RequestId $metadata.RequestId -ClientRequestId $metadata.ClientRequestId -RetryAfterUtc $metadata.RetryAfterUtc -ErrorRecord $ErrorRecord
    return [pscustomobject]@{StatusCode=$metadata.StatusCode;ErrorCode=$metadata.ErrorCode;ErrorMessage='';Body=$null;RetryAfter=$metadata.RetryAfterUtc;TransportOutcome=$transport;Diagnostic=$diagnostic}
}

function New-AppAddabilityOutcome {
    param([string]$Bucket,[string]$Result,[string]$Reason,[string]$ErrorCode,[bool]$Stop,[string]$Action,$Principal,$CreatedServicePrincipal,[string]$RetryAfterUtc=$null,$Diagnostic=$null)
    return [pscustomobject]@{Bucket=$Bucket;Result=$Result;Reason=$Reason;GraphErrorCode=$ErrorCode;Stop=$Stop;Action=$Action;Principal=$Principal;CreatedServicePrincipal=$CreatedServicePrincipal;RetryAfterUtc=$RetryAfterUtc;Diagnostic=$Diagnostic}
}

function Resolve-AppAddabilityOutcome {
    param(
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)]$InitialLookup,
        $CreateAttempt,
        $VerificationLookup
    )
    $initialStatus=Get-AppAddabilityStatus $InitialLookup
    if ($initialStatus -eq 200) {
        $check=Get-AppAddabilityPrincipalCheck $AppId $TenantId $InitialLookup
        if ($check.Ok) { return New-AppAddabilityOutcome 'Confirmed' 'AlreadyPresent' 'Exact Graph lookup verified matching AppId, Application type, and owner outside the lab.' '' $false '' $check.Principal $null -Diagnostic (Get-AppAddabilityValue $InitialLookup 'Diagnostic') }
        return New-AppAddabilityOutcome 'Pending' '' $check.Reason '' $false '' $check.Principal $null -Diagnostic (Get-AppAddabilityValue $InitialLookup 'Diagnostic')
    }
    if (-not (Test-AppAddabilityNotFound $InitialLookup)) {
        $status=$initialStatus;$code=Get-AppAddabilityErrorCode $InitialLookup
        $transport=[string](Get-AppAddabilityValue $InitialLookup 'TransportOutcome')
        $stop=($status -in @(401,403,429) -or $status -ge 500 -or $transport -in @('Timeout','TransportError','ContextFailure','LocalInvocationError','LocalConfigurationError','SdkInvocationError'))
        $reason=if($status -in @(401,403) -or $transport -eq 'ContextFailure'){'Graph authentication, account, tenant, or permission context failed; stopped before any create.'}elseif($status -eq 429){'Graph throttled the exact lookup; honor Retry-After and resume later.'}elseif($transport -in @('LocalInvocationError','LocalConfigurationError','SdkInvocationError')){'Local PowerShell or Graph SDK invocation failed; the app remains pending and processing stopped.'}elseif($status -ge 500 -or $transport -in @('Timeout','TransportError')){'Graph transport or service error; the app remains pending.'}else{'Exact AppId lookup was inconclusive.'}
        $retryAfter=Get-AppAddabilityRetryAfterUtc $InitialLookup
        if ($status -eq 429 -or $status -ge 500) { $stop=$true }
        return New-AppAddabilityOutcome 'Pending' 'Pending' $reason $code $stop '' $null $null $retryAfter -Diagnostic (Get-AppAddabilityValue $InitialLookup 'Diagnostic')
    }
    if ($null -eq $CreateAttempt) { return New-AppAddabilityOutcome 'Action' '' 'Confirmed not-found; create may be attempted.' '' $false 'Create' $null $null }

    $createStatus=Get-AppAddabilityStatus $CreateAttempt
    $createCode=Get-AppAddabilityErrorCode $CreateAttempt
    $createBody=Get-AppAddabilityValue $CreateAttempt 'Body'
    if ($createStatus -in @(200,201)) {
        $verification=Get-AppAddabilityPrincipalCheck $AppId $TenantId $VerificationLookup
        $createdRecord=$null
        $id=[guid]::Empty
        if ($null -ne $createBody -and [guid]::TryParse([string](Get-AppAddabilityValue $createBody 'id'),[ref]$id) -and $id -ne [guid]::Empty) {
            $createdRecord=[pscustomobject]@{AppId=$AppId;ServicePrincipalId=$id.ToString();Attribution='ConfirmedAppAddabilityCreateResponse';Verification='Pending'}
        }
        if ($verification.Ok) {
            if ($createdRecord) { $createdRecord.Verification='Verified' }
            return New-AppAddabilityOutcome 'Confirmed' 'NewlyAdded' 'Create succeeded and a follow-up exact lookup verified the resulting Application service principal and external owner.' '' $false '' $verification.Principal $createdRecord
        }
        return New-AppAddabilityOutcome 'Pending' 'Pending' $verification.Reason '' $false '' $verification.Principal $createdRecord -Diagnostic (Get-AppAddabilityValue $VerificationLookup 'Diagnostic')
    }

    $createMessage=[string](Get-AppAddabilityValue $CreateAttempt 'ErrorMessage')
    $ambiguous=Test-AppAddabilityAmbiguousWrite $CreateAttempt
    $statusNeedsStop=$createStatus -in @(401,403)
    if ($statusNeedsStop) { return New-AppAddabilityOutcome 'Pending' 'Pending' 'Graph authentication or permission failure; stopped without further Graph calls.' $createCode $true '' $null $null -Diagnostic (Get-AppAddabilityValue $CreateAttempt 'Diagnostic') }
    if ($null -eq $VerificationLookup) { return New-AppAddabilityOutcome 'Pending' 'Pending' 'Write failed without a reconciliation lookup; no retry was made.' $createCode $false '' $null $null -Diagnostic (Get-AppAddabilityValue $CreateAttempt 'Diagnostic') }

    if ((Get-AppAddabilityStatus $VerificationLookup) -eq 200) {
        $verification=Get-AppAddabilityPrincipalCheck $AppId $TenantId $VerificationLookup
        if ($verification.Ok) {
            $possible=$null
            if ($ambiguous) { $possible=[pscustomobject]@{AppId=$AppId;ServicePrincipalId=[string](Get-AppAddabilityValue $verification.Principal 'id');Attribution='PossibleAppAddabilityCreateAfterAmbiguousWrite';Verification='Verified'} }
            return New-AppAddabilityOutcome 'Confirmed' 'AlreadyPresentAfterReconciliation' 'Exact lookup after an ambiguous or duplicate write found a verified service principal; creation is not attributed to this app-addability.' $createCode $false '' $verification.Principal $possible -Diagnostic (Get-AppAddabilityValue $VerificationLookup 'Diagnostic')
        }
        return New-AppAddabilityOutcome 'Pending' 'Pending' $verification.Reason $createCode $false '' $verification.Principal $null -Diagnostic (Get-AppAddabilityValue $VerificationLookup 'Diagnostic')
    }

    if (Test-AppAddabilityNotFound $VerificationLookup) {
        if ($ambiguous) { return New-AppAddabilityOutcome 'Action' '' 'A post-write exact lookup confirmed not-found; a single create retry may be considered.' $createCode $false 'RetryCreateAfterLookup' $null $null }
        if (Test-AppAddabilityExplicitAppRejection $CreateAttempt $AppId) { return New-AppAddabilityOutcome 'CouldntAdd' 'ExplicitAppRejection' $createMessage $createCode $false '' $null $null -Diagnostic (Get-AppAddabilityValue $CreateAttempt 'Diagnostic') }
        $reason=if($createStatus -eq 429){'Graph throttled the app-specific write; honor Retry-After and resume later.'}elseif($createStatus -ge 500){'Graph service error; the app remains unresolved.'}else{'Graph did not explicitly reject this AppId; result remains inconclusive.'}
        $retryAfter=Get-AppAddabilityRetryAfterUtc $CreateAttempt
        $stop=($createStatus -eq 429 -or $createStatus -ge 500)
        return New-AppAddabilityOutcome 'Pending' 'Pending' $reason $createCode $stop '' $null $null $retryAfter -Diagnostic (Get-AppAddabilityValue $CreateAttempt 'Diagnostic')
    }
    return New-AppAddabilityOutcome 'Pending' 'Pending' 'Post-write exact lookup was inconclusive; no retry was made.' $createCode $false '' $null $null -Diagnostic (Get-AppAddabilityValue $VerificationLookup 'Diagnostic')
}

function Test-AppAddabilityContext {
    param($Context,[Parameter(Mandatory)][guid]$ExpectedTenantId,[Parameter(Mandatory)][string]$ExpectedAccount,[string]$RequiredScope='Application.ReadWrite.All')
    $tenant=[guid]::Empty
    if (-not [guid]::TryParse([string](Get-AppAddabilityValue $Context 'TenantId'),[ref]$tenant) -or $tenant -ne $ExpectedTenantId) { return [pscustomobject]@{Ok=$false;Reason='TenantMismatch';Stop=$true} }
    if ([string](Get-AppAddabilityValue $Context 'Account') -ine $ExpectedAccount) { return [pscustomobject]@{Ok=$false;Reason='AccountMismatch';Stop=$true} }
    $scopes=@(Get-AppAddabilityValue $Context 'Scopes'|ForEach-Object {[string]$_})
    if ($RequiredScope -notin $scopes) { return [pscustomobject]@{Ok=$false;Reason='RequiredPermissionUnavailable';Stop=$true} }
    return [pscustomobject]@{Ok=$true;Reason=$null;Stop=$false}
}

function Invoke-AppAddabilityGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$AppId,
        [Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][string]$ExpectedAccount
    )
    $id=([guid]$AppId).ToString()
    $operation=if ($Method -eq 'GET') {'LookupServicePrincipalByAppId'} else {'CreateServicePrincipal'}
    $uri=if ($Method -eq 'GET') {
        "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$id')"
    } else {
        'https://graph.microsoft.com/v1.0/servicePrincipals'
    }

    try {
        $context=Get-MgContext -ErrorAction Stop
        $contextCheck=Test-AppAddabilityContext $context $TenantId $ExpectedAccount
        if (-not $contextCheck.Ok) {
            $diagnostic=New-AppAddabilityDiagnostic -FailureStage 'ContextValidation' -RequestMethod $Method -Operation $operation -TransportOutcome 'ContextFailure'
            return [pscustomobject]@{StatusCode=0;ErrorCode='';ErrorMessage='';Body=$null;RetryAfter=$null;TransportOutcome='ContextFailure';Diagnostic=$diagnostic}
        }
        $requestContext=Get-MgRequestContext -ErrorAction Stop
        if ($requestContext.MaxRetry -ne 0) {
            Set-MgRequestContext -MaxRetry 0 -ClientTimeout 30 -Confirm:$false -ErrorAction Stop | Out-Null
        }
        if ((Get-MgRequestContext -ErrorAction Stop).MaxRetry -ne 0) {
            $diagnostic=New-AppAddabilityDiagnostic -FailureStage 'RetryPolicyValidation' -RequestMethod $Method -Operation $operation -TransportOutcome 'LocalConfigurationError'
            return [pscustomobject]@{StatusCode=0;ErrorCode='';ErrorMessage='';Body=$null;RetryAfter=$null;TransportOutcome='LocalConfigurationError';Diagnostic=$diagnostic}
        }
    } catch {
        return New-AppAddabilityFailedObservation -ErrorRecord $_ -RequestMethod $Method -Operation $operation -FailureStage 'RequestContextSetup'
    }

    $statusCode=0;$responseHeaders=$null;$body=$null;$requestError=$null
    try {
        if ($Method -eq 'GET') {
            $body=Invoke-MgGraphRequest -Method GET -Uri $uri -SkipHttpErrorCheck -StatusCodeVariable statusCode -ResponseHeadersVariable responseHeaders -OutputType PSObject -ErrorAction Stop
        } else {
            $body=Invoke-MgGraphRequest -Method POST -Uri $uri -Body @{appId=$id} -SkipHttpErrorCheck -StatusCodeVariable statusCode -ResponseHeadersVariable responseHeaders -OutputType PSObject -ErrorAction Stop
        }
    } catch {
        $requestError=$_
    }
    $metadata=Get-AppAddabilityHttpMetadata $body $responseHeaders $requestError ([int]$statusCode)
    if (-not $statusCode -and $metadata.StatusCode) { $statusCode=$metadata.StatusCode }
    $errorObject=Get-AppAddabilityValue $body 'error'
    $errorCode=[string](Get-AppAddabilityValue $errorObject 'code')
    $errorMessage=[string](Get-AppAddabilityValue $errorObject 'message')
    if (-not $errorCode) { $errorCode=$metadata.ErrorCode }
    $transportOutcome=Get-AppAddabilityTransportOutcome $requestError ([int]$statusCode)
    $diagnostic=$null
    if ($requestError -or [int]$statusCode -ge 400) {
        $stage=if ($requestError) {'GraphRequestInvocation'} else {'GraphResponse'}
        $diagnostic=New-AppAddabilityDiagnostic -FailureStage $stage -RequestMethod $Method -Operation $operation -TransportOutcome $transportOutcome -GraphStatusCode ([int]$statusCode) -GraphErrorCode $errorCode -RequestId $metadata.RequestId -ClientRequestId $metadata.ClientRequestId -RetryAfterUtc $metadata.RetryAfterUtc -ErrorRecord $requestError
    }
    return [pscustomobject]@{
        StatusCode=[int]$statusCode;ErrorCode=$errorCode;ErrorMessage=$errorMessage;Body=$body
        RetryAfter=$metadata.RetryAfterUtc;TransportOutcome=$transportOutcome;Diagnostic=$diagnostic
    }
}

function New-AppAddabilityCheckpoint {
    param([Parameter(Mandatory)]$Applications,[Parameter(Mandatory)][string]$SnapshotSha256,[Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][string]$ExpectedAccount)
    $queue=[Collections.Generic.List[object]]::new()
    if ($Applications -is [Collections.IDictionary]) {
        foreach($key in @($Applications.Keys | Sort-Object -CaseSensitive)) {
            $record=$Applications[$key]
            $id=[string](Get-AppAddabilityValue $record 'AppId');if(-not $id){$id=[string]$key}
            $name=''
            $records=Get-AppAddabilityValue $record 'Records'
            if ($records -is [Collections.IDictionary]) {
                foreach($sourceRecord in $records.Values){$attributes=Get-AppAddabilityValue $sourceRecord 'Attributes';$candidate=[string](Get-AppAddabilityValue $attributes 'Name');if($candidate){$name=$candidate;break}}
            }
            $queue.Add([ordered]@{AppId=([guid]$id).ToString();Source='PinnedPublicCatalog';Metadata=@{Name=$name};RetryAfterUtc=$null})
        }
    } else {
        foreach($record in @($Applications)) {
            $id=[string](Get-AppAddabilityValue $record 'AppId')
            $queue.Add([ordered]@{AppId=([guid]$id).ToString();Source='PinnedPublicCatalog';Metadata=@{Name=[string](Get-AppAddabilityValue $record 'Name')};RetryAfterUtc=$null})
        }
    }
    if ($queue.Count -eq 0) { throw 'The pinned catalog has no Application IDs.' }
    [ordered]@{
        Format='TokenForgeAppAddabilityCheckpoint';SchemaVersion=1;Status='Prepared';TenantId=$TenantId.ToString();ExpectedAccount=$ExpectedAccount
        SnapshotSha256=$SnapshotSha256;CreatedAtUtc=[DateTimeOffset]::UtcNow.ToString('o');UpdatedAtUtc=$null
        Queue=$queue.ToArray();InFlight=$null;Results=[ordered]@{Confirmed=@();CouldntAdd=@();Pending=@()};CreatedServicePrincipals=@();StopReceipts=@()
    }
}

function Invoke-AppAddabilityItem {
    param(
        [Parameter(Mandatory)]$Item,[Parameter(Mandatory)][guid]$TenantId,
        [Parameter(Mandatory)][scriptblock]$Request,[Parameter(Mandatory)][scriptblock]$BeforePost,
        [int]$MaxPostAttempts=2,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow
    )
    $attemptCount=0;$lookup=$null;$create=$null;$verification=$null
    try { $lookup=& $Request 'GET' $Item.AppId } catch { $lookup=New-AppAddabilityFailedObservation -ErrorRecord $_ -RequestMethod 'GET' -Operation 'LookupServicePrincipalByAppId' -FailureStage 'RequestCallback' }
    $outcome=Resolve-AppAddabilityOutcome $Item.AppId $TenantId $lookup
    if ($outcome.Bucket -ne 'Action') {
        if ($outcome.RetryAfterUtc) { $outcome.Stop=$true }
        return $outcome
    }
    while ($attemptCount -lt $MaxPostAttempts) {
        & $BeforePost $Item $attemptCount
        try { $create=& $Request 'POST' $Item.AppId } catch {
            $create=New-AppAddabilityFailedObservation -ErrorRecord $_ -RequestMethod 'POST' -Operation 'CreateServicePrincipal' -FailureStage 'RequestCallback'
        }
        $attemptCount++
        $status=Get-AppAddabilityStatus $create
        if ([string](Get-AppAddabilityValue $create 'TransportOutcome') -eq 'ContextFailure') { return New-AppAddabilityOutcome 'Pending' 'Pending' 'Graph context changed or could not be verified; stopped without further Graph requests.' '' $true '' $null $null -Diagnostic (Get-AppAddabilityValue $create 'Diagnostic') }
        if ($status -in @(401,403)) { return Resolve-AppAddabilityOutcome $Item.AppId $TenantId $lookup $create $null }
        if ([string](Get-AppAddabilityValue $create 'TransportOutcome') -in @('LocalInvocationError','LocalConfigurationError')) {
            return New-AppAddabilityOutcome 'Pending' 'Pending' 'Local PowerShell or Graph SDK invocation failed; stopped before another Graph request.' (Get-AppAddabilityErrorCode $create) $true '' $null $null (Get-AppAddabilityRetryAfterUtc $create $Now) -Diagnostic (Get-AppAddabilityValue $create 'Diagnostic')
        }
        if ($status -eq 429 -or ($status -ge 500 -and (Get-AppAddabilityRetryAfterUtc $create $Now))) {
            $reason=if($status -eq 429){'Graph throttled the app-specific write; honor Retry-After and resume later.'}else{'Graph service requested a retry delay; the result remains pending until that delay passes.'}
            $outcome=New-AppAddabilityOutcome 'Pending' 'Pending' $reason (Get-AppAddabilityErrorCode $create) $true '' $null $null (Get-AppAddabilityRetryAfterUtc $create $Now) -Diagnostic (Get-AppAddabilityValue $create 'Diagnostic')
            return $outcome
        }
        try { $verification=& $Request 'GET' $Item.AppId } catch { $verification=New-AppAddabilityFailedObservation -ErrorRecord $_ -RequestMethod 'GET' -Operation 'LookupServicePrincipalByAppId' -FailureStage 'VerificationCallback' }
        $outcome=Resolve-AppAddabilityOutcome $Item.AppId $TenantId $lookup $create $verification
        $verificationStatus=Get-AppAddabilityStatus $verification
        $verificationTransport=[string](Get-AppAddabilityValue $verification 'TransportOutcome')
        if ($verificationStatus -in @(401,403) -or $verificationStatus -eq 429 -or $verificationStatus -ge 500 -or $verificationTransport -in @('Timeout','TransportError','ContextFailure','LocalInvocationError','LocalConfigurationError','SdkInvocationError')) {
            $outcome.Stop=$true
            if ($verificationStatus -in @(401,403) -or $verificationTransport -eq 'ContextFailure') {
                $outcome.Reason='Graph authentication, account, tenant, or permission verification failed; stopped before another app.'
            } elseif ($verificationStatus -eq 429) {
                $outcome.Reason='Graph throttled an exact post-write lookup; honor Retry-After and resume later.'
                $outcome.RetryAfterUtc=Get-AppAddabilityRetryAfterUtc $verification $Now
            } elseif ($verificationStatus -ge 500 -or $verificationTransport -in @('Timeout','TransportError')) {
                $outcome.Reason='Graph transport or service error during exact post-write lookup; the app remains pending.'
                $outcome.RetryAfterUtc=Get-AppAddabilityRetryAfterUtc $verification $Now
            } elseif ($verificationTransport -in @('LocalInvocationError','LocalConfigurationError','SdkInvocationError')) {
                $outcome.Reason='Local PowerShell or Graph SDK invocation failed during exact post-write lookup; processing stopped.'
            }
            $outcome.Diagnostic=Get-AppAddabilityValue $verification 'Diagnostic'
            return $outcome
        }
        if ($outcome.Bucket -ne 'Action') { return $outcome }
        if ($attemptCount -ge $MaxPostAttempts) {
            return New-AppAddabilityOutcome 'Pending' '' 'The write remained ambiguous after an exact AppId lookup and the retry limit; resume with a fresh lookup.' (Get-AppAddabilityErrorCode $create) $false '' $null $outcome.CreatedServicePrincipal
        }
        $lookup=$verification;$create=$null;$verification=$null
    }
    return New-AppAddabilityOutcome 'Pending' '' 'The write outcome remains unresolved.' (Get-AppAddabilityErrorCode $create) $false '' $null $null
}

function Invoke-AppAddabilityCatalog {
    param([Parameter(Mandatory)]$State,[Parameter(Mandatory)][string]$CheckpointPath,[Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][string]$ExpectedAccount,[Parameter(Mandatory)][scriptblock]$Request)
    $contextCheck=Test-AppAddabilityContext (Get-MgContext) $TenantId $ExpectedAccount
    if (-not $contextCheck.Ok) { throw "Graph context check failed: $($contextCheck.Reason). No Graph request was sent." }
    $null=Get-MgRequestContext
    Set-MgRequestContext -MaxRetry 0 -ClientTimeout 30 -Confirm:$false -ErrorAction Stop | Out-Null
    if ((Get-MgRequestContext).MaxRetry -ne 0) { throw 'Graph SDK retries could not be disabled for this run.' }
    if ($State.InFlight) {
        $inFlightItem=@($State.Queue|Where-Object {$_.AppId -eq $State.InFlight.AppId})|Select-Object -First 1
        if (-not $inFlightItem) { throw 'Checkpoint in-flight AppId is missing from the queue.' }
        $State.Queue=@(@($inFlightItem)+@($State.Queue|Where-Object {$_.AppId -ne $State.InFlight.AppId}))
    }
    $initialQueueCount=@($State.Queue).Count
    for ($index=0;$index -lt $initialQueueCount;$index++) {
        if (@($State.Queue).Count -eq 0) { break }
        $item=$State.Queue[0]
        if ($item.RetryAfterUtc) {
            $due=[DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse([string]$item.RetryAfterUtc,[ref]$due) -and [DateTimeOffset]::UtcNow -lt $due) { break }
            $item.RetryAfterUtc=$null
        }
        $State.InFlight=[ordered]@{AppId=$item.AppId;Phase='Lookup';Attempt=0}
        Save-AppAddabilityCheckpoint $State $CheckpointPath
        $saveCheckpoint=(Get-Command Save-AppAddabilityCheckpoint -ErrorAction Stop).ScriptBlock
        $beforePost={ param($queuedItem,$attempt) $State.InFlight=[ordered]@{AppId=$queuedItem.AppId;Phase='PostIntent';Attempt=$attempt+1};& $saveCheckpoint $State $CheckpointPath }.GetNewClosure()
        $outcome=Invoke-AppAddabilityItem $item $TenantId $Request $beforePost
        Complete-AppAddabilityItem -State $State -Path $CheckpointPath -Item $item -Outcome $outcome -ObservedAtUtc ([DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd'))
        if ($outcome.Bucket -eq 'Pending' -and @($State.Queue).Count -gt 1) {
            $State.Queue=@(@($State.Queue | Select-Object -Skip 1)+$item)
            Save-AppAddabilityCheckpoint $State $CheckpointPath
        }
        if ($outcome.Stop) { break }
    }
    if (@($State.Queue).Count -eq 0) { $State.Status='Complete' } elseif ($State.Status -ne 'Stopped') { $State.Status='Pending' }
    Save-AppAddabilityCheckpoint $State $CheckpointPath
    return [pscustomobject]@{Status=$State.Status;QueueCount=@($State.Queue).Count;ConfirmedCount=@($State.Results.Confirmed).Count;CouldntAddCount=@($State.Results.CouldntAdd).Count;PendingCount=@($State.Results.Pending).Count;CheckpointPath=$CheckpointPath}
}

function Write-AppAddabilityJsonAtomic {
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Value,[Parameter(Mandatory)][string]$Path)
    $full=[IO.Path]::GetFullPath($Path);$dir=[IO.Path]::GetDirectoryName($full)
    if (-not [IO.Directory]::Exists($dir)) { [IO.Directory]::CreateDirectory($dir)|Out-Null }
    if ($IsLinux) { [IO.File]::SetUnixFileMode($dir,[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute) }
    $temp=Join-Path $dir ('.'+[guid]::NewGuid().ToString('N')+'.tmp')
    $json=ConvertTo-Json -InputObject $Value -Depth 100
    [IO.File]::WriteAllText($temp,$json,[Text.UTF8Encoding]::new($false))
    if ($IsLinux) { [IO.File]::SetUnixFileMode($temp,[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite) }
    [IO.File]::Move($temp,$full,$true)
}

function Save-AppAddabilityCheckpoint {
    param([Parameter(Mandatory)]$State,[Parameter(Mandatory)][string]$Path)
    $stamp=[DateTimeOffset]::UtcNow.ToString('o')
    if ($State -is [Collections.IDictionary]) { $State['UpdatedAtUtc']=$stamp }
    elseif ($State.PSObject.Properties['UpdatedAtUtc']) { $State.UpdatedAtUtc=$stamp }
    else { $State|Add-Member -NotePropertyName UpdatedAtUtc -NotePropertyValue $stamp -Force }
    Write-AppAddabilityJsonAtomic $State $Path
    $dir=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
    foreach($name in @('confirmed.json','couldnt-add.json','pending.json','created-service-principals.json')) {
        if ($name -eq 'confirmed.json') { $value=@($State.Results.Confirmed) }
        elseif ($name -eq 'couldnt-add.json') { $value=@($State.Results.CouldntAdd) }
        elseif ($name -eq 'pending.json') { $value=@($State.Results.Pending) }
        else { $value=@($State.CreatedServicePrincipals) }
        Write-AppAddabilityJsonAtomic -Value $value -Path (Join-Path $dir $name)
    }
    Write-AppAddabilityJsonAtomic -Value @(Get-AppAddabilityValue $State 'StopReceipts') -Path (Join-Path $dir 'stop-receipts.json')
}

function Complete-AppAddabilityItem {
    param([Parameter(Mandatory)]$State,[Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)]$Item,[Parameter(Mandatory)]$Outcome,[Parameter(Mandatory)][string]$ObservedAtUtc)
    if ($Outcome.Bucket -notin @('Confirmed','CouldntAdd','Pending')) { throw 'Only a classified app-addability result can be checkpointed.' }
    $entry=[ordered]@{AppId=$Item.AppId;UtcDate=$ObservedAtUtc;Result=$Outcome.Result;Reason=$Outcome.Reason;GraphErrorCode=$Outcome.GraphErrorCode;RetryAfterUtc=$Outcome.RetryAfterUtc;Source=$Item.Source;Metadata=$Item.Metadata;ServicePrincipal=$Outcome.Principal;Diagnostic=(Get-AppAddabilityValue $Outcome 'Diagnostic')}
    foreach($bucket in @('Confirmed','CouldntAdd','Pending')) { $State.Results[$bucket]=@($State.Results[$bucket] | Where-Object {$_.AppId -ne $Item.AppId}) }
    $State.Results[$Outcome.Bucket]=@(@($State.Results[$Outcome.Bucket])+$entry)
    if ($Outcome.CreatedServicePrincipal) {
        $existing=@($State.CreatedServicePrincipals | Where-Object {$_.AppId -eq $Outcome.CreatedServicePrincipal.AppId -and $_.ServicePrincipalId -eq $Outcome.CreatedServicePrincipal.ServicePrincipalId})
        if (-not $existing.Count) { $State.CreatedServicePrincipals=@(@($State.CreatedServicePrincipals)+$Outcome.CreatedServicePrincipal) }
    }
    if ($Outcome.Bucket -in @('Confirmed','CouldntAdd')) {
        $State.Queue=@($State.Queue|Where-Object {$_.AppId -ne $Item.AppId})
        $State.InFlight=$null
    } else {
        $queued=@($State.Queue|Where-Object {$_.AppId -eq $Item.AppId})|Select-Object -First 1
        if ($queued) { $queued.RetryAfterUtc=$Outcome.RetryAfterUtc }
        if ($Outcome.RetryAfterUtc) { $State.InFlight=[ordered]@{AppId=$Item.AppId;Phase='PostIntent';Attempt=1} } else { $State.InFlight=$null }
    }
    if ($Outcome.Stop) {
        $receipt=[ordered]@{
            AppId=$Item.AppId;ObservedAtUtc=$ObservedAtUtc;Reason=$Outcome.Reason
            FailureStage=(Get-AppAddabilityValue $Outcome.Diagnostic 'FailureStage')
            RequestMethod=(Get-AppAddabilityValue $Outcome.Diagnostic 'RequestMethod')
            Operation=(Get-AppAddabilityValue $Outcome.Diagnostic 'Operation')
            TransportOutcome=(Get-AppAddabilityValue $Outcome.Diagnostic 'TransportOutcome')
            ExceptionType=(Get-AppAddabilityValue $Outcome.Diagnostic 'ExceptionType')
            ErrorCategory=(Get-AppAddabilityValue $Outcome.Diagnostic 'ErrorCategory')
            GraphStatusCode=(Get-AppAddabilityValue $Outcome.Diagnostic 'GraphStatusCode')
            GraphErrorCode=(Get-AppAddabilityValue $Outcome.Diagnostic 'GraphErrorCode')
            RequestId=(Get-AppAddabilityValue $Outcome.Diagnostic 'RequestId')
            ClientRequestId=(Get-AppAddabilityValue $Outcome.Diagnostic 'ClientRequestId')
            RetryAfterUtc=$Outcome.RetryAfterUtc
        }
        $stopReceipts=@(Get-AppAddabilityValue $State 'StopReceipts' | Where-Object {$null -ne $_})+@($receipt)
        if ($State -is [Collections.IDictionary]) { $State['StopReceipts']=$stopReceipts }
        elseif ($State.PSObject.Properties['StopReceipts']) { $State.StopReceipts=$stopReceipts }
        else { $State|Add-Member -NotePropertyName StopReceipts -NotePropertyValue $stopReceipts -Force }
    }
    Save-AppAddabilityCheckpoint $State $Path
}
