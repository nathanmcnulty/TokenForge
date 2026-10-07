function Invoke-TokenForgeScopeProbe {
    <#
    .SYNOPSIS
    Resumable, bounded delegated-scope discovery for registered Microsoft clients.
    .DESCRIPTION
    Uses existing cookies only. Does not grant consent, process policy pages, or persist tokens.
    The database checkpoints every terminal app/resource observation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][securestring]$EstsAuth,
        [ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
        [guid[]]$ResourceId,
        [object[]]$Plan,
        [ValidateSet('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit')][string[]]$Protocols = @('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit'),
        [Parameter(Mandatory)][string]$DatabasePath,
        [string]$FlowDatabasePath,[switch]$ExploreAllFlows,[string]$NativeExecutablePath,[Collections.IDictionary]$FlowChanges,[Collections.IDictionary]$ScopeChanges,
        [guid[]]$ClientId,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,100000)][int]$MaxApplications = 100000,
        [ValidateRange(1,1000)][int]$MaxRedirects = 8,
        [ValidateRange(0,60000)][int]$DelayMilliseconds = 250,
        [switch]$Refresh,
        [string]$Tenant = 'organizations'
    )
    $Protocols=@($Protocols|Select-Object -Unique)
    $probePrincipal = if ($PrincipalFingerprint) { $PrincipalFingerprint } else { $Inventory.PrincipalFingerprint }
    if (-not $probePrincipal) { throw 'A probe principal fingerprint is required.' }
    if (-not $ResourceId -and -not $Plan) { throw 'Provide ResourceId or a probe Plan.' }
    $matrix = @{}
    foreach ($edge in @($Plan)) {
        if ($null -eq $edge) { continue }
        $client = [guid]$edge.ClientId; $resource = [guid]$edge.ResourceId
        if (-not $matrix.ContainsKey($client.ToString())) { $matrix[$client.ToString()] = @() }
        $matrix[$client.ToString()] += $resource
    }
    $probeLock=$null
    $probeLockPath=Resolve-TokenForgeVaultPath ($DatabasePath+'.probe.lock') -CreateDirectory
    try{
        if(-not(Test-Path $probeLockPath)){try{$probeLock=Open-TokenForgeVaultFile $probeLockPath -Create}catch [IO.IOException]{}}
        if(-not $probeLock){$probeLock=Open-TokenForgeVaultFile $probeLockPath}
    if($DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
        $null=Invoke-TokenForgeNativeEvidence $DatabasePath update -Document (New-TokenForgeScopeDatabase) -Domain evidence -NativeExecutablePath $NativeExecutablePath
        $database=Get-TokenForgeScopeDatabase $DatabasePath -NativeExecutablePath $NativeExecutablePath -Latest -TenantFingerprint $Inventory.TenantFingerprint -PrincipalFingerprint $probePrincipal
    }else{$database=Get-TokenForgeScopeDatabase $DatabasePath}
    if(-not $FlowDatabasePath){$FlowDatabasePath=$DatabasePath+'.flows.json'}
    $sqliteFlows=$FlowDatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)
    $flows=if($sqliteFlows){$null}else{Get-TokenForgeFlowEvidence $FlowDatabasePath}
    $apps = @($Inventory.Applications | Where-Object { -not $ClientId -or $_.AppId -in @($ClientId | ForEach-Object ToString) } | Sort-Object AppId)
    $processedApplications = 0
    foreach ($app in $apps) {
        $resources = @($ResourceId)
        if ($Plan) { $resources = @($matrix[$app.AppId] | Where-Object { $_ } | Sort-Object -Unique) }
        $pending = @($resources)
        if (-not $pending.Count) { continue }
        $processedThisApp=$false
        foreach ($resource in $pending) {
            $key = "$($app.AppId)/$resource"

            $watch = [Diagnostics.Stopwatch]::StartNew()
            $observation = [pscustomobject]@{
                ClientId = $app.AppId; ResourceId = $resource.ToString()
                TenantFingerprint = $Inventory.TenantFingerprint; PrincipalFingerprint = $probePrincipal
                ObservedAt = [DateTimeOffset]::UtcNow.ToString('o'); Outcome = 'Failed'
                Protocol = 'OAuth2V2Pkce'; Spa = $false; RequestedScopes = @('.default')
                ResponseScopes = @(); ScpScopes = @(); ClaimsReadable = $false; HasScpClaim = $false
                SignatureValidated = $false; NamespaceVerification = 'Unverifiable'; RequestVerification = 'Unverifiable'; ErrorCodes = @(); AttemptCount = 0; ElapsedSeconds = 0
                CatalogHash = $Inventory.DiscoveryCatalogHash
            }
            $aliases=@($resource.ToString())+@($Inventory.Applications|Where-Object AppId -eq $resource.ToString()|ForEach-Object { $_.IdentifierUris })
            if($resource.ToString() -eq '00000003-0000-0000-c000-000000000000'){$aliases+='https://graph.microsoft.com'}
            if($resource.ToString() -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013'){$aliases+=@('https://management.azure.com','https://management.core.windows.net')}
            $aliases=@($aliases|Where-Object {$_ -is [string] -and $_ -match '^[A-Za-z0-9_.:/-]{1,256}$'}|ForEach-Object {$_.TrimEnd('/')}|Sort-Object -Unique)
            $slots=@()
            $redirects=@($app.RedirectUris|Where-Object {$_ -is [string] -and $_ -notmatch '^(brk-|ms-appx-web:)'}|Select-Object -Unique|Sort-Object @{Expression={if($_ -eq $app.PreferredRedirectUri){0}elseif($_ -match 'nativeclient|localhost|^urn:'){1}else{2}}},@{Expression={$_}}|Select-Object -First $MaxRedirects)
            $eligibility=if($app.Registration -eq 'Missing'){'MissingRegistration'}elseif($app.Registration -eq 'OwnerMismatch' -or $app.Ownership -ne 'VerifiedMicrosoftOwner'){'OwnerMismatch'}elseif(-not $app.AccountEnabled){'Disabled'}elseif(-not $redirects.Count){if($app.RedirectUris.Count){'BrokerRedirectHint'}else{'NoRedirect'}}else{'Eligible'}
            if($eligibility -eq 'Eligible'){
                foreach($redirect in $redirects){
                    $uri=$null
                    if(-not[uri]::TryCreate($redirect,[UriKind]::Absolute,[ref]$uri) -or $uri.Query -or $uri.Fragment -or $uri.UserInfo){continue}
                    foreach($protocol in @($Protocols|Select-Object -Unique)){
                        $modes=if($protocol -eq 'OAuth2V2Pkce' -and $uri.Scheme -eq 'https' -and $uri.Host -ne 'login.microsoftonline.com'){@($false,$true)}else{@($false)}
                        foreach($mode in $modes){$slots+=@{Protocol=$protocol;Spa=$mode;RedirectFingerprint=(Get-TokenForgeFingerprint $redirect)}}
                    }
                }
                if(-not $slots.Count){$eligibility='InvalidRedirectHints'}
            }
            $flowPlan=@{TenantFingerprint=$Inventory.TenantFingerprint;PrincipalFingerprint=$probePrincipal;ClientId=$app.AppId;ResourceId=$resource.ToString();Tenant=$Tenant;CatalogHash=if($Inventory.DiscoveryCatalogHash -match '^[a-f0-9]{64}$'){$Inventory.DiscoveryCatalogHash}else{$null};Eligibility=$eligibility;ResourceAliases=$aliases;Cells=@($slots);PlannedAt=[DateTimeOffset]::UtcNow.ToString('o')}
            $planHash=Get-TokenForgeFlowPlanHash $flowPlan
            if($sqliteFlows){$flows=Get-TokenForgeFlowEvidence $FlowDatabasePath -PlanFingerprint $planHash -NativeExecutablePath $NativeExecutablePath}
            if($null -ne $FlowChanges -and $flows.Plans.ContainsKey($planHash)){
                Add-TokenForgeFlowChanges $FlowChanges $flows.Plans[$planHash] $planHash
                foreach($prior in @($flows.Attempts|Where-Object PlanFingerprint -eq $planHash)){Add-TokenForgeFlowChanges $FlowChanges -Attempt $prior}
            }
            $priorSlots=@{}
            foreach($prior in @($flows.Attempts|Where-Object PlanFingerprint -eq $planHash|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime})){$priorSlots[$prior.AttemptKey]=$prior}
            $previousAttempts=@($priorSlots.Values|Where-Object Outcome -ne 'Started')
            $previousKeys=@($previousAttempts|ForEach-Object {$_.AttemptKey}|Sort-Object -Unique)
            $previousSuccess=@($previousAttempts|Where-Object Outcome -in @('Succeeded','OpaqueToken','NoDelegatedScp'))
            $aggregate=@($database.Observations|Where-Object {$_.ClientId -eq $app.AppId -and $_.ResourceId -eq $resource.ToString() -and $_.TenantFingerprint -eq $Inventory.TenantFingerprint -and $_.PrincipalFingerprint -eq $probePrincipal}|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime} -Descending|Select-Object -First 1)
            $bestPrior=@($previousSuccess|Sort-Object @{Expression={if($_.Outcome -eq 'Succeeded'){0}else{1}}},@{Expression={([DateTimeOffset]$_.ObservedAt).UtcDateTime};Descending=$true}|Select-Object -First 1)
            $hasAggregate=$false
            if($aggregate.Count){
                if($bestPrior.Count){
                    $hasAggregate=([DateTimeOffset]$aggregate[0].ObservedAt -eq [DateTimeOffset]$bestPrior[0].ObservedAt -and $aggregate[0].Protocol -eq $bestPrior[0].Protocol -and $aggregate[0].Spa -eq $bestPrior[0].Spa -and $aggregate[0].RedirectFingerprint -eq $bestPrior[0].RedirectFingerprint)
                }elseif($previousAttempts.Count){
                    $last=@($previousAttempts|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime} -Descending)[0]
                    $hasAggregate=([DateTimeOffset]$aggregate[0].ObservedAt -ge [DateTimeOffset]$last.ObservedAt)
                }elseif($eligibility -ne 'Eligible'){
                    $expectedOutcome=if($eligibility -eq 'BrokerRedirectHint'){'BrokerRequired'}elseif($eligibility -eq 'InvalidRedirectHints'){'Failed'}else{$eligibility}
                    $hasAggregate=$aggregate[0].Outcome -eq $expectedOutcome
                }
            }
            $pairComplete=($flowPlan.Cells.Count -eq $previousKeys.Count -or (-not $ExploreAllFlows -and $previousSuccess.Count)) -and -not @($priorSlots.Values|Where-Object Outcome -eq 'Started').Count
            if(-not $Refresh -and $flows.Plans.ContainsKey($planHash) -and $pairComplete -and $hasAggregate -and -not @($previousAttempts|Where-Object Outcome -eq 'ContextMismatch').Count){if($null -ne $ScopeChanges){$ScopeChanges["$($app.AppId)/$resource"]=$aggregate[0]};continue}
            if(-not $processedThisApp){if($processedApplications -ge $MaxApplications){return};$processedApplications++;$processedThisApp=$true}
            $flows=Save-TokenForgeFlowEvidence $FlowDatabasePath -Plan $flowPlan -PlanFingerprint $planHash -ExistingDocument $flows -NativeExecutablePath $NativeExecutablePath -Changes $FlowChanges
            if ($app.Registration -eq 'Missing') { $observation.Outcome = 'MissingRegistration' }
            elseif ($app.Registration -eq 'OwnerMismatch' -or $app.Ownership -ne 'VerifiedMicrosoftOwner') { $observation.Outcome = 'OwnerMismatch' }
            elseif (-not $app.AccountEnabled) { $observation.Outcome = 'Disabled' }
            else {
                $redirects = @($app.RedirectUris | Where-Object { $_ -is [string] -and $_ -notmatch '^(brk-|ms-appx-web:)' } | Select-Object -Unique | Sort-Object @{ Expression = { if ($_ -eq $app.PreferredRedirectUri) { 0 } elseif ($_ -match 'nativeclient|localhost|^urn:') { 1 } else { 2 } } }, @{ Expression = { $_ } } | Select-Object -First $MaxRedirects)
                if (-not $redirects.Count) { $observation.Outcome = if ($app.RedirectUris.Count) { 'BrokerRequired' } else { 'NoRedirect' } }
                foreach ($redirect in $redirects) {
                    $uri = $null
                    if (-not [uri]::TryCreate($redirect,[UriKind]::Absolute,[ref]$uri) -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) { continue }
                    $attempts = @(foreach ($protocol in $Protocols) {
                        $modes = if ($protocol -eq 'OAuth2V2Pkce' -and $uri.Scheme -eq 'https' -and $uri.Host -ne 'login.microsoftonline.com') { @($false,$true) } else { @($false) }
                        foreach ($mode in $modes) { [pscustomobject]@{ Protocol = $protocol; Spa = $mode } }
                    })
                    foreach ($attempt in $attempts) {
                        $spa = $attempt.Spa
                        $token = $null
                        $redirectHash=Get-TokenForgeFingerprint $redirect
                        $attemptKey=Get-TokenForgeFingerprint ($planHash+'|'+$attempt.Protocol+'|'+[int]$spa+'|'+$redirectHash)
                        $previous=@($flows.Attempts|Where-Object {$_.PlanFingerprint -eq $planHash -and $_.AttemptKey -eq $attemptKey}|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime} -Descending|Select-Object -First 1)
                        $flowAttempt=$null
                        if(-not $Refresh -and $previous.Count -and $previous[0].Outcome -ne 'Started'){$flowAttempt=$previous[0]}
                        if($flowAttempt){
                            $observation.AttemptCount++
                            if($flowAttempt.Outcome -eq 'ContextMismatch'){$observation.Outcome='ContextMismatch';break}
                            if($flowAttempt.Outcome -in @('Succeeded','OpaqueToken','NoDelegatedScp')){
                                foreach($field in @('Outcome','Protocol','Spa','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','NamespaceVerification','RequestVerification')){$observation.$field=$flowAttempt[$field]}
                                $observation|Add-Member RedirectFingerprint $redirectHash -Force
                                if(-not $ExploreAllFlows){break}
                            }
                            continue
                        }
                        $started=[DateTimeOffset]::UtcNow.ToString('o')
                        $flowAttempt=@{AttemptId=[guid]::NewGuid().ToString();PlanFingerprint=$planHash;AttemptKey=$attemptKey;ClientId=$app.AppId;ResourceId=$resource.ToString();TenantFingerprint=$Inventory.TenantFingerprint;PrincipalFingerprint=$probePrincipal;StartedAt=$started;ObservedAt=$started;Protocol=$attempt.Protocol;Spa=[bool]$spa;RedirectFingerprint=$redirectHash;Outcome='Started';ResponseScopes=@();ScpScopes=@();ClaimsReadable=$false;HasScpClaim=$false;NamespaceVerification='Unverifiable';RequestVerification='Unverifiable';SignatureValidated=$false;ErrorCodes=@();ElapsedSeconds=0}
                        $flows=Save-TokenForgeFlowEvidence $FlowDatabasePath -Attempt $flowAttempt -ExistingDocument $flows -NativeExecutablePath $NativeExecutablePath -Changes $FlowChanges
                        $attemptWatch=[Diagnostics.Stopwatch]::StartNew()
                        $observation.AttemptCount++
                        if($observation.Outcome -notin @('Succeeded','OpaqueToken','NoDelegatedScp')){$observation.Protocol = $attempt.Protocol;$observation.Spa = $spa}
                        try {
                            $request = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $resource -RedirectUri $redirect -Tenant $Tenant -Spa:$spa -Protocol $attempt.Protocol
                            $token = Get-TokenForgeToken -Request $request -EstsAuth $EstsAuth -CookieName $CookieName -WarningAction SilentlyContinue
                            $claims = $token.TokenClaims
                            if ($claims.PSObject.Properties['TenantFingerprint'] -and $claims.PSObject.Properties['PrincipalFingerprint']) {
                                if (($claims.TenantFingerprint -and $claims.TenantFingerprint -ne $Inventory.TenantFingerprint) -or ($claims.PrincipalFingerprint -and $claims.PrincipalFingerprint -ne $probePrincipal)) {
                                    $flowAttempt.Outcome='ContextMismatch';$flowAttempt.NamespaceVerification='Mismatch'
                                    $observation.Outcome = 'ContextMismatch'
                                    $observation.NamespaceVerification = 'Mismatch'
                                    break
                                }
                                if ($claims.TenantFingerprint -and $claims.PrincipalFingerprint) { $observation.NamespaceVerification = 'Matched';$flowAttempt.NamespaceVerification='Matched' }
                            }
                            $aliases=$flowPlan.ResourceAliases
                            $audience = if ($claims.PSObject.Properties['Audience']) { [string]$claims.Audience } else { '' }
                            $issuedClient = if ($claims.PSObject.Properties['ClientId']) { [string]$claims.ClientId } else { '' }
                            $audienceMatched = $audience -and $audience.TrimEnd('/') -in @($aliases | ForEach-Object { ([string]$_).TrimEnd('/') })
                            if (($issuedClient -and $issuedClient -ne $app.AppId) -or ($audience -and -not $audienceMatched)) {
                                $flowAttempt.Outcome='ContextMismatch';$flowAttempt.RequestVerification='Mismatch'
                                $observation.Outcome = 'ContextMismatch'
                                $observation.RequestVerification = 'Mismatch'
                                break
                            }
                            if ($issuedClient -and $audienceMatched) { $observation.RequestVerification = 'Matched';$flowAttempt.RequestVerification='Matched' }
                            $observation.ResponseScopes = @($token.GrantedScopes)
                            $observation.ClaimsReadable = $token.TokenClaims.Readable
                            $observation.HasScpClaim = $token.TokenClaims.HasDelegatedScopeClaim
                            $observation.ScpScopes = @($token.TokenClaims.Scopes)
                            $observation.Spa = $spa
                            $observation.Protocol = $attempt.Protocol
                            $observation | Add-Member -NotePropertyName RedirectFingerprint -NotePropertyValue (Get-TokenForgeFingerprint -Value $redirect) -Force
                            $observation.Outcome = if (-not $token.TokenClaims.Readable) { 'OpaqueToken' } elseif (-not $token.TokenClaims.HasDelegatedScopeClaim -or -not $observation.ScpScopes.Count) { 'NoDelegatedScp' } else { 'Succeeded' }
                            foreach($field in @('ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim')){$flowAttempt[$field]=$observation.$field}
                            $flowAttempt.Outcome=$observation.Outcome
                            if($flowAttempt.Outcome -eq 'Succeeded' -and ($flowAttempt.NamespaceVerification -ne 'Matched' -or $flowAttempt.RequestVerification -ne 'Matched')){$flowAttempt.Outcome='NoDelegatedScp';$observation.Outcome='NoDelegatedScp'}
                            if(-not $ExploreAllFlows){break}
                        } catch {
                            $observation.ErrorCodes = @(@($observation.ErrorCodes) + @([regex]::Matches($_.Exception.Message,'\bAADSTS([0-9]{4,9})\b') | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique)
                            $flowAttempt.ErrorCodes=@([regex]::Matches($_.Exception.Message,'\bAADSTS([0-9]{4,9})\b')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique|Select-Object -First 16)
                            $flowAttempt.Outcome='Failed'
                        } finally {
                            $flowAttempt.ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');$flowAttempt.ElapsedSeconds=[math]::Round($attemptWatch.Elapsed.TotalSeconds,3)
                            # Persistence errors stop the sweep; no additional issuance after a failed checkpoint.
                            try{$flows=Save-TokenForgeFlowEvidence $FlowDatabasePath -Attempt $flowAttempt -ExistingDocument $flows -NativeExecutablePath $NativeExecutablePath -Changes $FlowChanges}finally{
                            if ($token) { $token.AccessToken.Dispose(); if ($token.RefreshToken) { $token.RefreshToken.Dispose() } }
                            $token = $null
                            }
                        }
                        if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
                    }
                    if ($observation.Outcome -eq 'ContextMismatch' -or (-not $ExploreAllFlows -and $observation.Outcome -in @('Succeeded','OpaqueToken','NoDelegatedScp'))) { break }
                }
            }
            $latest=@{}
            foreach($item in @($flows.Attempts|Where-Object PlanFingerprint -eq $planHash|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime})){$latest[$item.AttemptKey]=$item}
            $best=@($latest.Values|Where-Object Outcome -in @('Succeeded','OpaqueToken','NoDelegatedScp')|Sort-Object @{Expression={if($_.Outcome -eq 'Succeeded'){0}else{1}}},@{Expression={([DateTimeOffset]$_.ObservedAt).UtcDateTime};Descending=$true}|Select-Object -First 1)
            if(@($latest.Values|Where-Object Outcome -eq 'ContextMismatch').Count){$observation.Outcome='ContextMismatch';$observation.ScpScopes=@();$observation.ResponseScopes=@()}
            elseif($best.Count){
                foreach($field in @('Outcome','ObservedAt','Protocol','Spa','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','NamespaceVerification','RequestVerification')){$observation.$field=$best[0][$field]}
                $observation|Add-Member RedirectFingerprint $best[0].RedirectFingerprint -Force
            }
            if(-not $best.Count -and $latest.Count){$observation.ObservedAt=@($latest.Values|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime} -Descending)[0].ObservedAt}
            $observation.ElapsedSeconds = [math]::Round($watch.Elapsed.TotalSeconds,3)
            $database = Add-TokenForgeScopeObservation -Database $database -Observation $observation -Path $DatabasePath -NativeExecutablePath $NativeExecutablePath
            if($null -ne $ScopeChanges){$ScopeChanges["$($observation.ClientId)/$($observation.ResourceId)"]=$observation}
            $observation
            if($observation.Outcome -eq 'ContextMismatch'){return}
            if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
        }
    }
    }finally{if($probeLock){$probeLock.Dispose()}}
}

function Sync-TokenForgeApplicationRegistration {
    <# .SYNOPSIS
    Ensure verified/published Microsoft candidates are registered; checkpoint results without granting consent.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][securestring]$GraphToken,
        [Parameter(Mandatory)][string]$DatabasePath,
        [guid[]]$ClientId,
        [ValidateRange(1,100000)][int]$MaxApplications = 100000,
        [ValidateRange(0,60000)][int]$DelayMilliseconds = 250,
        [switch]$RetryFailures,
        [switch]$ResolvePublishedCandidates,
        [switch]$ResolveSignInCandidates,
        [string]$MetadataPath,[string]$NativeExecutablePath
    )
    $context = Get-TokenForgeTokenClaims -AccessToken $GraphToken
    if (-not $context.TenantFingerprint -or $context.TenantFingerprint -ne $Inventory.TenantFingerprint) { throw 'Graph token tenant does not match registration inventory.' }
    $registrationLock=$null
    $registrationLockPath=Resolve-TokenForgeVaultPath ($DatabasePath+'.probe.lock') -CreateDirectory
    try{
    $registrationLock=if(Test-Path -LiteralPath $registrationLockPath){Open-TokenForgeVaultFile $registrationLockPath}else{Open-TokenForgeVaultFile $registrationLockPath -Create}
    if(-not $MetadataPath){$MetadataPath=Join-Path (Split-Path $DatabasePath -Parent) 'applications.json'}
    if($DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
        if(-not $WhatIfPreference){$null=Invoke-TokenForgeNativeEvidence $DatabasePath update -Document (New-TokenForgeScopeDatabase) -Domain evidence -NativeExecutablePath $NativeExecutablePath}
        $database=Get-TokenForgeScopeDatabase $DatabasePath -NativeExecutablePath $NativeExecutablePath -Latest -TenantFingerprint $Inventory.TenantFingerprint
    }else{$database=Get-TokenForgeScopeDatabase $DatabasePath}
    $completed = @{};$unresolvedCleanup=@{}
    foreach ($attempt in $database.RegistrationAttempts) {
        if ($attempt.TenantFingerprint -eq $Inventory.TenantFingerprint) { $completed[$attempt.AppId] = $attempt.Outcome; if($attempt.Outcome -eq 'CleanupRequired'){$unresolvedCleanup[$attempt.AppId]=$true}elseif($attempt.Outcome -eq 'CleanupResolved'){$unresolvedCleanup.Remove($attempt.AppId)} }
    }
    foreach($id in @($completed.Keys)){if($completed[$id] -eq 'CleanupResolved'){$completed.Remove($id)}}
    if ($unresolvedCleanup.Count) { throw 'Registration stopped by an unresolved ownership-cleanup checkpoint. Verify cleanup and append a CleanupResolved record before resuming.' }
    $apps = @($Inventory.Applications | Where-Object { $_.Registration -eq 'Missing' -and ($_.Ownership -eq 'PublishedMicrosoftOwner' -or ($ResolvePublishedCandidates -and @($_.Sources | Where-Object { $_.Evidence -in @('PublishedMetadata','PublishedResource','PublishedGraph','PublishedEntraDocs','PublishedLearn','PublishedGitHub') }).Count -gt 0) -or ($ResolveSignInCandidates -and @($_.Sources|Where-Object Evidence -eq 'ObservedSignInNotOwnership').Count -gt 0)) -and (-not $ClientId -or $_.AppId -in @($ClientId | ForEach-Object ToString)) } | Sort-Object AppId)
    $processedApplications = 0
    foreach ($app in $apps) {
        if ($completed.ContainsKey($app.AppId) -and (-not $RetryFailures -or $completed[$app.AppId] -ne 'Failed')) {
            $saved=@($database.RegistrationAttempts|Where-Object {$_.AppId -eq $app.AppId -and $_.TenantFingerprint -eq $Inventory.TenantFingerprint}|Select-Object -Last 1)
            if($saved.Count -and -not $WhatIfPreference){$null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document @{UpdatedAt=$database.UpdatedAt;RegistrationAttempts=$saved} -Kind RegistrationAttempts -NativeExecutablePath $NativeExecutablePath}
            continue
        }
        if ($processedApplications -ge $MaxApplications) { break }
        $processedApplications++
        if (-not $PSCmdlet.ShouldProcess($app.AppId,'Register Microsoft-owned candidate without granting consent')) { continue }
        $httpStatus = $null
        try { $result = Register-TokenForgeApplication -GraphToken $GraphToken -Application $app -ResolvePublishedCandidate:$ResolvePublishedCandidates -ResolveSignInCandidate:$ResolveSignInCandidates -Confirm:$false; $outcome = $result.Outcome }
        catch { $outcome = 'Failed'; if ($_.Exception.Data['TokenForgeOutcome'] -in @('OwnerRejected','CleanupRequired')) { $outcome = [string]$_.Exception.Data['TokenForgeOutcome'] }; $match = [regex]::Match($_.Exception.Message,'\bHTTP ([0-9]{3})\b'); if ($match.Success) { $httpStatus = [int]$match.Groups[1].Value } }
        $attempt = [pscustomobject]@{ AppId = $app.AppId; TenantFingerprint = $Inventory.TenantFingerprint; AttemptedAt = [DateTimeOffset]::UtcNow.ToString('o'); Outcome = $outcome; HttpStatus = $httpStatus }
        $database.RegistrationAttempts += $attempt
        $database.UpdatedAt = [DateTimeOffset]::UtcNow.ToString('o')
        if($DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){
            $checkpoint=New-TokenForgeScopeDatabase;$checkpoint.RegistrationAttempts=@($attempt)
            $null=Invoke-TokenForgeNativeEvidence $DatabasePath update -Document $checkpoint -Domain evidence -NativeExecutablePath $NativeExecutablePath
        }else{Save-TokenForgeDocument -Document $database -Path $DatabasePath}
        $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document @{UpdatedAt=$database.UpdatedAt;RegistrationAttempts=@($attempt)} -Kind RegistrationAttempts -NativeExecutablePath $NativeExecutablePath
        $attempt
        if($httpStatus -in @(401,403)){throw "Registration stopped (HTTP $httpStatus); the failure was checkpointed before stopping."}
        if ($outcome -eq 'CleanupRequired') { throw 'Registration stopped because ownership cleanup is required; inspect the last application ID in RegistrationAttempts.' }
        if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
    }
    }finally{if($registrationLock){$registrationLock.Dispose()}}
}
