function Get-TokenForgeApplicationMetadata {
    <# .SYNOPSIS
    Read the persistent application metadata catalog; it contains no authentication credentials.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[switch]$PublicOnly)
    try {
        $file=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 134217728){throw 'Invalid metadata file.'}
        $document=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop
        # PowerShell 7.4 parses ISO dates as DateTime; normalize them back to UTC text.
        $normalizeDates={param($value)
            if($value -is [Collections.IDictionary]){foreach($key in @($value.Keys)){if($value[$key] -is [datetime]){$value[$key]=([DateTimeOffset]$value[$key].ToUniversalTime()).ToString('o')}else{& $normalizeDates $value[$key]}}}
            elseif($value -is [array]){foreach($item in $value){& $normalizeDates $item}}
        }; & $normalizeDates $document
        if($document.SchemaVersion -ne 1 -or $document.Format -cne 'TokenForgeApplicationMetadata' -or $document.Applications -isnot [Collections.IDictionary] -or $document.Origins -isnot [Collections.IDictionary] -or $document.Runs -isnot [array]){throw 'Invalid metadata schema.'}
        foreach($key in $document.Applications.Keys){$id=[guid]::Empty;if(-not [guid]::TryParse($key,[ref]$id) -or $id -eq [guid]::Empty -or $key -cne $id.ToString() -or $document.Applications[$key].AppId -cne $key -or $document.Applications[$key].Records -isnot [Collections.IDictionary]){throw 'Invalid application metadata.'}}
        if($PublicOnly){
            # Reject rather than redact: public CI must never merge an accidentally private ledger.
            $keys={param($object,$allowed)
                if($object -isnot [Collections.IDictionary] -or @($object.Keys|Where-Object {$_ -cnotin $allowed}).Count){throw 'Unexpected public metadata fields.'}
                foreach($field in $object.Keys){
                    $value=$object[$field]
                    if($field -in @('Applications','Origins','Records','Attributes')){
                        if($value -isnot [Collections.IDictionary]){throw 'Invalid public dictionary.'};continue
                    }
                    if($field -in @('Runs','PreviousVersions','Sources','SourceSnapshots','Grants')){
                        if($value -isnot [array]){throw 'Invalid public record array.'};continue
                    }
                    if($field -in @('Scopes','RedirectUris','IdentifierUris')){
                        if($value -isnot [array] -or @($value|Where-Object {$_ -isnot [string]}).Count){throw 'Invalid public string array.'};continue
                    }
                    if($null -eq $value){continue}
                    if($value -is [Collections.IDictionary] -or $value -is [array] -or $value -isnot [ValueType] -and $value -isnot [string]){throw 'Public scalar fields cannot contain objects.'}
                    if($field -in @('CreatedAt','UpdatedAt','FirstSeenAt','LastSeenAt','CurrentVersionFirstSeenAt','LastObservedAt','ObservedAt','RecordedAt')){
                        $date=[DateTimeOffset]::MinValue
                        if($value -isnot [string] -or -not [DateTimeOffset]::TryParse($value,[ref]$date)){throw 'Invalid public observation date.'}
                    }elseif($field -in @('ContentSha256','Sha256')){
                        if($value -isnot [string] -or $value -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid public content hash.'}
                    }elseif($field -in @('AppId','ResourceId','OwnerTenantId','Id','LastRunId')){
                        $guid=[guid]::Empty
                        if($value -isnot [string] -or -not [guid]::TryParse($value,[ref]$guid) -or $guid -eq [guid]::Empty){throw 'Invalid public GUID.'}
                    }elseif($field -in @('PublicClient','IsResourceCandidate','PresentInLatestRun')){
                        if($value -isnot [bool]){throw 'Invalid public boolean.'}
                    }elseif($field -in @('SchemaVersion','ApplicationRecordCount','IgnoredEmptyAppIdCount')){
                        if($value -isnot [long] -and $value -isnot [int] -or $value -lt 0){throw 'Invalid public count.'}
                    }elseif($field -ne 'Foci' -and $value -isnot [string]){throw 'Invalid public text attribute.'}
                }

            }
            $checkPayload={param($payload)
                & $keys $payload.Attributes @('AppId','Name','OwnerTenantId','Ownership','PublicClient','Foci','RedirectUris','PreferredRedirectUri','Grants','IsResourceCandidate','IdentifierUris')
                foreach($grant in @($payload.Attributes.Grants)){& $keys $grant @('ResourceId','Scopes')}
                foreach($source in @($payload.Sources)){
                    & $keys $source @('Name','Location','Evidence')
                    $uri=[uri]$source.Location
                    if($uri.Scheme -ne 'https' -or $uri.Host -ne 'raw.githubusercontent.com' -or $uri.UserInfo -or $uri.Query){throw 'Public CI requires public upstream source locations.'}
                }
            }
            & $keys $document @('Format','SchemaVersion','CreatedAt','UpdatedAt','Applications','Origins','Runs')
            foreach($app in $document.Applications.Values){
                & $keys $app @('AppId','FirstSeenAt','LastSeenAt','Records')
                foreach($origin in $app.Records.Keys){
                    $record=$app.Records[$origin]
                    & $keys $record @('Kind','TenantFingerprint','PrincipalFingerprint','ResourceId','FirstSeenAt','LastSeenAt','PresentInLatestRun','CurrentVersionFirstSeenAt','Attributes','Sources','ContentSha256','PreviousVersions')
                    if($origin -cne 'Discovery///' -or $record.Kind -cne 'Discovery' -or $record.TenantFingerprint -or $record.PrincipalFingerprint -or $record.ResourceId){throw 'Private origins cannot be published.'}
                    & $checkPayload $record
                    foreach($version in $record.PreviousVersions){& $keys $version @('FirstSeenAt','LastSeenAt','Attributes','Sources','ContentSha256');& $checkPayload $version}
                }
            }
            foreach($origin in $document.Origins.Keys){& $keys $document.Origins[$origin] @('Kind','LastObservedAt','LastRunId');if($origin -cne 'Discovery///' -or $document.Origins[$origin].Kind -cne 'Discovery'){throw 'Private origins cannot be published.'}}
            foreach($run in $document.Runs){
                & $keys $run @('Id','Kind','ObservedAt','RecordedAt','ApplicationRecordCount','IgnoredEmptyAppIdCount','TenantFingerprint','SourceSnapshots')
                if($run.Kind -cne 'Discovery' -or $run.TenantFingerprint){throw 'Private runs cannot be published.'}
                foreach($snapshot in $run.SourceSnapshots){& $keys $snapshot @('Location','Sha256','HashKind')}
            }
        }
        $document
    }catch{throw 'Application metadata cannot be read; check format, size, and file access. Details suppressed.'}
}

function Update-TokenForgeApplicationMetadata {
    <# .SYNOPSIS
    Merge collected application attributes into a persistent JSON catalog with provenance and change history.
    .DESCRIPTION
    Whitelists supported metadata fields. Tenant/account/resource origins remain independent.
    Missing IDs are retained; metadata is diagnostic and never feeds authentication or ownership authorization.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Document,
        [Parameter(Mandatory)][ValidateSet('Discovery','Inventory','SignIns','ScopeObservations','RegistrationAttempts','FlowAttempts')][string]$Kind
    )
    if($Kind -eq 'FlowAttempts'){Assert-TokenForgeFlowDocument $Document}
    $columns=switch($Kind){
        Discovery {@('AppId','Name','OwnerTenantId','Ownership','PublicClient','Foci','RedirectUris','PreferredRedirectUri','Grants','IsResourceCandidate','IdentifierUris')}
        Inventory {@('AppId','Name','PublishedName','ServicePrincipalType','PreferredSingleSignOnMode','LoginUrl','LogoutUrl','Homepage','Registration','Ownership','OwnerTenantId','AccountEnabled','AssignmentRequired','SignInAudience','PublicClient','Foci','RedirectUris','TenantRedirectUris','PreferredRedirectUri','PublishedGrants','DelegatedScopeDefinitions','AppRoleDefinitions','IdentifierUris','IsResourceCandidate')}
        SignIns {@('AppId','SignInCount','KnownInInventory','RegisteredMicrosoft','Evidence','ProtocolCounts','ClientTypeCounts','EventTypeCounts','ResourceCounts','OutcomeCounts','AuthenticationMethodCounts','CredentialTypeCounts','IncomingTokenTypeCounts')}
        RegistrationAttempts {@('AppId','Outcome','HttpStatus')}
        FlowAttempts {@('AttemptKey','PlanFingerprint','Protocol','Spa','RedirectFingerprint','Outcome','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','NamespaceVerification','RequestVerification','SignatureValidated','ErrorCodes','ElapsedSeconds')}
        ScopeObservations {@('ClientId','ResourceId','Outcome','Protocol','Spa','RequestedScopes','ResponseScopes','ScpScopes','ClaimsReadable','HasScpClaim','SignatureValidated','NamespaceVerification','RequestVerification','ErrorCodes','AttemptCount','ElapsedSeconds','RedirectFingerprint','CatalogHash')}
    }
    $stamp=if($Kind -eq 'Discovery'){$Document.FetchedAt}elseif($Kind -in @('ScopeObservations','RegistrationAttempts','FlowAttempts')){$Document.UpdatedAt}else{$Document.CapturedAt}
    $observed=([DateTimeOffset]$stamp).ToUniversalTime()
    if($observed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Application metadata observation date is in the future.'}
    $tenant=if($Kind -in @('Discovery','ScopeObservations','RegistrationAttempts','FlowAttempts')){$null}else{[string]$Document.TenantFingerprint}
    # Scope databases carry namespaces on each observation, not on the document.
    if($Kind -eq 'ScopeObservations'){$tenant=$null}
    if($Kind -in @('Inventory','SignIns') -and $tenant -notmatch '^[a-f0-9]{64}$'){throw 'A tenant fingerprint is required for private metadata.'}
    if($Kind -eq 'SignIns' -and $Document.Enumeration -ne 'Complete'){throw 'Incomplete sign-in discovery cannot update application metadata.'}
    $rows=if($Kind -eq 'RegistrationAttempts'){@($Document.RegistrationAttempts|Sort-Object {([DateTimeOffset]$_.AttemptedAt)})}elseif($Kind -eq 'FlowAttempts'){@($Document.Attempts|Sort-Object {([DateTimeOffset]$_.ObservedAt)})}elseif($Kind -eq 'ScopeObservations'){@($Document.Observations|Sort-Object {([DateTimeOffset]$_.ObservedAt)})}else{@($Document.Applications)}
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $null=New-Item -ItemType Directory -Path (Split-Path $full) -Force
    $lock=$null
    try {
        foreach($part in @($full,"$full.lock")){
            $file=Get-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
            if($file -and ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint))){throw 'Metadata files cannot be links or directories.'}
        }
        $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::OpenOrCreate;$options.Access=[IO.FileAccess]::ReadWrite;$options.Share=[IO.FileShare]::None
        if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
        try{$lock=[IO.FileStream]::new("$full.lock",$options)}catch{throw 'Application metadata is already in use or unavailable.'}
        $now=[DateTimeOffset]::UtcNow.ToString('o')
        $catalog=if(Test-Path -LiteralPath $full){Get-TokenForgeApplicationMetadata $full}else{@{Format='TokenForgeApplicationMetadata';SchemaVersion=1;CreatedAt=$now;UpdatedAt=$now;Applications=@{};Origins=@{};Runs=@()}}
        $runId=[guid]::NewGuid().ToString();$seen=@{};$affectedOrigins=@{};$count=0;$emptyIds=0
        foreach($row in $rows){
            $rawId=if($Kind -in @('ScopeObservations','FlowAttempts')){$row.ClientId}else{$row.AppId};$id=[guid]::Empty
            if(-not [guid]::TryParse([string]$rawId,[ref]$id)){throw 'Invalid application ID in collected metadata.'}
            if($id -eq [guid]::Empty){$emptyIds++;continue}
            $appId=$id.ToString();$rowTenant=$tenant;$principal=$null;$resource=$null;$date=$observed
            if($Kind -eq 'RegistrationAttempts'){
                $rowTenant=[string]$row.TenantFingerprint
                if($rowTenant -notmatch '^[a-f0-9]{64}$' -or $row.Outcome -cnotin @('Created','AlreadyPresent','Failed','OwnerRejected','CleanupRequired','CleanupResolved','NotCreated')){throw 'Invalid registration metadata.'}
                $date=([DateTimeOffset]$row.AttemptedAt).ToUniversalTime()
                if($date -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Future registration date.'}
                if($null -ne $row.HttpStatus -and ($row.HttpStatus -isnot [int] -and $row.HttpStatus -isnot [long] -or $row.HttpStatus -lt 100 -or $row.HttpStatus -gt 599)){throw 'Invalid registration status.'}
            }
            if($Kind -in @('ScopeObservations','FlowAttempts')){
                $rowTenant=[string]$row.TenantFingerprint;$principal=[string]$row.PrincipalFingerprint;$resource=[string]$row.ResourceId
                if($rowTenant -notmatch '^[a-f0-9]{64}$' -or $principal -notmatch '^[a-f0-9]{64}$'){throw 'Scope observation namespace is invalid.'}
                $resourceId=[guid]::Empty;if(-not [guid]::TryParse($resource,[ref]$resourceId) -or $resourceId -eq [guid]::Empty){throw 'Invalid scope resource ID.'};$resource=$resourceId.ToString()
                $date=([DateTimeOffset]$row.ObservedAt).ToUniversalTime()
                if($date -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Future scope observation date.'}
            }
            $origin=@($Kind,$rowTenant,$principal,$resource) -join '/'
            if($Kind -eq 'FlowAttempts'){if($row.AttemptKey -notmatch '^[a-f0-9]{64}$'){throw 'Invalid flow attempt key.'};$origin+='/'+$row.AttemptKey}
            $attributes=[ordered]@{}
            foreach($column in $columns){if($row.PSObject.Properties[$column]){$attributes[$column]=$row.$column}elseif($row -is [Collections.IDictionary] -and $row.Contains($column)){$attributes[$column]=$row[$column]}}
            foreach($nested in @('Grants','PublishedGrants','DelegatedScopeDefinitions','AppRoleDefinitions','ProtocolCounts','ClientTypeCounts','EventTypeCounts','ResourceCounts','OutcomeCounts','AuthenticationMethodCounts','CredentialTypeCounts','IncomingTokenTypeCounts')){
                if(-not $attributes.Contains($nested)){continue}
                $fields=switch($nested){
                    {$_ -in @('Grants','PublishedGrants')} {@('ResourceId','Scopes')}
                    DelegatedScopeDefinitions {@('Id','Value','Enabled','ConsentType','AdminConsentDisplayName','AdminConsentDescription','UserConsentDisplayName','UserConsentDescription')}
                    AppRoleDefinitions {@('Id','Value','DisplayName','Description','AllowedMemberTypes','Enabled')}
                    default {@('Value','Count')}
                }
                $attributes[$nested]=@(foreach($entry in $attributes[$nested]){
                    $projected=[ordered]@{}
                    foreach($field in $fields){
                        if($entry -is [Collections.IDictionary] -and $entry.Contains($field)){$projected[$field]=$entry[$field]}
                        elseif($entry.PSObject.Properties[$field]){$projected[$field]=$entry.$field}
                    }
                    $projected
                })
            }
            # Nested metadata records were projected above; remaining values must be simple leaves.
            # Reject credential-bearing objects rather than serializing them under an allowed field name.
            foreach($field in $attributes.Keys){
                $entries=if($field -in @('Grants','PublishedGrants','DelegatedScopeDefinitions','AppRoleDefinitions','ProtocolCounts','ClientTypeCounts','EventTypeCounts','ResourceCounts','OutcomeCounts','AuthenticationMethodCounts','CredentialTypeCounts','IncomingTokenTypeCounts')){
                    @($attributes[$field]|ForEach-Object {$_.Values})
                }else{@($attributes[$field])}
                foreach($value in $entries){
                    foreach($leaf in @($value)){
                        if($null -ne $leaf -and $leaf -isnot [string] -and $leaf -isnot [bool] -and $leaf -isnot [int] -and $leaf -isnot [long] -and $leaf -isnot [double] -and $leaf -isnot [decimal]){throw 'Collected metadata contains an unsupported value type.'}
                    }
                }
            }
            if($Kind -eq 'SignIns'){
                if($attributes.SignInCount -isnot [int] -and $attributes.SignInCount -isnot [long] -or $attributes.SignInCount -lt 0){throw 'Invalid sign-in count.'}
                foreach($field in @('ProtocolCounts','ClientTypeCounts','EventTypeCounts','ResourceCounts','OutcomeCounts','AuthenticationMethodCounts','CredentialTypeCounts','IncomingTokenTypeCounts')){
                    if(-not $attributes.Contains($field)){continue}
                    $allowed=@(Get-TokenForgeSignInSummaryValues $field)
                    $values=@{}
                    foreach($entry in $attributes[$field]){
                        if($entry.Count -isnot [int] -and $entry.Count -isnot [long] -or $entry.Count -lt 0 -or $entry.Count -gt $attributes.SignInCount -or $entry.Value -isnot [string]){throw 'Invalid sign-in summary count.'}
                        if($field -eq 'ResourceCounts'){$resourceGuid=[guid]::Empty;if(-not[guid]::TryParse($entry.Value,[ref]$resourceGuid) -or $resourceGuid -eq [guid]::Empty -or $entry.Value -cne $resourceGuid.ToString()){throw 'Invalid sign-in resource.'}}
                        elseif($entry.Value -cnotin $allowed){throw 'Invalid sign-in summary value.'}
                        if($values.ContainsKey($entry.Value)){throw 'Duplicate sign-in summary value.'};$values[$entry.Value]=$true
                    }
                }
            }
            $sources=@(if($Kind -in @('Discovery','Inventory')){@($row.Sources|ForEach-Object {[ordered]@{Name=$_.Name;Location=if($_.PSObject.Properties['Location'] -or ($_ -is [Collections.IDictionary] -and $_.Contains('Location'))){$_.Location}else{$null};Evidence=$_.Evidence}})}else{@([ordered]@{Name=$Kind;Location=if($Kind -eq 'SignIns'){'https://graph.microsoft.com/beta/auditLogs/signIns'}elseif($Kind -eq 'FlowAttempts'){'LocalFlowEvidence'}else{'LocalScopeDatabase'};Evidence=if($Kind -eq 'SignIns'){'ObservedSignInNotOwnership'}elseif($Kind -eq 'RegistrationAttempts'){'RegistrationAttemptNotConsent'}elseif($Kind -eq 'FlowAttempts'){'DiagnosticFlowAttempt'}else{'DiagnosticScopeObservation'}})})
            if($Kind -eq 'Inventory'){$sources+= [ordered]@{Name='TenantServicePrincipals';Location='https://graph.microsoft.com/v1.0/servicePrincipals';Evidence='TenantMetadataSnapshot'}}
            $hash=Get-TokenForgeFingerprint -Value (ConvertTo-Json -InputObject ([ordered]@{Attributes=$attributes;Sources=$sources}) -Depth 100 -Compress)
            if(-not $catalog.Applications.Contains($appId)){$catalog.Applications[$appId]=@{AppId=$appId;FirstSeenAt=$date.ToString('o');LastSeenAt=$date.ToString('o');Records=@{}}}
            $app=$catalog.Applications[$appId]
            if($date -lt [DateTimeOffset]::Parse($app.FirstSeenAt)){$app.FirstSeenAt=$date.ToString('o')}
            if($date -gt [DateTimeOffset]::Parse($app.LastSeenAt)){$app.LastSeenAt=$date.ToString('o')}
            $previousOrigin=$catalog.Origins[$origin]
            $currentSnapshot= -not $previousOrigin -or $observed -ge [DateTimeOffset]::Parse($previousOrigin.LastObservedAt)
            $old=$app.Records[$origin]
            if(-not $old){$app.Records[$origin]=@{Kind=$Kind;TenantFingerprint=$rowTenant;PrincipalFingerprint=$principal;ResourceId=$resource;FirstSeenAt=$date.ToString('o');LastSeenAt=$date.ToString('o');PresentInLatestRun=$currentSnapshot;CurrentVersionFirstSeenAt=$date.ToString('o');Attributes=$attributes;Sources=$sources;ContentSha256=$hash;PreviousVersions=@()}}
            elseif($date -ge [DateTimeOffset]::Parse($old.LastSeenAt)){
                if($old.ContentSha256 -cne $hash){$old.PreviousVersions+=@{FirstSeenAt=$old.CurrentVersionFirstSeenAt;LastSeenAt=$old.LastSeenAt;Attributes=$old.Attributes;Sources=$old.Sources;ContentSha256=$old.ContentSha256};$old.CurrentVersionFirstSeenAt=$date.ToString('o')}
                $old.Attributes=$attributes;$old.Sources=$sources;$old.ContentSha256=$hash;$old.LastSeenAt=$date.ToString('o');if($currentSnapshot){$old.PresentInLatestRun=$true}
                if($date -lt [DateTimeOffset]::Parse($old.FirstSeenAt)){$old.FirstSeenAt=$date.ToString('o')}
            }
            if($old -and $date -lt [DateTimeOffset]::Parse($old.FirstSeenAt)){$old.FirstSeenAt=$date.ToString('o')}
            $seen["$origin|$appId"]=$true;$affectedOrigins[$origin]=$true;$count++
        }
        # Complete snapshots can mark absence. Scope databases can be partial/batched, so do not mark their unseen pairs absent.
        if($Kind -notin @('ScopeObservations','RegistrationAttempts','FlowAttempts')){
            $origin=@($Kind,$tenant,$null,$null) -join '/';$affectedOrigins[$origin]=$true
            $previous=$catalog.Origins[$origin]
            if(-not $previous -or $observed -ge [DateTimeOffset]::Parse($previous.LastObservedAt)){
                foreach($app in $catalog.Applications.Values){if($app.Records.Contains($origin) -and -not $seen.ContainsKey("$origin|$($app.AppId)")){$app.Records[$origin].PresentInLatestRun=$false}}
            }
        }
        foreach($origin in $affectedOrigins.Keys){
            $previous=$catalog.Origins[$origin]
            if(-not $previous -or $observed -ge [DateTimeOffset]::Parse($previous.LastObservedAt)){$catalog.Origins[$origin]=@{Kind=$Kind;LastObservedAt=$observed.ToString('o');LastRunId=$runId}}
        }
        $run=@{Id=$runId;Kind=$Kind;ObservedAt=$observed.ToString('o');RecordedAt=$now;ApplicationRecordCount=$count;IgnoredEmptyAppIdCount=$emptyIds;TenantFingerprint=$tenant}
        if($Kind -eq 'Discovery'){$run.SourceSnapshots=@($Document.SourceSnapshots|ForEach-Object {[ordered]@{Location=$_.Location;Sha256=$_.Sha256;HashKind=$_.HashKind}})}
        if($Kind -eq 'SignIns'){$run.Window=@{Since=$Document.Since;Until=$Document.Until;EventTypes=@($Document.EventTypes)}}
        $catalog.Runs+= $run;$catalog.UpdatedAt=$now
        if([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject $catalog -Depth 100)) -gt 134217728){throw 'Application metadata exceeds the 128 MiB limit; archive history before retrying.'}
        Save-TokenForgeDocument -Document $catalog -Path $full
        [pscustomobject]@{Updated=$true;ApplicationCount=$catalog.Applications.Count;RunCount=$catalog.Runs.Count;Kind=$Kind}
    }finally{if($lock){$lock.Dispose()}}
}
