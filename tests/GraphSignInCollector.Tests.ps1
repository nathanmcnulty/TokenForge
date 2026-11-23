#Requires -Version 7.6
Describe 'Attended Graph beta sign-in collection' {
    BeforeAll {
        $collector = Join-Path $PSScriptRoot '../scripts/Get-TokenForgeGraphSignInGaps.ps1'
        $catalog = Join-Path $TestDrive catalog
        $null = New-Item -ItemType Directory $catalog
        Set-Content (Join-Path $catalog applications.json) '{"Format":"TokenForgeApplicationMetadata","SchemaVersion":2,"Applications":{"11111111-1111-4111-8111-111111111111":{}}}'
        Set-Content (Join-Path $catalog applications.non-verified.json) '{"Format":"TokenForgeNonVerifiedApplications","SchemaVersion":1,"Applications":{"22222222-2222-4222-8222-222222222222":{}}}'
        & git -C $catalog init -q
        & git -C $catalog add -- .
        & git -C $catalog -c user.name=Test -c user.email=test@example.invalid commit -qm 'Synthetic catalog'
        $commit = (& git -C $catalog rev-parse HEAD)
        if ($LASTEXITCODE) { throw 'Synthetic catalog fixture failed.' }

        $fake = New-Module -Name Microsoft.Graph.Authentication -ScriptBlock {
            function Get-MgContext { [CmdletBinding()]param() $global:TokenForgeSignInMock.Context }
            function Get-MgEnvironment {
                [CmdletBinding()]param([string]$Name)
                [pscustomobject]@{Name='Global';Type='Built-in';GraphEndpoint='https://graph.microsoft.com';AzureADEndpoint='https://login.microsoftonline.com'}
            }
            function Invoke-MgGraphRequest {
                [CmdletBinding()]param($Method,$Uri,$OutputType,[switch]$SkipHttpErrorCheck,
                    $OutputFilePath,[switch]$InferOutputFileName,$Headers,$GraphRequestSession)
                $state = $global:TokenForgeSignInMock
                $state.Calls.Add([string]$Uri)
                if ($Method -ne 'GET' -or -not $SkipHttpErrorCheck -or $OutputType -ne 'HttpResponseMessage' -or
                    $OutputFilePath -or $InferOutputFileName -or $Headers -or $GraphRequestSession) {
                    $state.Unsafe = $true
                    throw 'Unexpected mock request.'
                }
                if (-not $state.Queue.Count) { throw 'synthetic-private-transport' }
                $item = $state.Queue.Dequeue()
                if ($item.Code -eq 0) { throw [OperationCanceledException]::new('synthetic-private-timeout') }
                $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$item.Code)
                $effective = if ($item.Effective) { $item.Effective } else { 'https://graph.microsoft.com' + $Uri }
                $response.RequestMessage = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,[uri]$effective)
                $response.Content = [Net.Http.StringContent]::new((ConvertTo-Json -InputObject $item.Body -Depth 10 -Compress))
                if ($item.ContainsKey('Delay')) {
                    $response.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds($item.Delay))
                }
                $response
            }
            Export-ModuleMember -Function Get-MgContext,Get-MgEnvironment,Invoke-MgGraphRequest
        }
        $fake | Import-Module
        $tenant = [guid]'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        $actor = 'reader@example.invalid'
        $novel = '33333333-3333-4333-8333-333333333333'
        $resource = '44444444-4444-4444-8444-444444444444'
        $standard = @{ TenantId=$tenant;Account=$actor;CatalogRepository=$catalog;CatalogCommit=$commit;
            Since=[DateTimeOffset]'2026-01-05T23:00:00Z';Until=[DateTimeOffset]'2026-01-06T01:00:00Z' }
        function Add-Page($Body,[int]$Code=200,[int]$Delay=-1,[string]$Effective='') {
            $item = @{ Code=$Code; Body=$Body; Effective=$Effective }
            if ($Delay -ge 0) { $item.Delay=$Delay }
            $global:TokenForgeSignInMock.Queue.Enqueue($item)
        }
        function New-Row($Id,$Type,$Stamp,$App=$novel) {
            @{ id=$Id; signInEventTypes=@($Type); createdDateTime=$Stamp; appId=$App; resourceId=$resource;
               userPrincipalName='synthetic-private-user'; ipAddress='synthetic-private-ip'; status=@{errorCode=0} }
        }
        function Get-Run([hashtable]$Options) {
            $arguments = $standard.Clone()
            foreach ($item in $Options.GetEnumerator()) { $arguments[$item.Key]=$item.Value }
            $raw = & $collector @arguments -CheckpointDirectory $checkpoint
            $raw | Should -Not -Match 'synthetic-private|reader@example\.invalid|aaaaaaaa-aaaa-4aaa'
            $raw | ConvertFrom-Json -AsHashtable -DateKind String
        }
    }
    BeforeEach {
        $checkpoint = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory $checkpoint
        if (-not $IsWindows) { [IO.File]::SetUnixFileMode($checkpoint,[IO.UnixFileMode]'UserRead,UserWrite,UserExecute') }
        $global:TokenForgeSignInMock = @{
            Context=[pscustomobject]@{TenantId=$tenant.ToString();Account=$actor;AuthType='Delegated';
                ContextScope='Process';Environment='Global';Scopes=@('AuditLog.Read.All')}
            Calls=[Collections.Generic.List[string]]::new()
            Queue=[Collections.Generic.Queue[object]]::new()
            Unsafe=$false
        }
    }
    AfterAll {
        Remove-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        Remove-Variable TokenForgeSignInMock -Scope Global -ErrorAction SilentlyContinue
    }

    It 'collects both beta categories in adjacent UTC slices and follows an empty nonterminal page' {
        $link = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=empty%2Bcontinuation'
        Add-Page @{value=@();'@odata.nextLink'=$link}
        $event = New-Row 'synthetic-private-event' interactiveUser '2026-01-05T23:20:00Z'
        $boundary = New-Row 'synthetic-private-boundary' interactiveUser '2026-01-06T00:00:00Z'
        Add-Page @{value=@($event,$event,$boundary)}
        Add-Page @{value=@($boundary,(New-Row 'synthetic-private-verified' interactiveUser '2026-01-06T00:30:00Z' '11111111-1111-4111-8111-111111111111'),
            (New-Row 'synthetic-private-nonverified' interactiveUser '2026-01-06T00:45:00Z' '22222222-2222-4222-8222-222222222222'))}
        Add-Page @{value=@((New-Row 'synthetic-private-quiet' nonInteractiveUser '2026-01-05T23:30:00Z'))}
        Add-Page @{value=@()}
        $run = Get-Run @{}
        $run.CollectionComplete | Should -BeTrue
        $run.TenantHistoryComplete | Should -BeFalse
        $run.SignInOutcome | Should -Be 'NotInferred'
        $run.ActualAudience | Should -Be 'UnknownFromSignInLogs'
        $run.Windows.Count | Should -Be 4
        $run.Windows[0].Pages | Should -Be 2
        $run.Windows[0].UntilExclusive | Should -Be $run.Windows[1].Since
        $global:TokenForgeSignInMock.Calls[1] | Should -Be '/beta/auditLogs/signIns?$skiptoken=empty%2Bcontinuation'
        [uri]::UnescapeDataString($global:TokenForgeSignInMock.Calls[0]) | Should -Match "signInEventTypes/any\(t: t eq 'interactiveUser'\)"
        [uri]::UnescapeDataString($global:TokenForgeSignInMock.Calls[3]) | Should -Match "signInEventTypes/any\(t: t eq 'nonInteractiveUser'\)"
        $global:TokenForgeSignInMock.Calls[0] | Should -Not -Match 'appOwnerTenantId'
        $stored = Get-Content (Join-Path $checkpoint $run.Windows[0].Receipt) -Raw
        $stored | Should -Not -Match 'synthetic-private|reader@example\.invalid|skiptoken'
        $agg = ($stored | ConvertFrom-Json -AsHashtable -DateKind String).Aggregate
        $agg.Windows[0].DuplicateEvents | Should -Be 1
        $agg.Windows[0].BoundaryEventsSkipped | Should -Be 1
        @($agg.Candidates | Where-Object IdentifierKind -eq 'AppId').Count | Should -Be 1
        $agg.Candidates.Identifier | Should -Contain $novel
        $last = (Get-Content (Join-Path $checkpoint $run.Windows[3].Receipt) -Raw | ConvertFrom-Json -AsHashtable -DateKind String).Aggregate
        $last.Windows[0].UniqueEvents | Should -Be 0
    }

    It 'retries the same address for a bounded Retry-After and does not inherit caller defaults' {
        $PSDefaultParameterValues=@{'Invoke-MgGraphRequest:OutputFilePath'=(Join-Path $TestDrive raw.json);
            'Invoke-MgGraphRequest:InferOutputFileName'=$true;'Invoke-MgGraphRequest:Headers'=@{Unsafe='canary'};
            'Invoke-MgGraphRequest:GraphRequestSession'='unsafe'}
        Add-Page @{} 429 0
        Add-Page @{value=@()}
        $run = Get-Run @{EventType=@('interactiveUser');Until=[DateTimeOffset]'2026-01-06T00:00:00Z'}
        $run.CollectionComplete | Should -BeTrue
        $run.Windows[0].Requests | Should -Be 2
        $global:TokenForgeSignInMock.Calls[0] | Should -Be $global:TokenForgeSignInMock.Calls[1]
        $global:TokenForgeSignInMock.Unsafe | Should -BeFalse
        Test-Path (Join-Path $TestDrive raw.json) | Should -BeFalse
    }

    It 'restarts an interrupted window from its initial request and retains completed windows' {
        Add-Page @{value=@()}
        Add-Page @{value=@();'@odata.nextLink'='https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=second'}
        Add-Page @{} 0
        $option=@{EventType=@('nonInteractiveUser');WindowHours=1}
        $before=Get-Run $option
        $before.Windows.Status | Should -Be @('Complete','TransportTimeout')
        $before.CollectionComplete | Should -BeFalse
        @(Get-ChildItem $checkpoint -Filter '*.json').Count | Should -Be 1
        $expected=$global:TokenForgeSignInMock.Calls[1]
        $global:TokenForgeSignInMock.Calls.Clear()
        Add-Page @{value=@()}
        $after=Get-Run $option
        $after.Windows.Status | Should -Be @('Resumed','Complete')
        $after.CollectionComplete | Should -BeTrue
        $global:TokenForgeSignInMock.Calls.ToArray() | Should -Be @($expected)
    }

    It 'rejects off-origin, non-beta, malformed and cyclic continuations' {
        foreach ($test in @(
            @{Link='https://example.invalid/beta/auditLogs/signIns?$skiptoken=1';Status='InvalidNextLink';Calls=1},
            @{Link='https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=1';Status='InvalidNextLink';Calls=1},
            @{Link='https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=1#frag';Status='InvalidNextLink';Calls=1},
            @{Link=$null;Status='InvalidNextLink';Calls=1},
            @{Link='https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=1';Status='PaginationLoop';Calls=2}
        )) {
            $global:TokenForgeSignInMock.Calls.Clear()
            Add-Page @{value=@();'@odata.nextLink'=$test.Link}
            if ($test.Calls -eq 2) { Add-Page @{value=@();'@odata.nextLink'=$test.Link} }
            $run=Get-Run @{EventType=@('interactiveUser');Until=[DateTimeOffset]'2026-01-06T00:00:00Z'}
            $run.Windows[0].Status | Should -Be $test.Status
            $global:TokenForgeSignInMock.Calls.Count | Should -Be $test.Calls
        }
        @(Get-ChildItem $checkpoint -Filter '*.json').Count | Should -Be 0
    }

    It 'distinguishes throttling, consent failures, wrong event shape and an observed redirected response' {
        $option=@{EventType=@('interactiveUser');Until=[DateTimeOffset]'2026-01-06T00:00:00Z';MaxRetryDelaySeconds=0}
        Add-Page @{} 429 60
        $deferred=Get-Run $option
        $deferred.Windows[0].Status | Should -Be 'RetryDeferred'
        $deferred.Windows[0].RetryAfterSeconds | Should -Be 60
        Add-Page @{error='synthetic-private-denial'} 403
        (Get-Run $option).Windows[0].Status | Should -Be 'AccessDenied'
        Add-Page @{value=@((New-Row 'synthetic-private-wrong' nonInteractiveUser '2026-01-05T23:30:00Z'))}
        (Get-Run $option).Windows[0].Status | Should -Be 'UnexpectedEventType'
        Add-Page @{value=@()} 200 -1 'https://example.invalid/beta/auditLogs/signIns?continuation=synthetic'
        (Get-Run $option).Windows[0].Status | Should -Be 'UnexpectedResponseOrigin'
    }

    It 'rejects wrong account, tenant and missing scope before making any request' {
        $option=@{EventType=@('interactiveUser')}
        $global:TokenForgeSignInMock.Context.Account='other@example.invalid'
        { Get-Run $option } | Should -Throw '*existing delegated*'
        $global:TokenForgeSignInMock.Context.Account=$actor
        $global:TokenForgeSignInMock.Context.TenantId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        { Get-Run $option } | Should -Throw '*existing delegated*'
        $global:TokenForgeSignInMock.Context.TenantId=$tenant.ToString()
        $global:TokenForgeSignInMock.Context.Scopes=@('User.Read')
        { Get-Run $option } | Should -Throw '*existing delegated*'
        $global:TokenForgeSignInMock.Calls.Count | Should -Be 0
    }

    It 'leaves exhausted page limits unfinished and rejects malformed saved windows' {
        $option=@{EventType=@('interactiveUser');Until=[DateTimeOffset]'2026-01-06T00:00:00Z';MaxPagesPerWindow=1}
        Add-Page @{value=@();'@odata.nextLink'='https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=next'}
        (Get-Run $option).Windows[0].Status | Should -Be 'PageLimit'
        @(Get-ChildItem $checkpoint -Filter '*.json').Count | Should -Be 0
        Add-Page @{value=@()}
        $run=Get-Run $option
        $file=Join-Path $checkpoint $run.Windows[0].Receipt
        $data=Get-Content $file -Raw | ConvertFrom-Json -AsHashtable -DateKind String
        $data.Aggregate.Remove('Windows')
        Set-Content $file (ConvertTo-Json -InputObject $data -Depth 16)
        $global:TokenForgeSignInMock.Calls.Clear()
        (Get-Run $option).Windows[0].Status | Should -Be 'InvalidCheckpoint'
        $global:TokenForgeSignInMock.Calls.Count | Should -Be 0
    }

    It 'accepts more than one thousand projected rows without widening the offline default' {
        $rows = for ($i=0;$i -lt 501;$i++) { New-Row "synthetic-private-${i}" interactiveUser '2026-01-05T23:20:00Z' }
        $other = for ($i=501;$i -lt 1002;$i++) { New-Row "synthetic-private-${i}" interactiveUser '2026-01-05T23:21:00Z' }
        Add-Page @{value=@($rows);'@odata.nextLink'='https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=second'}
        Add-Page @{value=@($other)}
        $run=Get-Run @{EventType=@('interactiveUser');Until=[DateTimeOffset]'2026-01-06T00:00:00Z'}
        $run.CollectionComplete | Should -BeTrue
        $file=Join-Path $checkpoint $run.Windows[0].Receipt
        ((Get-Content $file -Raw | ConvertFrom-Json -AsHashtable).Aggregate.Windows[0].UniqueEvents) | Should -Be 1002
    }
}
