#Requires -Version 7.6
Describe 'Attended Graph directory audit provisioning collector' {
    BeforeAll {
        $collector = Join-Path $PSScriptRoot '../scripts/Get-TokenForgeGraphDirectoryProvisioningGaps.ps1'
        $catalog = Join-Path $TestDrive catalog
        $null = New-Item -ItemType Directory $catalog
        $verified = '11111111-1111-4111-8111-111111111111'
        $nonverified = '22222222-2222-4222-8222-222222222222'
        $candidate = '33333333-3333-4333-8333-333333333333'
        $object = '44444444-4444-4444-8444-444444444444'
        $tenant = [guid]'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        $account = 'reader@example.invalid'
        Set-Content (Join-Path $catalog applications.json) ('{"Format":"TokenForgeApplicationMetadata","SchemaVersion":2,"Applications":{"'+$verified+'":{}}}')
        Set-Content (Join-Path $catalog applications.non-verified.json) ('{"Format":"TokenForgeNonVerifiedApplications","SchemaVersion":1,"Applications":{"'+$nonverified+'":{}}}')
        & git -C $catalog init -q
        & git -C $catalog add -- .
        & git -C $catalog -c user.name=Test -c user.email=test@example.invalid commit -qm 'Synthetic catalog'
        $commit = (& git -C $catalog rev-parse HEAD)
        if ($LASTEXITCODE) { throw 'Synthetic catalog fixture failed.' }
        $script:catalogFiles = Get-ChildItem $catalog -Filter '*.json' | Get-FileHash
        $start = [DateTimeOffset]'2026-01-05T23:00:00Z'
        $end = [DateTimeOffset]'2026-01-06T01:00:00Z'
        $link = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=private-continuation'
        $fake = New-Module -Name Microsoft.Graph.Authentication -ScriptBlock {
            function Get-MgContext { [CmdletBinding()]param() $global:TokenForgeDirectoryMock.Context }
            function Get-MgEnvironment {
                [CmdletBinding()]param([string]$Name)
                [pscustomobject]@{Name='Global';Type='Built-in';GraphEndpoint='https://graph.microsoft.com';AzureADEndpoint='https://login.microsoftonline.com'}
            }
            function Invoke-MgGraphRequest {
                [CmdletBinding()]param($Method,$Uri,$OutputType,[switch]$SkipHttpErrorCheck,
                    [string]$StatusCodeVariable,$OutputFilePath,[switch]$InferOutputFileName,$Headers,$GraphRequestSession)
                $state = $global:TokenForgeDirectoryMock
                $state.Calls.Add([string]$Uri)
                if ($Method -ne 'GET' -or -not $SkipHttpErrorCheck -or $OutputType -ne 'HttpResponseMessage' -or
                    $OutputFilePath -or $InferOutputFileName -or $Headers -or $GraphRequestSession) {
                    $state.Unsafe = $true
                    throw 'Unexpected mock request.'
                }
                if (-not $state.Queue.Count) { throw 'synthetic-private-transport' }
                $item = $state.Queue.Dequeue()
                $PSCmdlet.SessionState.PSVariable.Set($StatusCodeVariable,[int]$item.Code)
                if ($item.Plain) { return 'synthetic-private-throttle' }
                $response = [Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$item.Code)
                $effective = if ($item.Effective) { $item.Effective } else { 'https://graph.microsoft.com' + $Uri }
                $response.RequestMessage = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,[uri]$effective)
                $content = if ($item.Raw) { $item.Raw } else { ConvertTo-Json -InputObject $item.Body -Depth 12 -Compress }
                $response.Content = [Net.Http.StringContent]::new($content)
                $response
            }
            Export-ModuleMember -Function Get-MgContext,Get-MgEnvironment,Invoke-MgGraphRequest
        }
        $fake | Import-Module
        function Add-Page($Body,[int]$Code=200,[string]$Effective='', [string]$Raw='', [switch]$Plain) {
            $global:TokenForgeDirectoryMock.Queue.Enqueue(@{ Body=$Body;Code=$Code;Effective=$Effective;Raw=$Raw;Plain=[bool]$Plain })
        }
        function New-Event($Id=$candidate,$Stamp='2026-01-05T23:20:00Z') {
            @{ activityDisplayName='Add service principal';activityDateTime=$Stamp;result='success';
                id='synthetic-private-row';initiatedBy=@{user=@{userPrincipalName='synthetic-private-account'};app=@{appId=$object}};
                targetResources=@(@{type='ServicePrincipal';id=$object;displayName='synthetic-private-target'});
                additionalDetails=@(@{key='AppId';value=$Id},@{key='AppOwnerOrganizationId';value=$tenant.ToString()}) }
        }
        function Get-Run([DateTimeOffset]$Stop=$end,[string]$Pin=$commit) {
            $argsForRun = @{TenantId=$tenant;Account=$account;CatalogRepository=$catalog;CatalogCommit=$Pin;Since=$start;Until=$Stop}
            $raw = & $collector @argsForRun
            $raw | Should -Not -Match 'synthetic-private|private-continuation|reader@example\.invalid|aaaaaaaa-aaaa-4aaa|44444444-4444-4444'
            $raw | ConvertFrom-Json -AsHashtable -DateKind String
        }
    }
    BeforeEach {
        $global:TokenForgeDirectoryMock = @{
            Context=[pscustomobject]@{TenantId=$tenant.ToString();Account=$account;AuthType='Delegated';
                ContextScope='Process';Environment='Global';Scopes=@('AuditLog.Read.All')}
            Calls=[Collections.Generic.List[string]]::new()
            Queue=[Collections.Generic.Queue[object]]::new()
            Unsafe=$false
        }
    }
    AfterAll {
        Remove-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        Remove-Variable TokenForgeDirectoryMock -Scope Global -ErrorAction SilentlyContinue
    }
    It 'distinguishes an empty terminal window from an empty continuation' {
        Add-Page @{value=@();'@odata.nextLink'=$link}
        Add-Page @{value=@()}
        Add-Page @{value=@()}
        $r = Get-Run
        $r.RequestedWindowTraversalComplete | Should -BeTrue
        $r.ProviderRetention | Should -Be 'Unknown'
        $r.CandidateAppIds.Count | Should -Be 0
        $r.Windows.Count | Should -Be 2
        $r.Windows[0].Pages | Should -Be 2
        $r.Windows[0].UntilExclusive | Should -Be $r.Windows[1].Since
        $global:TokenForgeDirectoryMock.Calls[1] | Should -Be '/v1.0/auditLogs/directoryAudits?$skiptoken=private-continuation'
        [uri]::UnescapeDataString($global:TokenForgeDirectoryMock.Calls[0]) | Should -Match "activityDisplayName eq 'Add service principal'.+activityDateTime ge .+activityDateTime le"
    }
    It 'deduplicates candidates across windows and filters both exact catalog partitions' {
        $boundary = New-Event $candidate '2026-01-06T00:00:00Z'
        Add-Page @{value=@((New-Event $verified),(New-Event $nonverified),(New-Event),$boundary)}
        Add-Page @{value=@($boundary)}
        $r = Get-Run
        $r.RequestedWindowTraversalComplete | Should -BeTrue
        $r.CandidateAppIds.Count | Should -Be 1
        $r.CandidateAppIds[0] | Should -Be $candidate
        $r.Windows[0].SuccessfulTargetAppIdRows | Should -Be 3
        $r.Windows[1].SuccessfulTargetAppIdRows | Should -Be 1
        Compare-Object $script:catalogFiles (Get-ChildItem $catalog -Filter '*.json' | Get-FileHash) -Property Path,Hash | Should -BeNullOrEmpty
    }
    It 'leaves malformed targets and ambiguous fields unresolved' {
        $one = New-Event; $one.targetResources += @{type='Application';id=$candidate}
        $two = New-Event; $two.targetResources[0].Remove('id')
        $three = New-Event; $three.additionalDetails += @{key='appid';value=$candidate}
        $four = New-Event; $four.additionalDetails[0].key='appid'
        $five = New-Event; $five.additionalDetails[0].value=@($candidate)
        $six = New-Event; $six.targetResources[0].type=@('ServicePrincipal')
        $seven = New-Event; $seven.result=@('success')
        Add-Page @{value=@($one,$two,$three,$four,$five,$six,$seven)}
        $r = Get-Run ([DateTimeOffset]'2026-01-05T23:59:59Z')
        $r.CandidateAppIds.Count | Should -Be 0
        $r.Windows[0].UnresolvedSuccessfulRows | Should -Be 6
        $r.Windows[0].OtherResultRows | Should -Be 1
    }
    It 'rejects untrusted links and withholds candidates from incomplete windows' {
        Add-Page @{value=@((New-Event));'@odata.nextLink'='https://other.invalid/v1.0/auditLogs/directoryAudits?x=1'}
        $r = Get-Run
        $r.RequestedWindowTraversalComplete | Should -BeFalse
        $r.Windows[0].Status | Should -Be 'InvalidNextLink'
        $r.Windows[1].Status | Should -Be 'NotAttempted'
        $r.CandidateAppIds.Count | Should -Be 0
        $global:TokenForgeDirectoryMock.Calls.Count | Should -Be 1
    }
    It 'rechecks delegated scope and disables inherited request defaults' {
        $global:TokenForgeDirectoryMock.Context.Scopes = @('User.Read')
        (Get-Run).Windows[0].Status | Should -Be 'ContextRejected'
        $global:TokenForgeDirectoryMock.Calls.Count | Should -Be 0
        $global:TokenForgeDirectoryMock.Context.Scopes = @('AuditLog.Read.All')
        $PSDefaultParameterValues = @{'Invoke-MgGraphRequest:OutputFilePath'='synthetic-private-forbidden'}
        Add-Page @{value=@()}
        (Get-Run ([DateTimeOffset]'2026-01-05T23:59:59Z')).RequestedWindowTraversalComplete | Should -BeTrue
        $global:TokenForgeDirectoryMock.Unsafe | Should -BeFalse
    }
    It 'records safe HTTP failure and rejects a changed effective URI' {
        Add-Page @{} -Code 429 -Plain
        $r = Get-Run
        $r.Windows[0].Status | Should -Be 'HttpFailure'
        $r.Windows[0].HttpStatus | Should -Be 429
        Add-Page @{value=@((New-Event))} -Effective 'https://other.invalid/v1.0/auditLogs/directoryAudits?private-continuation=1'
        $r = Get-Run
        $r.Windows[0].Status | Should -Be 'UnexpectedResponseUri'
        $r.CandidateAppIds.Count | Should -Be 0
    }
    It 'rejects duplicate JSON keys and non-commit catalog pins' {
        Add-Page @{} -Raw '{"value":[],"value":[]}'
        (Get-Run).Windows[0].Status | Should -Be 'InvalidPage'
        $tree = git -C $catalog rev-parse 'HEAD^{tree}'
        { Get-Run -Pin $tree } | Should -Throw '*must be a Git commit*'
        $global:TokenForgeDirectoryMock.Calls.Count | Should -Be 1
    }
}
