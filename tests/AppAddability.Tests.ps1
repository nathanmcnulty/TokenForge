BeforeAll {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    . "$PSScriptRoot/../scripts/TokenForgeAppAddability.ps1"
    $script:Tenant=[guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    $script:App=[guid]'11111111-1111-1111-1111-111111111111'
    $script:Owner=[guid]'22222222-2222-2222-2222-222222222222'
    $script:Object=[guid]'33333333-3333-3333-3333-333333333333'
    $script:Account='operator@example.test'

    function New-AppAddabilityObservation {
        param([int]$Status,[string]$Code='',[string]$Message='',$Body=$null,[string]$RetryAfter='',[string]$Transport='')
        [pscustomobject]@{StatusCode=$Status;ErrorCode=$Code;ErrorMessage=$Message;Body=$Body;RetryAfter=$RetryAfter;TransportOutcome=$Transport}
    }
    function New-AppAddabilityPrincipal {
        param([string]$AppId=$script:App.ToString(),[string]$Type='Application',[string]$OwnerId=$script:Owner.ToString(),[string]$Id=$script:Object.ToString())
        [pscustomobject]@{appId=$AppId;servicePrincipalType=$Type;appOwnerOrganizationId=$OwnerId;id=$Id;displayName='Fixture app'}
    }
    function New-AppAddabilityRequest {
        param([Collections.Queue]$Responses,[Collections.Generic.List[string]]$Calls)
        return {
            param($Method,$AppId)
            $Calls.Add([string]$Method)
            $next=$Responses.Dequeue()
            if ($next -is [scriptblock]) { return & $next }
            return $next
        }.GetNewClosure()
    }
}

Describe 'App addability result handling' {
    It 'accepts an external non-Microsoft owner after exact verification' {
        $nonMicrosoftOwner='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $outcome=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId $nonMicrosoftOwner))
        $outcome.Bucket | Should -Be 'Confirmed'
        $outcome.Result | Should -Be 'AlreadyPresent'
    }

    It 'keeps owner-in-tenant, wrong-type, and mismatched-AppId principals pending' {
        $inside=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId $script:Tenant.ToString()))
        $wrongType=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -Type 'ManagedIdentity'))
        $wrongApp=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -AppId '44444444-4444-4444-4444-444444444444'))
        $inside.Bucket | Should -Be 'Pending'
        $wrongType.Bucket | Should -Be 'Pending'
        $wrongApp.Bucket | Should -Be 'Pending'
    }

    It 'creates only after an exact not-found and verifies with a second exact lookup' {
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue((New-AppAddabilityObservation 201 '' '' ([pscustomobject]@{id=$script:Object.ToString();appId=$script:App.ToString()})))
        $responses.Enqueue((New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')))
        $calls=[Collections.Generic.List[string]]::new()
        $request=New-AppAddabilityRequest $responses $calls
        $beforePost={ param($item,$attempt) }.GetNewClosure()
        $item=[pscustomobject]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'}}
        $outcome=Invoke-AppAddabilityItem $item $script:Tenant $request $beforePost
        $outcome.Bucket | Should -Be 'Confirmed'
        $outcome.Result | Should -Be 'NewlyAdded'
        ($calls -join ',') | Should -Be 'GET,POST,GET'
    }

    It 'reconciles a timed-out POST before the single safe retry' {
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue({ throw [TimeoutException]::new('synthetic timeout') })
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue((New-AppAddabilityObservation 201 '' '' ([pscustomobject]@{id=$script:Object.ToString();appId=$script:App.ToString()})))
        $responses.Enqueue((New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')))
        $calls=[Collections.Generic.List[string]]::new()
        $request=New-AppAddabilityRequest $responses $calls
        $beforePost={ param($item,$attempt) }.GetNewClosure()
        $item=[pscustomobject]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'}}
        $outcome=Invoke-AppAddabilityItem $item $script:Tenant $request $beforePost
        $outcome.Bucket | Should -Be 'Confirmed'
        $outcome.Result | Should -Be 'NewlyAdded'
        ($calls -join ',') | Should -Be 'GET,POST,GET,POST,GET'
    }

    It 'keeps throttling pending and records Retry-After without another POST' {
        $now=[DateTimeOffset]'2026-11-21T12:00:00Z'
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue((New-AppAddabilityObservation 429 'TooManyRequests' 'throttled' $null '30'))
        $calls=[Collections.Generic.List[string]]::new()
        $request=New-AppAddabilityRequest $responses $calls
        $beforePost={ param($item,$attempt) }.GetNewClosure()
        $item=[pscustomobject]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'}}
        $outcome=Invoke-AppAddabilityItem $item $script:Tenant $request $beforePost -Now $now
        $outcome.Bucket | Should -Be 'Pending'
        $outcome.Stop | Should -BeTrue
        [DateTimeOffset]::Parse($outcome.RetryAfterUtc) | Should -Be $now.AddSeconds(30)
        ($calls -join ',') | Should -Be 'GET,POST'
    }

    It 'stops after a throttled post-write verification lookup and preserves the retry delay' {
        $now=[DateTimeOffset]'2026-11-21T12:00:00Z'
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue((New-AppAddabilityObservation 201 '' '' ([pscustomobject]@{id=$script:Object.ToString();appId=$script:App.ToString()})))
        $responses.Enqueue((New-AppAddabilityObservation 429 'TooManyRequests' 'throttled' $null '45'))
        $calls=[Collections.Generic.List[string]]::new()
        $request=New-AppAddabilityRequest $responses $calls
        $beforePost={ param($item,$attempt) }.GetNewClosure()
        $item=[pscustomobject]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'}}
        $outcome=Invoke-AppAddabilityItem $item $script:Tenant $request $beforePost -Now $now
        $outcome.Bucket | Should -Be 'Pending'
        $outcome.Stop | Should -BeTrue
        [DateTimeOffset]::Parse($outcome.RetryAfterUtc) | Should -Be $now.AddSeconds(45)
        $outcome.CreatedServicePrincipal.Verification | Should -Be 'Pending'
        ($calls -join ',') | Should -Be 'GET,POST,GET'
    }

    It 'keeps non-specific bad requests pending' {
        $create=New-AppAddabilityObservation 400 'Request_BadRequest' 'The request body was invalid.'
        $outcome=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 404 'Request_ResourceNotFound') $create (New-AppAddabilityObservation 404 'Request_ResourceNotFound')
        $outcome.Bucket | Should -Be 'Pending'
    }

    It 'classifies only a clear app-specific single-tenant refusal' {
        $explicit=New-AppAddabilityObservation 400 'Request_BadRequest' "The application $($script:App) is single-tenant and cannot be added to another tenant."
        $generic=New-AppAddabilityObservation 400 'Request_BadRequest' 'The application request was invalid.'
        $explicitResult=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 404 'Request_ResourceNotFound') $explicit (New-AppAddabilityObservation 404 'Request_ResourceNotFound')
        $genericResult=Resolve-AppAddabilityOutcome $script:App.ToString() $script:Tenant (New-AppAddabilityObservation 404 'Request_ResourceNotFound') $generic (New-AppAddabilityObservation 404 'Request_ResourceNotFound')
        $explicitResult.Bucket | Should -Be 'CouldntAdd'
        $explicitResult.GraphErrorCode | Should -Be 'Request_BadRequest'
        $genericResult.Bucket | Should -Be 'Pending'
        $genericResult.Result | Should -Be 'Pending'
    }
}

Describe 'App addability context, transport, and restart safety' {
    BeforeEach {
        $script:mockContext=[pscustomobject]@{TenantId=$script:Tenant.ToString();Account=$script:Account;Scopes=@('Application.ReadWrite.All')}
        Mock Get-MgContext { $script:mockContext }
        Mock Get-MgRequestContext { [pscustomobject]@{MaxRetry=0} }
        Mock Set-MgRequestContext {}
    }

    It 'rejects account, tenant, or permission mismatch before any request' {
        $good=[pscustomobject]@{TenantId=$script:Tenant.ToString();Account=$script:Account;Scopes=@('Application.ReadWrite.All')}
        (Test-AppAddabilityContext $good $script:Tenant $script:Account).Ok | Should -BeTrue
        (Test-AppAddabilityContext $good ([guid]::NewGuid()) $script:Account).Reason | Should -Be 'TenantMismatch'
        (Test-AppAddabilityContext ([pscustomobject]@{TenantId=$script:Tenant.ToString();Account='other@example.test';Scopes=@('Application.ReadWrite.All')}) $script:Tenant $script:Account).Reason | Should -Be 'AccountMismatch'
        (Test-AppAddabilityContext ([pscustomobject]@{TenantId=$script:Tenant.ToString();Account=$script:Account;Scopes=@('User.Read')}) $script:Tenant $script:Account).Reason | Should -Be 'RequiredPermissionUnavailable'
    }

    It 'limits the Graph wrapper to GET and POST and configures zero SDK retries' {
        $script:graphMethods=[Collections.Generic.List[string]]::new()
        Mock Invoke-MgGraphRequest {
            $script:graphMethods.Add([string]$Method)
            [pscustomobject]@{appId=$script:App.ToString()}
        }
        Invoke-AppAddabilityGraphRequest -Method GET -AppId $script:App.ToString() -TenantId $script:Tenant -ExpectedAccount $script:Account | Out-Null
        Invoke-AppAddabilityGraphRequest -Method POST -AppId $script:App.ToString() -TenantId $script:Tenant -ExpectedAccount $script:Account | Out-Null
        { Invoke-AppAddabilityGraphRequest -Method DELETE -AppId $script:App.ToString() -TenantId $script:Tenant -ExpectedAccount $script:Account } | Should -Throw
        ($script:graphMethods -join ',') | Should -Be 'GET,POST'
        Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
        Should -Invoke Set-MgRequestContext -Times 0
    }

    It 'reconciles a saved POST intent before repeating after restart' {
        $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
        $item=[ordered]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'};RetryAfterUtc=$null}
        $state=[ordered]@{Format='TokenForgeAppAddabilityCheckpoint';SchemaVersion=1;Status='Pending';TenantId=$script:Tenant.ToString();ExpectedAccount=$script:Account;SnapshotSha256=('a'*64);CreatedAtUtc='2026-11-21T00:00:00Z';UpdatedAtUtc=$null;Queue=@($item);InFlight=[ordered]@{AppId=$script:App.ToString();Phase='PostIntent';Attempt=1};Results=[ordered]@{Confirmed=@();CouldntAdd=@();Pending=@()};CreatedServicePrincipals=@()}
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')))
        $calls=[Collections.Generic.List[string]]::new();$request=New-AppAddabilityRequest $responses $calls
        $result=Invoke-AppAddabilityCatalog -State $state -CheckpointPath (Join-Path $root 'checkpoint.json') -TenantId $script:Tenant -ExpectedAccount $script:Account -Request $request
        ($calls -join ',') | Should -Be 'GET'
        $result.ConfirmedCount | Should -Be 1
        $result.QueueCount | Should -Be 0
        $saved=Get-Content (Join-Path $root 'checkpoint.json') -Raw | ConvertFrom-Json -AsHashtable
        @($saved.Results.Confirmed).Count | Should -Be 1
        @($saved.Results.Pending).Count | Should -Be 0
        ([int][IO.File]::GetUnixFileMode((Join-Path $root 'checkpoint.json')) -band 63) | Should -Be 0
    }

    It 'waits out a persisted Retry-After before exact lookup and retry' {
        $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
        $due=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o')
        $item=[ordered]@{AppId=$script:App.ToString();Source='Fixture';Metadata=@{Name='Fixture app'};RetryAfterUtc=$due}
        $state=[ordered]@{Format='TokenForgeAppAddabilityCheckpoint';SchemaVersion=1;Status='Pending';TenantId=$script:Tenant.ToString();ExpectedAccount=$script:Account;SnapshotSha256=('a'*64);CreatedAtUtc='2026-11-21T00:00:00Z';UpdatedAtUtc=$null;Queue=@($item);InFlight=[ordered]@{AppId=$script:App.ToString();Phase='PostIntent';Attempt=1};Results=[ordered]@{Confirmed=@();CouldntAdd=@();Pending=@([ordered]@{AppId=$script:App.ToString();UtcDate='2026-11-21';Result='';Reason='Graph throttled';GraphErrorCode='TooManyRequests';RetryAfterUtc=$due;Source='Fixture';Metadata=@{Name='Fixture app'};ServicePrincipal=$null})};CreatedServicePrincipals=@()}
        $responses=[Collections.Queue]::new()
        $responses.Enqueue((New-AppAddabilityObservation 404 'Request_ResourceNotFound'))
        $responses.Enqueue((New-AppAddabilityObservation 201 '' '' ([pscustomobject]@{id=$script:Object.ToString();appId=$script:App.ToString()})))
        $responses.Enqueue((New-AppAddabilityObservation 200 '' '' (New-AppAddabilityPrincipal -OwnerId 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb')))
        $calls=[Collections.Generic.List[string]]::new();$request=New-AppAddabilityRequest $responses $calls
        $result=Invoke-AppAddabilityCatalog -State $state -CheckpointPath (Join-Path $root 'checkpoint.json') -TenantId $script:Tenant -ExpectedAccount $script:Account -Request $request
        ($calls -join ',') | Should -Be 'GET,POST,GET'
        $result.ConfirmedCount | Should -Be 1
        $result.QueueCount | Should -Be 0
    }

    It 'sends no Graph request when the connected account or tenant is wrong' {
        $script:mockContext=[pscustomobject]@{TenantId='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';Account=$script:Account;Scopes=@('Application.ReadWrite.All')}
        $state=[ordered]@{Queue=@();Results=[ordered]@{Confirmed=@();CouldntAdd=@();Pending=@()};InFlight=$null;Status='Prepared';CreatedServicePrincipals=@()}
        $request={ param($Method,$AppId) throw 'should not run' }.GetNewClosure()
        { Invoke-AppAddabilityCatalog -State $state -CheckpointPath (Join-Path $TestDrive 'blocked.json') -TenantId $script:Tenant -ExpectedAccount $script:Account -Request $request } | Should -Throw '*TenantMismatch*'
        Should -Invoke Set-MgRequestContext -Times 0
    }
}
