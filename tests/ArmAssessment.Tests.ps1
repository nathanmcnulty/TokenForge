BeforeAll {
    . "$PSScriptRoot/fixtures/refresh/RefreshFixture.ps1"
    $arm='797f4846-ba00-4fd7-ba43-dac1f8f63013'
    function Read-ArmJson($Value){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($Value)}
    function New-ArmInput {
        $input=New-RefreshInput
        $input.Profile=Read-ArmJson ([TokenForge.Core.AdminWorkflows]::CreateStrictProfile('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',[TokenForge.Core.ApplicationCatalogPolicy]::Hash('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),$script:rfBoot,[string[]]@($script:rfBoot,$script:rfClient)))
        $input.Inventory.TenantFingerprint=$input.Profile.ExpectedTenantFingerprint
        $input.Inventory.PrincipalFingerprint=$input.Profile.ExpectedPrincipalFingerprint
        $input.Inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
        $resource=Copy-Refresh $input.Inventory.Applications[-1];$resource.AppId=$arm
        $resource.DelegatedScopeDefinitions=@(@{Id='44444444-4444-4444-4444-444444444444';Value='user_impersonation';Enabled=$true})
        $input.Inventory.Applications+=@($resource)
        $input.Requirements.Tools[0].Id='subscriptions'
        $input.Requirements.Tools[0].ResourceId=$arm
        $input.Requirements.Tools[0].Scopes=@('user_impersonation')
        $input.Requirements.Tools[0].Operations=@('ArmSubscriptionsV1')
        $input.Policy=Read-ArmJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($input.Requirements|ConvertTo-Json -Depth 20 -Compress)))
        return $input
    }
    function Invoke-ArmFake([bool]$Proof=$true,[string]$ToolId='subscriptions') {
        [TokenForge.Core.AdminWorkflows]::Acquire(($i.Profile|ConvertTo-Json -Depth 30 -Compress),($i.Requirements|ConvertTo-Json -Depth 30 -Compress),($i.Inventory|ConvertTo-Json -Depth 30 -Compress),$ToolId,$cookie,'ESTSAUTH',[NullString]::Value,[NullString]::Value,$Proof,[NullString]::Value,$execute,$identity,$api,[Threading.CancellationToken]::None)
    }
}
Describe 'ARM selected read-only assessment and refresh evidence' {
    BeforeEach {
        $i=New-ArmInput
        $cookie=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
        $script:armStatus=200;$script:armThrow=$false
        $script:armCalls=[Collections.Generic.List[object]]::new()
        $execute=[Func[TokenForge.Core.ScopePlanning+RequestRow,TokenForge.Core.ProfileCredentialToken]]{
            param($request)
            $script:armCalls.Add($request)
            $body=@{tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';oid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';appid=$request.ClientId;aud=$request.ResourceId;scp=($request.Scopes -join ' ');exp=[DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
            $jwt='e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body)).TrimEnd('=').Replace('+','-').Replace('/','_')+'.synthetic'
            $access=ConvertTo-SecureString $jwt -AsPlainText -Force
            try{return [TokenForge.Core.ProfileCredentialToken]::new($request.ToTransport(),$access,$null,[DateTimeOffset]::UtcNow.AddMinutes(30),0)}finally{$access.Dispose()}
        }
        $identity=[Func[Security.SecureString,string]]{param($token) 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
        $api=[Func[Security.SecureString,TokenForge.Core.ProfileApiCheck]]{param($token) if($script:armThrow){throw [OperationCanceledException]::new()};[TokenForge.Core.ProfileApiCheck]::new($script:armStatus,($null -ne $script:armStatus -and $script:armStatus -ge 200 -and $script:armStatus -le 299))}
    }
    AfterEach {$cookie.Dispose()}
    It 'binds ARM issuance and proof to the declared resource, version and operation' {
        $result=Invoke-ArmFake
        try{
            $m=Read-ArmJson $result.ToJson()
            $m.Status|Should -Be IssuedWithinStrictPolicy
            $m.ApiCheck.Operation|Should -Be ArmSubscriptionsV1
            $m.ApiCheck.ApiVersion|Should -Be '2022-12-01'
            $m.ApiComparisonContext.ResourceId|Should -Be $arm
            $m.ApiComparisonContext.OperationFingerprint|Should -Be ([TokenForge.Core.ApplicationCatalogPolicy]::Hash('ArmSubscriptionsV1'))
            $script:armCalls.Count|Should -Be 2
            $script:armCalls[0].ResourceId|Should -Be $script:rfGraph
            $script:armCalls[1].ResourceId|Should -Be $arm
            $script:armCalls[1].Scopes|Should -Be @('user_impersonation')
            $snapshot=ConvertTo-TokenForgeToolEvidence $m
            (Test-TokenForgeTool -Profile $i.Profile -Requirements $i.Requirements -Inventory $i.Inventory -Snapshot $snapshot -ToolId subscriptions).Status|Should -Be VerifiedWorking
            $result.ToJson()|Should -Not -Match 'synthetic|AccessToken|RefreshToken|Cookie|eyJ'
        }finally{$result.Dispose()}
    }
    It 'rejects mismatched resource, undeclared scope, URI operation and multiple proofs (<Case>)' -ForEach @(
        @{Case='Graph operation'},@{Case='Graph resource'},@{Case='Missing scope'},@{Case='Arbitrary URI'},@{Case='Two operations'}
    ) {
        switch($Case){
            'Graph operation' {$i.Requirements.Tools[0].Operations=@('GraphMeV1')}
            'Graph resource' {$i.Requirements.Tools[0].ResourceId=$script:rfGraph}
            'Missing scope' {$i.Requirements.Tools[0].Scopes=@('Other.Read')}
            'Arbitrary URI' {$i.Requirements.Tools[0].Operations=@('https://management.azure.com/delete')}
            'Two operations' {$i.Requirements.Tools[0].Operations=@('ArmSubscriptionsV1','GraphMeV1')}
        }
        {[TokenForge.Core.AdminWorkflows]::ValidateRequirements(($i.Requirements|ConvertTo-Json -Depth 30 -Compress))}|Should -Throw
        $script:armCalls.Count|Should -Be 0
    }
    It 'never promotes issuance alone, HTTP denial, unknown response or cancellation (<Case>)' -ForEach @(
        @{Case='No proof'},@{Case='Denied'},@{Case='Unknown'},@{Case='Cancelled'}
    ) {
        if($Case -eq 'Denied'){$script:armStatus=403}
        if($Case -eq 'Unknown'){$script:armStatus=$null}
        if($Case -eq 'Cancelled'){$script:armThrow=$true}
        $result=Invoke-ArmFake ($Case -ne 'No proof')
        try{
            $m=Read-ArmJson $result.ToJson();$m.IssuanceSucceeded|Should -BeTrue
            $snapshot=ConvertTo-TokenForgeToolEvidence $m
            (Test-TokenForgeTool -Profile $i.Profile -Requirements $i.Requirements -Inventory $i.Inventory -Snapshot $snapshot -ToolId subscriptions).Status|Should -Not -Be VerifiedWorking
        }finally{$result.Dispose()}
    }
    It 'refuses modified ARM operation, version, approval and resource evidence (<Case>)' -ForEach @(
        @{Case='Operation'},@{Case='Version'},@{Case='Approval'},@{Case='Resource'},@{Case='Fingerprint'}
    ) {
        $result=Invoke-ArmFake
        try{
            $m=Read-ArmJson $result.ToJson()
            switch($Case){
                Operation {$m.ApiCheck.Operation='GraphMeV1'}
                Version {$m.ApiCheck.ApiVersion='v1.0'}
                Approval {$m.ApiComparisonContext.ApprovalFingerprint='a'*64}
                Resource {$m.ApiComparisonContext.ResourceId=$script:rfGraph}
                Fingerprint {$m.ApiComparisonContext.OperationFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash('GraphMeV1')}
            }
            {ConvertTo-TokenForgeToolEvidence $m}|Should -Throw
        }finally{$result.Dispose()}
    }
    It 'captures ARM proof and reuses its original observations with an all-fresh no-work plan' {
        $asOf=[DateTimeOffset]::UtcNow.AddSeconds(-1)
        $initial=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf $asOf
        $initial.SelectedCount|Should -Be 1
        $initial.Candidates[0].Reason|Should -Be MissingEvidence
        $result=Invoke-ArmFake
        try{$snapshot=ConvertTo-TokenForgeToolEvidence (Read-ArmJson $result.ToJson())}finally{$result.Dispose()}
        $i.History=ConvertTo-TokenForgeRefreshHistory -PlanJson ($initial|ConvertTo-Json -Depth 64 -Compress) -SnapshotJson ($snapshot|ConvertTo-Json -Depth 64 -Compress)
        $i.Snapshot=$snapshot
        $reused=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow)
        $reused.SelectedCount|Should -Be 0
        $reused.HasIssuancePlan|Should -BeFalse
        $reused.ReusedCount|Should -Be 1
        $reused.Candidates[0].ReuseReferences.Count|Should -Be 2
        $reused.Candidates[0].ReuseReferences.ObservedAt|Should -Be @($snapshot.Collections.Records.ObservedAt)
        $script:armCalls.Count|Should -Be 2
    }
    It 'preserves prior ARM history while capturing missing Graph evidence, then selects no work for both' {
        $graphTool=Copy-Refresh $i.Requirements.Tools[0]
        $graphTool.Id='profile';$graphTool.ResourceId=$script:rfGraph;$graphTool.Scopes=@('User.Read');$graphTool.Operations=@('GraphMeV1')
        $i.Requirements.Tools+=@($graphTool)
        $i.Policy=Read-ArmJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($i.Requirements|ConvertTo-Json -Depth 20 -Compress)))
        $p1=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow.AddSeconds(-1))
        $p1.SelectedCount|Should -Be 2
        $frozen=$p1|ConvertTo-Json -Depth 64 -Compress
        $result=Invoke-ArmFake
        try{$s1=ConvertTo-TokenForgeToolEvidence (Read-ArmJson $result.ToJson())}finally{$result.Dispose()}
        $i.History=ConvertTo-TokenForgeRefreshHistory -PlanJson $frozen -SnapshotJson ($s1|ConvertTo-Json -Depth 64 -Compress)
        $i.Snapshot=$s1
        $p2=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow)
        $p2.SelectedCount|Should -Be 1;$p2.ReusedCount|Should -Be 1
        @($p2.Candidates|Where-Object Selected)[0].ToolId|Should -Be profile
        $originalRefs=$i.History.Entries[0].ObservationReferences|ConvertTo-Json -Depth 20 -Compress
        $planJson=$p2|ConvertTo-Json -Depth 64 -Compress
        $private=Join-Path $TestDrive 'refresh-private';$null=[IO.Directory]::CreateDirectory($private,[IO.UnixFileMode]448)
        $state=Join-Path $private 'refresh-run.json'
        $run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$state);$run.Dispose()
        $exported=Export-TokenForgeRefreshHistory -PlanJson $planJson -StatePath $state
        $exported.Entries.Count|Should -Be 1
        ($exported.Entries[0].ObservationReferences|ConvertTo-Json -Depth 20 -Compress)|Should -BeExactly $originalRefs
        {Export-TokenForgeRefreshHistory -PlanJson $planJson -StatePath $state -HistoryJson ''}|Should -Throw
        $result=Invoke-ArmFake -ToolId profile
        try{$s2=ConvertTo-TokenForgeToolEvidence (Read-ArmJson $result.ToJson())}finally{$result.Dispose()}
        $historyOptions=@{PlanJson=($p2|ConvertTo-Json -Depth 64 -Compress);SnapshotJson=($s2|ConvertTo-Json -Depth 64 -Compress)}
        {ConvertTo-TokenForgeRefreshHistory @historyOptions -HistoryJson ''}|Should -Throw
        $i.History=ConvertTo-TokenForgeRefreshHistory @historyOptions
        $i.History.Entries.Count|Should -Be 2
        ($i.History.Entries[0].ObservationReferences|ConvertTo-Json -Depth 20 -Compress)|Should -BeExactly $originalRefs
        $i.Snapshot=$s2
        $p3=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow)
        $p3.SelectedCount|Should -Be 0;$p3.ReusedCount|Should -Be 2;$p3.HasIssuancePlan|Should -BeFalse
        $i.Inventory.Applications[0].Name='Unrelated display label'
        (Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow)).ReusedCount|Should -Be 2
        $i.Inventory.TenantGrants+=@(@{ClientId=$script:rfClient;ResourceId=$arm;Scopes=@('user_impersonation');PrincipalFingerprint=$null;ConsentType='AllPrincipals';AppliesToCurrentPrincipal=$true;Evidence='TenantConfiguredGrant'})
        $changed=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf ([DateTimeOffset]::UtcNow)
        $changed.SelectedCount|Should -Be 1;$changed.ReusedCount|Should -Be 1
        @($changed.Candidates|Where-Object Selected)[0].ToolId|Should -Be subscriptions
        @($changed.Candidates|Where-Object Selected)[0].Reason|Should -Be ToolCriticalRelevantChange
        (Read-ArmJson ([TokenForge.Core.AdminWorkflows]::ValidateRefresh($frozen))).PlanId|Should -Be $p1.PlanId
        ($p1|ConvertTo-Json -Depth 64 -Compress)|Should -BeExactly $frozen
        $script:armCalls.Count|Should -Be 4
    }
    It 'selects an overdue ARM proof while retaining its actual synthetic observation date' {
        $result=Invoke-ArmFake
        try{$m=Read-ArmJson $result.ToJson()}finally{$result.Dispose()}
        # Synthetic historical evidence, never a relabeled live receipt.
        $now=[DateTimeOffset]::UtcNow;$m.ObservedAt=$now.AddHours(-25).ToString('o')
        $i.Inventory.CapturedAt=$now.AddHours(-27).ToString('o')
        $initial=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf $now.AddHours(-26)
        $snapshot=ConvertTo-TokenForgeToolEvidence $m
        $i.History=ConvertTo-TokenForgeRefreshHistory -PlanJson ($initial|ConvertTo-Json -Depth 64 -Compress) -SnapshotJson ($snapshot|ConvertTo-Json -Depth 64 -Compress)
        $i.Snapshot=$snapshot;$i.Inventory.CapturedAt=$now.AddMinutes(-1).ToString('o')
        $p=Get-TokenForgeRefreshPlan -InputJson ($i|ConvertTo-Json -Depth 64 -Compress) -AsOf $now
        $p.SelectedCount|Should -Be 1;$p.ReusedCount|Should -Be 0
        $p.Candidates[0].Reason|Should -Be OverdueRefresh
        $p.Candidates[0].ObservedAt|Should -Be $m.ObservedAt
        $i.History.Entries[0].ObservationReferences.ObservedAt|Should -Be @($m.ObservedAt,$m.ObservedAt)
    }
}
