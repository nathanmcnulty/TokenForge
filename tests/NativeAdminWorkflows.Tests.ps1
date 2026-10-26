BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function Write-AdminFile($Path,$Object) {
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,$true)
  try{$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Object -Depth 64 -Compress));$file.Write($bytes);$file.Flush($true)}finally{$file.Dispose()}
 }
 function Invoke-AdminNative([string[]]$Options,[int]$Exit=0,[switch]$Invalid) {
  $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE);$start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
  $start.Environment['PATH']=Join-Path $root no-powershell
  foreach($arg in @('admin')+$Options){$start.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($start)
  try{$process.StandardInput.Close();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync();if(-not $process.WaitForExit(15000)){$process.Kill($true);throw 'Native administrator fixture timed out.'};$process.ExitCode|Should -Be $Exit;$stdout=$out.GetAwaiter().GetResult();$stderr=$err.GetAwaiter().GetResult()
   if($Invalid){$stdout|Should -BeNullOrEmpty;($stderr|ConvertFrom-Json).Code|Should -Be OperationFailed;$stderr|Should -Not -Match 'synthetic-private|AccessToken';$stderr|Should -Not -Match ([regex]::Escape($root))}
   else{$stderr|Should -BeNullOrEmpty;[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($stdout)}
  }finally{$process.Dispose()}
 }
}
Describe 'Native Goal 3 shared administrator consumers' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111';$boot='22222222-2222-2222-2222-222222222222';$tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$stamp=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o');$asOf=[DateTimeOffset]::UtcNow.ToString('o')
  $profile=New-TokenForgeStrictProfile -TenantId $tenant -PrincipalFingerprint ('b'*64) -BootstrapClientId $boot -ApprovedClientId @($client,$boot)
  $requirements=@{Format='TokenForgeToolRequirements';SchemaVersion=1;Tools=@(@{Id='read-profile';ClientIds=@($client);ResourceId=$graph;Scopes=@('User.Read');Protocol='OAuth2V2Pkce';CallbackClass='Native';Operations=@();Prerequisites=@();SecuritySensitive=$false})}
  $inventory=@{SchemaVersion=1;CapturedAt=$stamp;TenantFingerprint=$profile.ExpectedTenantFingerprint;PrincipalFingerprint=$profile.ExpectedPrincipalFingerprint;GrantEnumeration='Complete';TenantGrants=@();Applications=@(foreach($id in @($client,$boot,$graph)){@{AppId=$id;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true});AppRoleDefinitions=@()}})}
  $plan=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Plan(($profile|ConvertTo-Json -Depth 30 -Compress),($requirements|ConvertTo-Json -Depth 30 -Compress),($inventory|ConvertTo-Json -Depth 30 -Compress),'read-profile'))
  $snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType='IssuedScopes';Privacy='Private';Status='Complete';Context=$plan.Context;Source=@{Id='synthetic';Location=('urn:sha256:'+('d'*64));ContentSha256=('d'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=$stamp};Records=@(@{RecordId=('e'*64);ObservedAt=$stamp;Outcome='Succeeded';Identity=@{ClientId=$client;ResourceId=$graph};Value=@{Scopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';ClaimsReadable=$true;HasScpClaim=$true;SignatureValidated=$false}})})}
  $pp=Join-Path $root profile.json;$rp=Join-Path $root requirements.json;$ip=Join-Path $root inventory.json;$sp=Join-Path $root snapshot.json
  Write-AdminFile $pp $profile;Write-AdminFile $rp $requirements;Write-AdminFile $ip $inventory
  $options=@('--profile-path',$pp,'--requirements-path',$rp,'--inventory-path',$ip,'--snapshot-path',$sp,'--tool','read-profile','--as-of',$asOf,'--json')
 }
 It 'returns the same JSON and exit code for every tool health status' -TestCases @(@{Status='VerifiedWorking';Exit=0},@{Status='AtRisk';Exit=2},@{Status='NeedsObservation';Exit=3},@{Status='Blocked';Exit=4}) {
  param($Status,$Exit)
  switch($Status){AtRisk {$snapshot.Collections[0].Records[0].ObservedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')} NeedsObservation {$snapshot.Collections=@()} Blocked {$snapshot.Collections[0].Records[0].Value.Scopes=@('User.Read','Mail.Read')}}
  Write-AdminFile $sp $snapshot
  $native=Invoke-AdminNative (@('check')+$options) $Exit
  $ps=Test-TokenForgeTool -Profile $profile -Requirements $requirements -Inventory $inventory -Snapshot $snapshot -ToolId read-profile -AsOf $asOf
  $native.Status|Should -Be $Status;($native|ConvertTo-Json -Depth 64 -Compress)|Should -Be ($ps|ConvertTo-Json -Depth 64 -Compress)
  $explain=Invoke-AdminNative (@('explain')+$options) $Exit
  $expected=Get-TokenForgeToolExplanation -Profile $profile -Requirements $requirements -Inventory $inventory -Snapshot $snapshot -ToolId read-profile -AsOf $asOf
  ($explain|ConvertTo-Json -Depth 64 -Compress)|Should -Be ($expected|ConvertTo-Json -Depth 64 -Compress)
 }
 It 'performs zero requests without an explicit existing session and converts metadata to evidence' {
  $m=Invoke-AdminNative @('acquire','--profile-path',$pp,'--requirements-path',$rp,'--inventory-path',$ip,'--tool','read-profile') 4
  $m.BootstrapAttempts|Should -Be 0;$m.FinalAttempts|Should -Be 0;$m.Reason|Should -Be ExistingSilentSessionRequired
  $ap=Join-Path $root acquisition.json;Write-AdminFile $ap $m
  $s=Invoke-AdminNative @('evidence','--acquisition-path',$ap)
  ($s|ConvertTo-Json -Depth 64 -Compress)|Should -Be ((ConvertTo-TokenForgeToolEvidence $m)|ConvertTo-Json -Depth 64 -Compress)
 }
 It 'blocks an unsupported route before reading stdin even when explicitly selected' {
  $requirements.Tools[0].Protocol='OAuth2V1Implicit';Remove-Item $rp;Write-AdminFile $rp $requirements
  $m=Invoke-AdminNative @('acquire','--profile-path',$pp,'--requirements-path',$rp,'--inventory-path',$ip,'--tool','read-profile','--cookie-stdin') 4
  $m.Reason|Should -Be UnsupportedStrictProtocol;$m.BootstrapAttempts|Should -Be 0
 }
 It 'prepares an identical private change packet from saved typed evidence' {
  $bp=Join-Path $root before.json;Write-AdminFile $bp $snapshot;$snapshot.Collections[0].Records[0].Value.Scopes=@('User.Read','Mail.Read');Write-AdminFile $sp $snapshot
  $b=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($bp))
  $native=Invoke-AdminNative @('packet','--requirements-path',$rp,'--before-path',$bp,'--after-path',$sp,'--source-revision',('1'*40),'--package-sha256',('2'*64),'--as-of',$asOf,'--security-sensitive')
  $ps=New-TokenForgeToolChangePacket -Requirements $requirements -Before $b -After $snapshot -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64) -AsOf $asOf -SecuritySensitive
  ($native|ConvertTo-Json -Depth 64 -Compress)|Should -Be ($ps|ConvertTo-Json -Depth 64 -Compress)
  $native.Entries[0].Change.EventType|Should -Be MatchedRequestScopesChanged;$native.DisclosureRoute|Should -Be PrivateSecurityDisclosure
 }
 It 'rejects duplicate and unknown arguments before evidence ingress' -TestCases @(@{Flag='--tool'},@{Flag='--unknown'}) {
  param($Flag)
  Invoke-AdminNative (@('check')+$options+@($Flag,'synthetic-private')) 1 -Invalid
 }
 It 'rejects private file symlinks and broad permissions' -Skip:$IsWindows {
  Write-AdminFile $sp $snapshot;$link=Join-Path $root link.json;$null=New-Item -ItemType SymbolicLink -Path $link -Target $pp
  Invoke-AdminNative @('check','--profile-path',$link,'--requirements-path',$rp,'--inventory-path',$ip,'--snapshot-path',$sp,'--tool','read-profile') 1 -Invalid
  [IO.File]::SetUnixFileMode($pp,[IO.UnixFileMode]420)
  Invoke-AdminNative (@('check')+$options) 1 -Invalid
 }
 It 'does not echo credential-bearing input or overwrite saved evidence' {
  $snapshot.Collections[0].Records[0].Value.AccessToken='synthetic-private';Write-AdminFile $sp $snapshot;$hash=(Get-FileHash $sp).Hash
  Invoke-AdminNative (@('check')+$options) 1 -Invalid
  (Get-FileHash $sp).Hash|Should -Be $hash
 }
}
