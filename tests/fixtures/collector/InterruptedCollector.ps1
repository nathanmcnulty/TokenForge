#Requires -Version 7.6
# Synthetic child-process crash fixture. Every token path is replaced before probing.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('BeforeRequest','RemoteResult','TerminalBeforeProjection','ExportBeforeMove')][string]$Boundary,
 [Parameter(Mandatory)][string]$Root,
 [Parameter(Mandatory)][string]$NativeExecutablePath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit
)
$ErrorActionPreference='Stop'
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $repository 'scripts/TokenForgeDiscoveryCandidate.ps1')

function global:Write-TfKillFixtureFile([string]$Path,[string]$Text) {
 $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::Create;$options.Access=[IO.FileAccess]::Write
 $options.UnixCreateMode=[IO.UnixFileMode]384
 $stream=[IO.FileStream]::new($Path,$options)
 try{$bytes=[Text.Encoding]::UTF8.GetBytes($Text);$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
}
function global:Wait-TfKillFixtureBoundary {
 $marker=[ordered]@{SchemaVersion=1;Boundary=$global:TfKillBoundary;CohortId=$global:TfKillCohort}
 $temporary=Join-Path $global:TfKillRoot 'ready.json.pending'
 Write-TfKillFixtureFile $temporary ($marker|ConvertTo-Json -Compress)
 [IO.File]::Move($temporary,(Join-Path $global:TfKillRoot 'ready.json'),$false)
 $timer=[Diagnostics.Stopwatch]::StartNew()
 while($timer.Elapsed.TotalSeconds -lt 120){[Threading.Thread]::Sleep(100)}
 throw 'Crash fixture was not killed within its bounded handshake window.'
}
$global:TfKillRoot=$Root;$global:TfKillBoundary=$Boundary;$global:TfKillCohort=$null
$global:TfKillCalls=0;$global:TfKillChecks=0
& (Get-Module TokenForge) {
 function script:Get-TokenForgeToken {
  [CmdletBinding()]param($Request,$EstsAuth,$CookieName,$OperationBudget)
  $global:TfKillCalls++
  Write-TfKillFixtureFile (Join-Path $global:TfKillRoot 'token-calls.txt') ([string]$global:TfKillCalls)
  # This object is synthetic. No transport or authorization helper is called.
  $result=[pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  if($global:TfKillBoundary -ceq 'RemoteResult'){
   Write-TfKillFixtureFile (Join-Path $global:TfKillRoot 'simulated-result.json') '{"SchemaVersion":1,"SimulatedResultReceived":true}'
   Wait-TfKillFixtureBoundary
  }
  $result
 }
}
$null=[IO.Directory]::CreateDirectory($Root,[IO.UnixFileMode]448)
$scopePath=Join-Path $Root scopes.sqlite;$flowPath=Join-Path $Root flows.sqlite
$callback='https://login.microsoftonline.com/common/oauth2/nativeclient';$client='11111111-1111-1111-1111-111111111111'
$app=[pscustomobject]@{AppId=$client;Name='Synthetic crash fixture';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@($callback);PreferredRedirectUri=$callback;IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}
$inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($app)}
Write-TfKillFixtureFile (Join-Path $Root 'inventory.json') ($inventory|ConvertTo-Json -Depth 32)
$cohort=New-TokenForgeResearchCohort -Inventory $inventory -DatabasePath $scopePath -GraphOnly -Protocols OAuth2V2Pkce -MaxRedirects 1 -BatchSize 1 -ExploreAllFlows -NativeExecutablePath $NativeExecutablePath
$global:TfKillCohort=$cohort.PlanId
$secret=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
try{
 $probe=@{Inventory=$inventory;EstsAuth=$secret;Plan=@($cohort.Cohort.Pairs);DatabasePath=$scopePath;FlowDatabasePath=$flowPath;CohortFingerprint=$cohort.PlanId;Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;DelayMilliseconds=0;NativeExecutablePath=$NativeExecutablePath}
 if($Boundary -cne 'ExportBeforeMove'){
  $probe.CheckpointAction={
   $global:TfKillChecks++
   if(($global:TfKillBoundary -ceq 'BeforeRequest' -and $global:TfKillChecks -eq 1) -or ($global:TfKillBoundary -ceq 'TerminalBeforeProjection' -and $global:TfKillChecks -eq 2)){Wait-TfKillFixtureBoundary}
  }
 }
 $null=Invoke-TokenForgeScopeProbe @probe
 if($Boundary -ceq 'ExportBeforeMove'){
  # Test-only interception after independent staging verification, before final move.
  # The production helper is unchanged, and the real verifier still runs first.
  $global:TfKillOriginalVerifier=(Get-Command Assert-TfDiscoveryCandidate).ScriptBlock
  function Assert-TfDiscoveryCandidate {
   [CmdletBinding()]param([string]$CandidatePath,[string]$CandidateHash,[string]$ReviewPath)
   $verified=& $global:TfKillOriginalVerifier @PSBoundParameters
   Wait-TfKillFixtureBoundary
   $verified
  }
  $null=New-TfDiscoveryCandidate -ScopePath $scopePath -FlowPath $flowPath -CohortId $cohort.PlanId -OutputPath (Join-Path $Root candidate) -SourceCommit $SourceCommit -ProducerRunId 1 -ProducerAttempt 1 -NativeExecutablePath $NativeExecutablePath
 }
 throw 'Crash fixture unexpectedly passed its selected interruption boundary.'
}finally{$secret.Dispose()}
