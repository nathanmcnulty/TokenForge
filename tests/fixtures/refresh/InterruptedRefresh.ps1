param([string]$PlanPath,[string]$StatePath,[string]$Boundary)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot/../../../src/TokenForge/TokenForge.psd1" -Force
$planJson=[IO.File]::ReadAllText($PlanPath);$plan=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($planJson)
$run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$StatePath);$id=$plan.Candidates[0].RequestId
if($Boundary -in @('BeforeRequest','RemoteResult')){
 $sequence=$run.Reserve($id,'FinalIssuance')
 if($Boundary -eq 'RemoteResult'){[IO.File]::WriteAllText($StatePath+'.simulated-call','1')}
}else{
 foreach($kind in @('BootstrapIssuance','FinalIssuance')){$sequence=$run.Reserve($id,$kind);$run.Complete($sequence)}
 $sequence=$run.Reserve($id,'IdentityGet');$run.Complete($sequence,200)
 $now=[DateTimeOffset]::UtcNow.ToString('o')
 $snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType='IssuedScopes';Privacy='Private';Status='Complete';Context=$plan.Candidates[0].Context;Source=@{Id='synthetic-kill';Location=('urn:sha256:'+('d'*64));ContentSha256=('d'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=$now};Records=@(@{RecordId=('e'*64);ObservedAt=$now;Outcome='Succeeded';Identity=@{ClientId=$plan.Candidates[0].Context.ClientId;ResourceId=$plan.Candidates[0].Context.ResourceId};Value=@{Scopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';ClaimsReadable=$true;HasScpClaim=$true;SignatureValidated=$false}})})}
 $run.SaveEvidence($id,($snapshot|ConvertTo-Json -Depth 100 -Compress))
 if($Boundary -eq 'ProjectionStaged'){[IO.File]::WriteAllText($StatePath+'.projection.tmp',$run.ProjectHistory())}
}
[IO.File]::WriteAllText($StatePath+'.ready',$Boundary)
while($true){[Threading.Thread]::Sleep(100)}
