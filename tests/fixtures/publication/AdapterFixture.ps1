function Write-PublicationFixtureFile([string]$Path,[string]$Text){
 $file=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,$true)
 try{$bytes=[Text.Encoding]::UTF8.GetBytes($Text);$file.Write($bytes);$file.Flush($true)}finally{$file.Dispose()}
}
function Set-PublicationFixtureApproval($Fixture){
 $body=ConvertTo-Json -InputObject $Fixture.Approval -Depth 10 -Compress
 foreach($id in @('101','102')){$Fixture.Server[($Fixture.Api+'/issues/comments/'+$id)].body=$body}
}
function New-PublicationAdapterFixture([string]$Parent){
 $root=Join-Path $Parent ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
 $candidate=Join-Path $root candidate;$null=[IO.Directory]::CreateDirectory($candidate,[IO.UnixFileMode]448)
 $source='a'*40;$sealer='b'*40;$old='c'*40;$new='d'*40;$oldTree='e'*40;$newTree='f'*40
 $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
 $recipe=@{SchemaVersion=1;Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;Pairs=@(@{ClientId=$client;ResourceId=$graph;MatrixKnown=$false;Excluded=$false;Cells=@()})}
 $coverage=@{SchemaVersion=1;Pairs=@(@{CellOutcomes=@()})}
 $scopes=@{SchemaVersion=1;Observations=@();Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'}
 $flows=@{Format='TokenForgeAnonymousFlows';SchemaVersion=1;Observations=@();Disclaimer='Account/session/tenant-dependent observations, not universal support or consent.'}
 $validation=Get-TfCandidateValidation $recipe $coverage $scopes $flows
 foreach($entry in @(@{Name='recipe.json';Value=$recipe},@{Name='coverage.json';Value=$coverage},@{Name='scopes.json';Value=$scopes},@{Name='flows.json';Value=$flows},@{Name='validation.json';Value=$validation})){Write-TfCandidateJson $entry.Value (Join-Path $candidate $entry.Name)}
 [IO.File]::WriteAllText((Join-Path $candidate review.md),(Get-TfCandidateReviewText $validation))
 $files=@(Get-ChildItem $candidate -File|Sort-Object Name|ForEach-Object {@{Path=$_.Name;Sha256=(Get-TfCandidateFileHash $_.FullName)}})
 $manifest=@{SchemaVersion=1;SourceCommit=$source;ProducerRunId='10';ProducerAttempt='1';RecipeSha256=(Get-TfCandidateFileHash (Join-Path $candidate recipe.json));FrozenRecipeSha256=('1'*64);ScopeEvidenceSha256=('2'*64);FlowEvidenceSha256=('3'*64);Files=$files}
 Write-TfCandidateJson $manifest (Join-Path $candidate manifest.json);$candidateHash=Get-TfCandidateFileHash (Join-Path $candidate manifest.json)
 $zip=Join-Path $root candidate.zip;[IO.Compression.ZipFile]::CreateFromDirectory($candidate,$zip);[IO.File]::SetUnixFileMode($zip,[IO.UnixFileMode]384)
 $zipHash=Get-TfCandidateFileHash $zip
 $workflow=[Text.Encoding]::UTF8.GetBytes('synthetic audited producer');$sealBytes=[Text.Encoding]::UTF8.GetBytes('synthetic audited reusable sealer')
 $policy=@{SchemaVersion=1;Repository='example/TokenForge';RepositoryId='100';MainBranch='main';DataBranch='discovery-data';WorkflowId='20';WorkflowPath='.github/workflows/producer.yml';WorkflowSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($workflow)).ToLowerInvariant());SealerPath='.github/workflows/sealer.yml';SealerCommit=$sealer;SealerSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sealBytes)).ToLowerInvariant());VerifierSha256=('4'*64);TrustRootSha256=('5'*64);ProducerIds=@('1');ReviewerIds=@('2');MaintainerIds=@('3');ReaderIds=@('4');JournalRoot=(Join-Path $root state)}
 $policyPath=Join-Path $root policy.json;Write-PublicationFixtureFile $policyPath (ConvertTo-Json -InputObject $policy -Depth 10 -Compress);$policyHash=Get-TfCandidateFileHash $policyPath
 $approval=@{SchemaVersion=1;Kind='TokenForgePublicationApprovalV2';PolicySha256=$policyHash;RepositoryId='100';Ref='refs/heads/discovery-data';Mapping='CandidateDirectoryV1';CandidateHash=$candidateHash;ArtifactId='30';ArtifactSha256=$zipHash;SourceCommit=$source;ProducerRunId='10';ProducerAttempt='1';ExpectedParent=$old;ProposedCommit=$new;CreatedAt='2026-10-23T12:00:00.0000000+00:00';ExpiresAt='2026-10-23T13:00:00.0000000+00:00';Decision='Approved'}
 $api='/repos/example/TokenForge';$server=@{}
 $server[$api]=@{id=100;full_name='example/TokenForge';default_branch='main';archived=$false;disabled=$false}
 $actors=@{};foreach($n in 1..5){$actors[[string]$n]=@{id=$n;login=('actor'+$n);type='User'};$server[($api+'/collaborators/actor'+$n+'/permission')]=@{user=$actors[[string]$n];permission=if($n -eq 2){'write'}else{'admin'}}}
 $server['/user']=$actors['4']
 $server[($api+'/pulls/40')]=@{number=40;state='open';draft=$false;merged=$false;user=$actors['5'];base=@{repo=@{id=100};ref='discovery-data'};head=@{repo=@{id=100};sha=$new}}
 foreach($pair in @(@{Comment=101;Actor='2'},@{Comment=102;Actor='3'})){$server[($api+'/issues/comments/'+$pair.Comment)]=@{id=$pair.Comment;user=$actors[$pair.Actor];issue_url=('https://api.github.com'+$api+'/issues/40');created_at='2026-10-23T12:01:00Z';updated_at='2026-10-23T12:01:00Z';body=''}}
 $server[($api+'/issues/40/comments?per_page=100')]=@($server[($api+'/issues/comments/101')],$server[($api+'/issues/comments/102')])
 $server[($api+'/actions/runs/10')]=@{id=10;run_attempt=1;workflow_id=20;head_sha=$source;head_branch='main';path=$policy.WorkflowPath;event='workflow_dispatch';status='completed';conclusion='success';repository=@{id=100};head_repository=@{id=100};actor=$actors['1'];triggering_actor=$actors['1']}
 $server[($api+'/actions/artifacts/30')]=@{id=30;digest=('sha256:'+$zipHash);size_in_bytes=(Get-Item $zip).Length;expired=$false;expires_at='2026-10-23T14:00:00Z';workflow_run=@{id=10;repository_id=100;head_repository_id=100;head_sha=$source;head_branch='main'}}
 $server[($api+'/branches/main')]=@{commit=@{sha=$source};protected=$true}
 $server[($api+'/branches/main/protection')]=@{enforce_admins=@{enabled=$true};required_pull_request_reviews=@{dismiss_stale_reviews=$true;required_approving_review_count=1}}
 $server[($api+'/compare/'+$sealer+'...'+$source)]=@{status='ahead';merge_base_commit=@{sha=$sealer}}
 foreach($src in @(@{Path=$policy.WorkflowPath;Commit=$source;Bytes=$workflow},@{Path=$policy.SealerPath;Commit=$sealer;Bytes=$sealBytes})){$server[($api+'/contents/'+$src.Path+'?ref='+$src.Commit)]=@{type='file';encoding='base64';path=$src.Path;sha=(Get-TfPublicationBlobHash $src.Bytes);content=[Convert]::ToBase64String($src.Bytes)}}
 $server[($api+'/git/commits/'+$old)]=@{sha=$old;tree=@{sha=$oldTree};parents=@()}
 $server[($api+'/git/commits/'+$new)]=@{sha=$new;tree=@{sha=$newTree};parents=@(@{sha=$old})}
 $readme=@{path='README.md';mode='100644';type='blob';sha=('6'*40)};$prefix='candidates/'+$candidateHash
 $server[($api+'/git/trees/'+$oldTree+'?recursive=1')]=@{sha=$oldTree;truncated=$false;tree=@($readme)}
 $leaves=@(Get-ChildItem $candidate -File|ForEach-Object {@{path=($prefix+'/'+$_.Name);mode='100644';type='blob';sha=(Get-TfPublicationBlobHash ([IO.File]::ReadAllBytes($_.FullName)))}})
 $server[($api+'/git/trees/'+$newTree+'?recursive=1')]=@{sha=$newTree;truncated=$false;tree=@($readme,@{path='candidates';mode='040000';type='tree';sha=('7'*40)},@{path=$prefix;mode='040000';type='tree';sha=('8'*40)})+$leaves}
 $server[($api+'/git/ref/heads/discovery-data')]=@{ref='refs/heads/discovery-data';object=@{type='commit';sha=$old}}
 $certificate=@{issuer='https://token.actions.githubusercontent.com';sourceRepositoryURI='https://github.com/example/TokenForge';sourceRepositoryIdentifier='100';sourceRepositoryDigest=$source;sourceRepositoryRef='refs/heads/main';buildSignerURI=('https://github.com/example/TokenForge/'+$policy.SealerPath+'@'+$sealer);buildSignerDigest=$sealer;runInvocationURI='https://github.com/example/TokenForge/actions/runs/10/attempts/1';runnerEnvironment='github-hosted'}
 $attestation=@{verificationResult=@{signature=@{certificate=$certificate};statement=@{predicateType='https://slsa.dev/provenance/v1';subject=@(@{digest=@{sha256=$zipHash}})};verifiedTimestamps=@(@{type='Tlog';timestamp='2026-10-23T12:00:00Z'})}}
 $fixture=@{Root=$root;Candidate=$candidate;Zip=$zip;Api=$api;Source=$source;Old=$old;New=$new;OldTree=$oldTree;NewTree=$newTree;Policy=$policy;PolicyPath=$policyPath;PolicyHash=$policyHash;Approval=$approval;Server=$server;Attestation=$attestation;Actors=$actors;Log=[Collections.Generic.List[string]]::new();Calls=@{};OnRead=$null;Paginated=$false;Status=200}
 Set-PublicationFixtureApproval $fixture
 $fixture.Options=@{PolicyPath=$policyPath;PolicySha256=$policyHash;ArchivePath=$zip;PullRequest='40';ReviewerComment='101';MaintainerComment='102';Synthetic=$true;FixtureTime=([DateTimeOffset]'2026-10-23T12:05:00Z');ReadFixture=({param($route)
  $fixture.Log.Add($route);if(-not $fixture.Calls.ContainsKey($route)){$fixture.Calls[$route]=0};$fixture.Calls[$route]++
  if($fixture.OnRead){& $fixture.OnRead $fixture $route}
  if(-not $fixture.Server.ContainsKey($route)){throw 'Unexpected route; no fallback.'}
  @{Status=$fixture.Status;Paginated=$fixture.Paginated;Bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $fixture.Server[$route] -Depth 40 -Compress))}
 }.GetNewClosure());VerifyFixtureAttestation=({,@($fixture.Attestation)}.GetNewClosure())}
 $fixture
}
