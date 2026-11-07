# Synthetic offline fixture only. It creates no GitHub authority or live destination.
function New-LocalPublicationFixture([string]$Parent,[switch]$Partial,[switch]$NoPacket,[string]$ExpectedParent=('d'*40)) {
 $root=Join-Path $Parent ([guid]::NewGuid().ToString('N'))
 $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
 $evidencePath=Join-Path $root 'evidence-manifest.json';$selectionPath=Join-Path $root 'selection.json'
 Write-TfCandidateJson ([ordered]@{SchemaVersion=1;Kind='SyntheticLocalEvidenceManifest';SourceCommit=('b'*40);PackageManifestSha256=('3'*64);CompilationSource=('c'*40)}) $evidencePath
 Write-TfCandidateJson ([ordered]@{SchemaVersion=1;Kind='SyntheticLocalSelection';ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';SelectedAt='2026-01-01T00:00:00Z'}) $selectionPath
 foreach($path in @($evidencePath,$selectionPath)){[IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]384)}
 $candidate=Join-Path $root 'candidate';$null=[IO.Directory]::CreateDirectory($candidate,[IO.UnixFileMode]448)
 $client='11111111-1111-1111-1111-111111111111';$resource='00000003-0000-0000-c000-000000000000';$source='a'*40
 $recipe=[ordered]@{SchemaVersion=1;Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;Pairs=@([ordered]@{ClientId=$client;ResourceId=$resource;MatrixKnown=$true;Excluded=$false;Cells=@([ordered]@{Protocol='OAuth2V2Pkce';Spa=$false})})}
 $coverage=[ordered]@{SchemaVersion=1;Pairs=@([ordered]@{CellOutcomes=@($(if($Partial){'Pending'}else{'Succeeded'}))})}
 $scopes=[ordered]@{SchemaVersion=1;Observations=@([ordered]@{ClientId=$client;ResourceId=$resource;ObservedAt='2026-01-01T00:00:00Z';Scopes=@('User.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false});Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'}
 $flows=[ordered]@{Format='TokenForgeAnonymousFlows';SchemaVersion=1;Observations=@([ordered]@{ClientId=$client;ResourceId=$resource;Protocol='OAuth2V2Pkce';Spa=$false;Scopes=@('User.Read');SignatureValidated=$false;Evidence='AnonymousObservedFlowNotUniversalCapability'});Disclaimer='Account/session/tenant-dependent observations, not universal support or consent.'}
 $validation=Get-TfCandidateValidation $recipe $coverage $scopes $flows
 foreach($item in @(@{Name='recipe.json';Value=$recipe},@{Name='coverage.json';Value=$coverage},@{Name='scopes.json';Value=$scopes},@{Name='flows.json';Value=$flows},@{Name='validation.json';Value=$validation})){
  Write-TfCandidateJson $item.Value (Join-Path $candidate $item.Name)
 }
 [IO.File]::WriteAllText((Join-Path $candidate 'review.md'),(Get-TfCandidateReviewText $validation),[Text.UTF8Encoding]::new($false))
 $files=@(Get-ChildItem -LiteralPath $candidate -File|Sort-Object Name|ForEach-Object {[ordered]@{Path=$_.Name;Sha256=(Get-TfCandidateFileHash $_.FullName)}})
 $origin=[ordered]@{Kind='LocalSnapshotV1';ExportId='11111111-2222-3333-4444-555555555555';EvidenceManifestSha256=(Get-TfCandidateFileHash $evidencePath);SelectionSha256=(Get-TfCandidateFileHash $selectionPath);EvidenceSourceCommit=('b'*40);EvidencePackageManifestSha256=('3'*64);EvidenceCompilationSource=('c'*40)}
 $manifest=[ordered]@{SchemaVersion=2;SourceCommit=$source;Origin=$origin;RecipeSha256=(Get-TfCandidateFileHash (Join-Path $candidate 'recipe.json'));FrozenRecipeSha256=('4'*64);ScopeEvidenceSha256=('5'*64);FlowEvidenceSha256=('6'*64);Files=$files}
 Write-TfCandidateJson $manifest (Join-Path $candidate 'manifest.json')
 foreach($file in Get-ChildItem -LiteralPath $candidate -File){[IO.File]::SetUnixFileMode($file.FullName,[IO.UnixFileMode]384)}
 $hash=Get-TfCandidateFileHash (Join-Path $candidate 'manifest.json')
 $null=Assert-TfDiscoveryCandidate -CandidatePath $candidate -CandidateHash $hash
 $state=Join-Path $root state;$null=[IO.Directory]::CreateDirectory($state,[IO.UnixFileMode]448)
 $policy=[ordered]@{SchemaVersion=1;Mode='LocalSoleAdministratorV1';Synthetic=$true;Repository='example/TokenForge';RepositoryId='100';UserId='1';DataBranch='data';SourcePullRequest='40';SourceCommit=$source;PackageManifestSha256=('7'*64);RuntimeInventorySha256=('8'*64);ExpectedPermission='admin';CredentialSource='ExistingSession';JournalRoot=$state;MaxReads=96;MaxDispatches=2;MaxSeconds=600}
 $policyPath=Join-Path $root 'policy.json';Write-TfCandidateJson $policy $policyPath;[IO.File]::SetUnixFileMode($policyPath,[IO.UnixFileMode]384)
 $policySha=Get-TfCandidateFileHash $policyPath
 $baseTreePath=Join-Path $root 'base-tree.json';Write-TfCandidateJson ([ordered]@{sha='4b825dc642cb6eb9a060e54bf8d69288fbee4904';truncated=$false;tree=@()}) $baseTreePath;[IO.File]::SetUnixFileMode($baseTreePath,[IO.UnixFileMode]384)
 $packetPath=Join-Path $root packet
 $options=@{PolicyPath=$policyPath;PolicySha256=$policySha;CandidatePath=$candidate;CandidateHash=$hash;BaseTreePath=$baseTreePath;EvidenceManifestPath=$evidencePath;SelectionPath=$selectionPath;ExpectedParent=$ExpectedParent;UnixSeconds=1760000000L;AuthorName='TokenForge';AuthorEmail='fixture@example.invalid';OutputPath=$packetPath}
 $fixture=@{Root=$root;Candidate=$candidate;CandidateHash=$hash;Manifest=$manifest;Origin=$origin;Validation=$validation;Policy=$policy;PolicyPath=$policyPath;PolicySha256=$policySha;BaseTreePath=$baseTreePath;EvidenceManifestPath=$evidencePath;SelectionPath=$selectionPath;PacketPath=$packetPath;Options=$options;Synthetic=$true;AuthorizationEstablished=$false;Publication='NotAttempted'}
 if($NoPacket -or $Partial){return $fixture}
 $result=New-TokenForgeLocalPublicationPacket @options
 $packet=Read-TfLocalDocument (Join-Path $packetPath 'packet.json') 32KB
 $review=[ordered]@{SchemaVersion=1;Kind='TokenForgeIndependentLocalPublicationReviewV1';PacketSha256=$result.PacketSha256;PolicySha256=$packet.Value.PolicySha256;SourceCommit=$packet.Value.SourceCommit;CandidateHash=$packet.Value.CandidateHash;EvidenceManifestSha256=$packet.Value.EvidenceManifestSha256;SelectionSha256=$packet.Value.SelectionSha256;RepositoryId=$packet.Value.RepositoryId;Ref=$packet.Value.Ref;ExpectedParent=$packet.Value.ExpectedParent;ProposedCommit=$packet.Value.ProposedCommit;ProposedTree=$packet.Value.ProposedTree;ObjectInventorySha256=$packet.Value.ObjectInventorySha256;ReviewInvocation='synthetic:local-packet-fixture';Reviewer='fixture-agent';Decision='Accepted';Findings=@()}
 $reviewPath=Join-Path $root review.json;Write-TfCandidateJson $review $reviewPath;[IO.File]::SetUnixFileMode($reviewPath,[IO.UnixFileMode]384)
 $created=[DateTimeOffset]::Parse('2026-11-06T12:00:00Z')
 $draftOptions=@{PacketPath=$packetPath;PacketSha256=$result.PacketSha256;ReviewPath=$reviewPath;CreatedAt=$created;ExpiresAt=$created.AddMinutes(15);RecoveryUntil=$created.AddHours(1);MaxDispatches=2;Nonce=('e'*32)}
 $draft=New-TokenForgeLocalPublicationApprovalDraft @draftOptions
 $fixture.Packet=$packet.Value;$fixture.PacketSha256=$result.PacketSha256;$fixture.Review=$review;$fixture.ReviewPath=$reviewPath;$fixture.Draft=$draft;$fixture.DraftOptions=$draftOptions
 return $fixture
}
