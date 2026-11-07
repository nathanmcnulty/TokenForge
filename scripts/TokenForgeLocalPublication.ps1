#Requires -Version 7.6
# Explicit local mode. Importing this file never authorizes or dispatches publication.
. (Join-Path $PSScriptRoot TokenForgePublicHealth.ps1)
. (Join-Path $PSScriptRoot TokenForgePublicationWriter.ps1)
. (Join-Path $PSScriptRoot TokenForgeLocalPublicationGit.ps1)
. (Join-Path $PSScriptRoot TokenForgeLocalPublicationTransport.ps1)

function Get-TfLocalDigest([byte[]]$Bytes){[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()}
function ConvertTo-TfLocalJsonBytes($Value){,[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $Value -Depth 100 -Compress))}
function Read-TfLocalDocument([string]$Path,[long]$Maximum=4MB){
 $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($Path),$false)
 $f=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($f.Length -lt 1 -or $f.Length -gt $Maximum){throw 'Local publication input bound.'};$b=[byte[]]::new([int]$f.Length);$f.ReadExactly($b);if($f.ReadByte() -ne -1){throw 'Input changed.'};,@{Bytes=$b;Value=(Read-TfPublicationJson $b);Sha256=(Get-TfLocalDigest $b)}}finally{$f.Dispose()}
}
function Write-TfLocalDocument([string]$Path,$Value){
 $b=ConvertTo-TfLocalJsonBytes $Value;$f=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,$true)
 try{$f.Write($b);$f.Flush($true)}finally{$f.Dispose()}
}
function New-TokenForgeLocalPublicationRuntimeInventory {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$OutputPath)
 # Run from the extracted package in a fresh process; no compilation or download.
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 $manifest=Read-TfLocalDocument (Join-Path $root public-health-package.json) 1MB
 $files=[ordered]@{}
 foreach($file in @(Get-ChildItem -LiteralPath $PSHOME -File -Recurse -Force|Sort-Object FullName)){
  Assert-TokenForgeHealthPath $file.FullName
  $files[[IO.Path]::GetRelativePath($PSHOME,$file.FullName)]=[ordered]@{Bytes=$file.Length;Sha256=(Get-TfCandidateFileHash $file.FullName)}
 }
 $value=[ordered]@{SchemaVersion=1;Kind='TokenForgeLocalRuntimeInventoryV1';PackageRoot=$root;PackageManifestSha256=$manifest.Sha256;PowerShellRoot=$PSHOME;PowerShellVersion=$PSVersionTable.PSVersion.ToString();PowerShellFiles=$files}
 Write-TfLocalDocument $OutputPath $value
 @{Path=$OutputPath;Sha256=(Get-TfCandidateFileHash $OutputPath);AuthorizationEstablished=$false}
}
function Assert-TfLocalRuntimeInventory($Doc,$Policy){
 if($Doc.Sha256 -cne $Policy.RuntimeInventorySha256){throw 'Actual runtime inventory pin mismatch.'}
 $v=$Doc.Value;Assert-TfCiKeys $v @('SchemaVersion','Kind','PackageRoot','PackageManifestSha256','PowerShellRoot','PowerShellVersion','PowerShellFiles')
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 if($v.SchemaVersion -ne 1 -or $v.Kind -cne 'TokenForgeLocalRuntimeInventoryV1' -or $v.PackageRoot -cne $root -or $v.PackageManifestSha256 -cne $Policy.PackageManifestSha256 -or $v.PowerShellRoot -cne $PSHOME -or $v.PowerShellVersion -cne $PSVersionTable.PSVersion.ToString()){throw 'Actual package/runtime location or version mismatch.'}
 $m=Read-TfLocalDocument (Join-Path $root public-health-package.json) 1MB
 if($m.Sha256 -cne $Policy.PackageManifestSha256 -or $m.Value.sourceRevision -cne $Policy.SourceCommit -or $m.Value.kind -cne 'TokenForgePublicHealthLinuxPackage' -or $m.Value.files -isnot [Collections.IDictionary]){throw 'Actual package/source pin mismatch.'}
 $actual=@(Get-ChildItem -LiteralPath $root -Recurse -File -Force|ForEach-Object {Assert-TokenForgeHealthPath $_.FullName;[IO.Path]::GetRelativePath($root,$_.FullName)})
 if(@(Compare-Object @(@($m.Value.files.Keys)+'public-health-package.json') $actual).Count){throw 'Actual package membership mismatch.'}
 foreach($key in $m.Value.files.Keys){
  $f=$m.Value.files[$key];$path=Join-Path $root $key
  if((Get-Item -LiteralPath $path).Length -ne $f.bytes -or (Get-TfCandidateFileHash $path) -cne $f.sha256){throw 'Actual package bytes mismatch.'}
 }
 foreach($name in @('TokenForgeLocalPublication.ps1','TokenForgeLocalPublicationGit.ps1','TokenForgeLocalPublicationTransport.ps1','TokenForgePublicationWriter.ps1','TokenForgePublicationAdapter.ps1','TokenForgePublicationRecovery.ps1','TokenForgePublicPermissions.ps1','TokenForgeDiscoveryCandidate.ps1','TokenForgeCiState.ps1','TokenForgeCiEvidenceQueue.ps1','TokenForgePublicHealth.ps1')){if(-not $m.Value.files.Contains('scripts/'+$name)){throw 'Incomplete publisher package.'}}
 if($v.PowerShellFiles -isnot [Collections.IDictionary] -or $v.PowerShellFiles.Count -lt 10 -or $v.PowerShellFiles.Count -gt 10000){throw 'PowerShell inventory bound.'}
 $runtimeFiles=@(Get-ChildItem -LiteralPath $PSHOME -File -Recurse -Force|ForEach-Object {Assert-TokenForgeHealthPath $_.FullName;[IO.Path]::GetRelativePath($PSHOME,$_.FullName)})
 if(@(Compare-Object @($v.PowerShellFiles.Keys) $runtimeFiles).Count){throw 'PowerShell membership changed.'}
 foreach($key in $v.PowerShellFiles.Keys){$f=$v.PowerShellFiles[$key];Assert-TfCiKeys $f @('Bytes','Sha256');$path=Join-Path $PSHOME $key;if((Get-Item -LiteralPath $path).Length -ne $f.Bytes -or (Get-TfCandidateFileHash $path) -cne $f.Sha256){throw 'PowerShell bytes changed.'}}
 # Reuses the approved disk-pair and loaded-assembly/MVID guard from #128.
 Initialize-TokenForgeHealthRuntime (Join-Path $root tokenforge)
}
function Assert-TfLocalPolicy($P){
 Assert-TfCiKeys $P @('SchemaVersion','Mode','Synthetic','Repository','RepositoryId','UserId','DataBranch','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256','ExpectedPermission','CredentialSource','JournalRoot','MaxReads','MaxDispatches','MaxSeconds')
 if($P.Synthetic -isnot [bool]){throw 'Explicit synthetic policy domain required.'}
 if($P.SchemaVersion -ne 1 -or $P.Mode -cne 'LocalSoleAdministratorV1' -or $P.Repository -isnot [string] -or $P.Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $P.DataBranch -isnot [string] -or $P.DataBranch -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$' -or $P.DataBranch -ceq 'main'){throw 'Local mode policy refused.'}
 foreach($n in @('RepositoryId','UserId','SourcePullRequest')){if($P[$n] -isnot [string]){throw 'Policy identity type.'};$null=Get-TfPublicationId $P[$n]}
 Assert-TokenForgePublicationPlanHash $P.SourceCommit -Length 40
 foreach($n in @('PackageManifestSha256','RuntimeInventorySha256')){Assert-TokenForgePublicationPlanHash $P[$n]}
 if($P.ExpectedPermission -cnotin @('write','maintain','admin') -or $P.CredentialSource -isnot [string] -or $P.CredentialSource -cnotmatch '^[A-Za-z0-9_.-]{1,80}$'){throw 'Credential binding refused.'}
 if($P.JournalRoot -isnot [string] -or $P.JournalRoot -cne [IO.Path]::GetFullPath($P.JournalRoot) -or -not [IO.Path]::IsPathFullyQualified($P.JournalRoot)){throw 'Journal root refused.'}
 foreach($n in @('MaxReads','MaxDispatches','MaxSeconds')){if($P[$n] -isnot [int] -and $P[$n] -isnot [long]){throw 'Policy limit type.'}}
 if($P.MaxReads -lt 20 -or $P.MaxReads -gt 96 -or $P.MaxDispatches -lt 1 -or $P.MaxDispatches -gt 2 -or $P.MaxSeconds -lt 10 -or $P.MaxSeconds -gt 600){throw 'Local policy limits refused.'}
}
function Assert-TfLocalCandidateComplete($Candidate,[string]$Hash,$Policy){
 $m=Assert-TfDiscoveryCandidate -CandidatePath $Candidate -CandidateHash $Hash
 if($m.SchemaVersion -ne 2 -or $m.SourceCommit -cne $Policy.SourceCommit){throw 'Local candidate/source binding required.'}
 $v=Read-TfCandidateJson (Join-Path $Candidate validation.json)
 foreach($n in @('UnknownMatrixPairs','InFlightUnknownCells','PendingCells','PausedCells','RequestBlockedCells','TransientFailureCells')){if($v[$n] -ne 0){throw 'Partial candidate refused.'}}
 if($v.SelectedPairs -lt 1 -or $v.ScopeObservations -lt 1 -or $v.FlowObservations -lt 1){throw 'Nonempty assessed candidate required.'}
 return ,$m
}
function Get-TfLocalSemanticDiff($Files,[string]$Hash){
 $recipe=Read-TfPublicationJson $Files['recipe.json'];$scopes=Read-TfPublicationJson $Files['scopes.json'];$flows=Read-TfPublicationJson $Files['flows.json']
 $lines=[Collections.Generic.List[string]]::new()
 $lines.Add("# Proposed immutable snapshot $Hash")
 $lines.Add('')
 $lines.Add('Adds one new seven-file snapshot; removes or modifies no existing paths. Every unrelated Git entry/mode/blob is preserved. This is an account-scoped historical observation, not a universal capability claim or a refreshed assessment.')
 $lines.Add('');$lines.Add('| Added client | Resource | Frozen cells |');$lines.Add('| --- | --- | --- |')
 foreach($pair in $recipe.Pairs){$cells=@($pair.Cells|ForEach-Object {$_.Protocol+':SPA='+$_.Spa}) -join ', ';$lines.Add('| '+$pair.ClientId+' | '+$pair.ResourceId+' | '+$cells+' |')}
 $lines.Add('');$lines.Add('| Added scope observation | Resource | Original observation time | Scopes |');$lines.Add('| --- | --- | --- | --- |')
 foreach($row in $scopes.Observations){$lines.Add('| '+$row.ClientId+' | '+$row.ResourceId+' | '+$row.ObservedAt+' | '+(@($row.Scopes) -join ', ')+' |')}
 $lines.Add('');$lines.Add('| Added flow observation | Resource | Flow | Scopes |');$lines.Add('| --- | --- | --- | --- |')
 foreach($row in $flows.Observations){$lines.Add('| '+$row.ClientId+' | '+$row.ResourceId+' | '+$row.Protocol+':SPA='+$row.Spa+' | '+(@($row.Scopes) -join ', ')+' |')}
 $lines.Add('');$lines.Add([Text.Encoding]::UTF8.GetString($Files['review.md']))
 return ($lines -join "`n")+"`n"
}
function New-TokenForgeLocalPublicationPacket {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PolicyPath,[Parameter(Mandatory)][string]$PolicySha256,[Parameter(Mandatory)][string]$CandidatePath,[Parameter(Mandatory)][string]$CandidateHash,[Parameter(Mandatory)][string]$BaseTreePath,[Parameter(Mandatory)][string]$ExpectedParent,[Parameter(Mandatory)][long]$UnixSeconds,[Parameter(Mandatory)][string]$AuthorName,[Parameter(Mandatory)][string]$AuthorEmail,[Parameter(Mandatory)][string]$OutputPath,[string]$RuntimeInventoryPath,[Parameter(Mandatory)][string]$EvidenceManifestPath,[Parameter(Mandatory)][string]$SelectionPath)
 $p=Read-TfLocalDocument $PolicyPath 16KB;if($p.Sha256 -cne $PolicySha256){throw 'Policy pin mismatch.'};Assert-TfLocalPolicy $p.Value
 $runtime=$null;if(-not $p.Value.Synthetic){$runtime=Read-TfLocalDocument $RuntimeInventoryPath 4MB;Assert-TfLocalRuntimeInventory $runtime $p.Value}
 $m=Assert-TfLocalCandidateComplete $CandidatePath $CandidateHash $p.Value
 $evidence=Read-TfLocalDocument $EvidenceManifestPath 4MB;$selection=Read-TfLocalDocument $SelectionPath 4MB
 if($evidence.Sha256 -cne $m.Origin.EvidenceManifestSha256 -or $selection.Sha256 -cne $m.Origin.SelectionSha256){throw 'Original evidence or selection bytes do not match local origin.'}
 $tree=Read-TfLocalDocument $BaseTreePath;Assert-TfCiKeys $tree.Value @('sha','truncated','tree')
 if($tree.Value.truncated -cne $false -or $tree.Value.tree -isnot [array]){throw 'Complete base tree required.'}
 Assert-TokenForgePublicationPlanHash $ExpectedParent -Length 40
 $files=[ordered]@{};$inventory=@();$total=0
 foreach($n in @('coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json')){
  $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath((Join-Path $CandidatePath $n)),$false)
  $bytes=[IO.File]::ReadAllBytes($path);$total+=$bytes.Length;if($bytes.Length -gt 1MB -or $total -gt 2MB){throw 'Candidate payload bound.'};$files[$n]=$bytes;$inventory+=[ordered]@{Path=$n;Bytes=$bytes.Length;Sha256=(Get-TfLocalDigest $bytes)}
 }
 # Recheck the manifest after the byte snapshot; all accepted files must match it.
 if((Get-TfLocalDigest $files['manifest.json']) -cne $CandidateHash){throw 'Candidate changed.'}
 foreach($entry in $m.Files){if((Get-TfLocalDigest $files[$entry.Path]) -cne $entry.Sha256){throw 'Candidate changed.'}}
 $git=New-TfLocalGitProposal -Parent $ExpectedParent -BaseTreeSha $tree.Value.sha -BaseEntries $tree.Value.tree -Files $files -CandidateHash $CandidateHash -UnixSeconds $UnixSeconds -AuthorName $AuthorName -AuthorEmail $AuthorEmail
 $null=Assert-TfLocalGitPack -Bytes $git.Pack -Objects $git.Objects
 $diff=Get-TfLocalSemanticDiff $files $CandidateHash
 $packet=[ordered]@{SchemaVersion=1;Kind='TokenForgeLocalPublicationPacketV1';PolicySha256=$PolicySha256;Repository=$p.Value.Repository;RepositoryId=$p.Value.RepositoryId;Ref=('refs/heads/'+$p.Value.DataBranch);SourcePullRequest=$p.Value.SourcePullRequest;SourceCommit=$p.Value.SourceCommit;PackageManifestSha256=$p.Value.PackageManifestSha256;RuntimeInventorySha256=$p.Value.RuntimeInventorySha256;EvidenceManifestSha256=$m.Origin.EvidenceManifestSha256;SelectionSha256=$m.Origin.SelectionSha256;CandidateHash=$CandidateHash;ContentInventorySha256=(Get-TfLocalDigest (ConvertTo-TfLocalJsonBytes $inventory));PackSha256=$git.PackSha256;ObjectInventorySha256=$git.InventorySha256;ExpectedParent=$ExpectedParent;BaseTree=$git.BaseTree;ProposedCommit=$git.ProposedCommit;ProposedTree=$git.ProposedTree;UnixSeconds=$UnixSeconds;AuthorName=$AuthorName;AuthorEmail=$AuthorEmail;DiffSha256=(Get-TfLocalDigest ([Text.Encoding]::UTF8.GetBytes($diff)));Files=$inventory}
 $output=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($OutputPath),$false)
 if(Test-Path $output){throw 'Choose a new immutable packet destination.'}
 $parent=Split-Path $output -Parent;$stage=Join-Path $parent ('.publication-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($stage,[IO.UnixFileMode]448)
 try{
  $private=Join-Path $stage private-evidence;$null=[IO.Directory]::CreateDirectory($private,[IO.UnixFileMode]448)
  foreach($item in @(@{Name='evidence-manifest.json';Bytes=$evidence.Bytes},@{Name='selection.json';Bytes=$selection.Bytes})){$f=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $private $item.Name),$true);try{$f.Write($item.Bytes);$f.Flush($true)}finally{$f.Dispose()}}
  $candidate=Join-Path $stage candidate;$null=[IO.Directory]::CreateDirectory($candidate,[IO.UnixFileMode]448)
  foreach($n in $files.Keys){$f=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $candidate $n),$true);try{$f.Write($files[$n]);$f.Flush($true)}finally{$f.Dispose()}}
  if($runtime){$f=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $stage runtime-inventory.json),$true);try{$f.Write($runtime.Bytes);$f.Flush($true)}finally{$f.Dispose()}}
  Write-TfLocalDocument (Join-Path $stage policy.json) $p.Value;Write-TfLocalDocument (Join-Path $stage base-tree.json) $tree.Value
  # Preserve the exact independently supplied policy bytes; its external hash is authoritative.
  [IO.File]::WriteAllBytes((Join-Path $stage policy.json),$p.Bytes)
  foreach($pair in @(@{Name='pack.bin';Bytes=$git.Pack},@{Name='semantic-diff.md';Bytes=[Text.Encoding]::UTF8.GetBytes($diff)})){$f=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $stage $pair.Name),$true);try{$f.Write($pair.Bytes);$f.Flush($true)}finally{$f.Dispose()}}
  Write-TfLocalDocument (Join-Path $stage packet.json) $packet
  [IO.Directory]::Move($stage,$output);$stage=$null
 }finally{if($stage -and (Test-Path $stage)){Remove-Item $stage -Recurse -Force}}
 @{PacketPath=$output;PacketSha256=(Get-TfCandidateFileHash (Join-Path $output packet.json));CandidateHash=$CandidateHash;ProposedCommit=$git.ProposedCommit;AuthorizationEstablished=$false;Publication='NotAttempted'}
}
function Read-TfLocalPacket([string]$Path,[string]$Digest){
 $doc=Read-TfLocalDocument (Join-Path $Path packet.json) 32KB;if($doc.Sha256 -cne $Digest){throw 'Packet pin mismatch.'};$p=$doc.Value
 Assert-TfCiKeys $p @('SchemaVersion','Kind','PolicySha256','Repository','RepositoryId','Ref','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256','EvidenceManifestSha256','SelectionSha256','CandidateHash','ContentInventorySha256','PackSha256','ObjectInventorySha256','ExpectedParent','BaseTree','ProposedCommit','ProposedTree','UnixSeconds','AuthorName','AuthorEmail','DiffSha256','Files')
 if($p.SchemaVersion -ne 1 -or $p.Kind -cne 'TokenForgeLocalPublicationPacketV1'){throw 'Packet version refused.'}
 $policy=Read-TfLocalDocument (Join-Path $Path policy.json) 16KB;if($policy.Sha256 -cne $p.PolicySha256){throw 'Packet policy changed.'};Assert-TfLocalPolicy $policy.Value
 foreach($n in @('Repository','RepositoryId','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256')){if($p[$n] -cne $policy.Value[$n]){throw 'Packet identity changed.'}}
 if($p.Ref -cne ('refs/heads/'+$policy.Value.DataBranch)){throw 'Packet destination changed.'}
 if(-not $policy.Value.Synthetic){Assert-TfLocalRuntimeInventory (Read-TfLocalDocument (Join-Path $Path runtime-inventory.json) 4MB) $policy.Value}
 $m=Assert-TfLocalCandidateComplete (Join-Path $Path candidate) $p.CandidateHash $policy.Value
 foreach($n in @('EvidenceManifestSha256','SelectionSha256')){if($p[$n] -cne $m.Origin[$n]){throw 'Evidence binding changed.'}}
 $evidence=Read-TfLocalDocument (Join-Path $Path private-evidence/evidence-manifest.json) 4MB;$selection=Read-TfLocalDocument (Join-Path $Path private-evidence/selection.json) 4MB
 if($evidence.Sha256 -cne $p.EvidenceManifestSha256 -or $selection.Sha256 -cne $p.SelectionSha256){throw 'Retained evidence or selection changed.'}
 $files=[ordered]@{};$inventory=@();$total=0
 foreach($n in @('coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json')){$bytes=[IO.File]::ReadAllBytes((Join-Path $Path ('candidate/'+$n)));$total+=$bytes.Length;if($bytes.Length -gt 1MB -or $total -gt 2MB){throw 'File bound.'};$files[$n]=$bytes;$inventory+=[ordered]@{Path=$n;Bytes=$bytes.Length;Sha256=(Get-TfLocalDigest $bytes)}}
 if((Get-TfLocalDigest (ConvertTo-TfLocalJsonBytes $inventory)) -cne $p.ContentInventorySha256 -or (Get-TfLocalDigest (ConvertTo-TfLocalJsonBytes $p.Files)) -cne $p.ContentInventorySha256){throw 'Content inventory changed.'}
 $base=Read-TfLocalDocument (Join-Path $Path base-tree.json);Assert-TfCiKeys $base.Value @('sha','truncated','tree');if($base.Value.truncated -cne $false -or $base.Value.sha -cne $p.BaseTree){throw 'Base tree changed.'}
 $git=New-TfLocalGitProposal -Parent $p.ExpectedParent -BaseTreeSha $p.BaseTree -BaseEntries $base.Value.tree -Files $files -CandidateHash $p.CandidateHash -UnixSeconds $p.UnixSeconds -AuthorName $p.AuthorName -AuthorEmail $p.AuthorEmail
 foreach($n in @('ProposedCommit','ProposedTree','PackSha256','ObjectInventorySha256')){$key=if($n -ceq 'ObjectInventorySha256'){'InventorySha256'}else{$n};if($p[$n] -cne $git[$key]){throw 'Proposed content changed.'}}
 $packPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath((Join-Path $Path pack.bin)),$false);if((Get-Item $packPath).Length -gt 8MB){throw 'Pack bound.'};$pack=[IO.File]::ReadAllBytes($packPath);$null=Assert-TfLocalGitPack -Bytes $pack -Objects $git.Objects
 if((Get-TfCandidateFileHash (Join-Path $Path semantic-diff.md)) -cne $p.DiffSha256 -or (Get-TfLocalDigest ([Text.Encoding]::UTF8.GetBytes((Get-TfLocalSemanticDiff $files $p.CandidateHash)))) -cne $p.DiffSha256){throw 'Review diff changed.'}
 ,@{Packet=$p;PacketSha256=$Digest;Policy=$policy.Value;Files=$files;Git=$git;Pack=$pack}
}
function Assert-TfLocalIndependentReview($Review,$Packet,[string]$PacketSha){
 Assert-TfCiKeys $Review @('SchemaVersion','Kind','PacketSha256','PolicySha256','SourceCommit','CandidateHash','EvidenceManifestSha256','SelectionSha256','RepositoryId','Ref','ExpectedParent','ProposedCommit','ProposedTree','ObjectInventorySha256','ReviewInvocation','Reviewer','Decision','Findings')
 if($Review.SchemaVersion -ne 1 -or $Review.Kind -cne 'TokenForgeIndependentLocalPublicationReviewV1' -or $Review.PacketSha256 -cne $PacketSha -or $Review.Decision -cne 'Accepted' -or $Review.Findings -isnot [array] -or $Review.Findings.Count -ne 0){throw 'Accepted independent review required; not publication authority.'}
 foreach($n in @('PolicySha256','SourceCommit','CandidateHash','EvidenceManifestSha256','SelectionSha256','RepositoryId','Ref','ExpectedParent','ProposedCommit','ProposedTree','ObjectInventorySha256')){if($Review[$n] -cne $Packet[$n]){throw 'Stale independent review.'}}
 foreach($n in @('ReviewInvocation','Reviewer')){if($Review[$n] -isnot [string] -or $Review[$n] -cnotmatch '^[A-Za-z0-9_./:-]{1,160}$'){throw 'Review invocation required.'}}
}
function New-TokenForgeLocalPublicationApprovalDraft {
 [CmdletBinding()]param([string]$PacketPath,[string]$PacketSha256,[string]$ReviewPath,[DateTimeOffset]$CreatedAt,[DateTimeOffset]$ExpiresAt,[DateTimeOffset]$RecoveryUntil,[ValidateRange(1,2)][int]$MaxDispatches=1,[string]$Nonce=([guid]::NewGuid().ToString('N')))
 $x=Read-TfLocalPacket $PacketPath $PacketSha256;$review=Read-TfLocalDocument $ReviewPath 16KB;Assert-TfLocalIndependentReview $review.Value $x.Packet $PacketSha256
 if($CreatedAt.Offset -ne [TimeSpan]::Zero -or $ExpiresAt -le $CreatedAt -or ($ExpiresAt-$CreatedAt).TotalSeconds -gt 900 -or $RecoveryUntil -lt $ExpiresAt -or ($RecoveryUntil-$CreatedAt).TotalHours -gt 24 -or $MaxDispatches -gt $x.Policy.MaxDispatches -or $Nonce -cnotmatch '^[a-f0-9]{32}$'){throw 'Approval draft bounds.'}
 $a=[ordered]@{SchemaVersion=1;Kind='TokenForgeSoleAdministratorApprovalV1';Decision='ApproveExactTransaction';Nonce=$Nonce;PacketSha256=$PacketSha256;ReviewSha256=$review.Sha256;ReviewInvocation=$review.Value.ReviewInvocation;UserId=$x.Policy.UserId;ExpectedPermission=$x.Policy.ExpectedPermission;CredentialSource=$x.Policy.CredentialSource;CreatedAt=$CreatedAt.ToString('o');ExpiresAt=$ExpiresAt.ToString('o');RecoveryUntil=$RecoveryUntil.ToString('o');MaxDispatches=$MaxDispatches}
 foreach($n in @('PolicySha256','Repository','RepositoryId','Ref','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256','EvidenceManifestSha256','SelectionSha256','CandidateHash','ContentInventorySha256','PackSha256','ObjectInventorySha256','ExpectedParent','ProposedCommit','ProposedTree')){$a[$n]=$x.Packet[$n]}
 $bytes=ConvertTo-TfLocalJsonBytes $a
 @{Body=[Text.Encoding]::UTF8.GetString($bytes);BodySha256=(Get-TfLocalDigest $bytes);AuthorizationEstablished=$false;Meaning='Draft only. Nathan must post exact bytes himself; independent review or this file grants no authority.'}
}

function Save-TfLocalPublicationState($Context){Save-TfPublicationLedger (Join-Path $Context.Root 'local-publication.json') $Context.Ledger}
function Assert-TfLocalJournalRecord($R,$Policy){
 Assert-TfCiKeys $R @('PacketSha256','PolicySha256','State','Dispatches','Reads','BytesReserved','LastAck','ObservedCommit','VerifiedAt','PendingRead','ApprovalSha256','CommentId','RecoveryUntil','ExecutionDeadline','Attempts','ObjectTransfer','AuthoritySha256')
 if($R.ObjectTransfer -cnotin @('NotAttempted','Unknown','ContentVerified')){throw 'Journal object-transfer state refused.'}
 foreach($n in @('PacketSha256','PolicySha256')){Assert-TokenForgePublicationPlanHash $R[$n]}
 Assert-TokenForgePublicationPlanHash $R.ObservedCommit -Length 40
 if($R.State -cnotin @('Prepared','DispatchStarted','Unknown','UnknownAtParent','Rejected','Consumed','Conflict','ObservedWithoutDispatch','AppliedVerified','AppliedAdvanced') -or $R.LastAck -cnotin @('None','Unknown','Accepted','Rejected')){throw 'Journal status refused.'}
 foreach($n in @('Dispatches','Reads','BytesReserved')){if(($R[$n] -isnot [int] -and $R[$n] -isnot [long]) -or $R[$n] -lt 0){throw 'Journal counter refused.'}}
 if($R.Dispatches -gt 2 -or $R.Reads -gt 96 -or $R.BytesReserved -gt 32MB -or $R.Attempts -isnot [array] -or $R.Attempts.Count -ne $R.Dispatches){throw 'Journal accounting refused.'}
 $null=Read-TokenForgePublicationPlanTime $R.ExecutionDeadline
 if($R.VerifiedAt){$null=Read-TokenForgePublicationPlanTime $R.VerifiedAt}
 if($R.PendingRead){
  Assert-TfCiKeys $R.PendingRead @('Operation','ReservedBytes','StartedAt')
  if($R.PendingRead.Operation -cnotin @('GetUser','GetRepository','GetPermission','GetPullRequest','GetComment','GetComments','GetCommentEdit','GetCommit','GetRef','GetAdvertisement','PostUpdate','GetTree','GetCompare','GetBlob') -or $R.PendingRead.ReservedBytes -le 0 -or $R.PendingRead.ReservedBytes -gt $R.BytesReserved -or $R.Reads -lt 1){throw 'Journal pending charge refused.'}
  $null=Read-TokenForgePublicationPlanTime $R.PendingRead.StartedAt
 }
 if($R.Dispatches -gt 0){
  Assert-TokenForgePublicationPlanHash $R.ApprovalSha256;Assert-TokenForgePublicationPlanHash $R.AuthoritySha256;$null=Get-TfPublicationId $R.CommentId
  $null=Read-TokenForgePublicationPlanTime $R.RecoveryUntil
  if($R.LastAck -ceq 'None'){throw 'Missing dispatch accounting.'}
 }elseif($R.State -cnotin @('Prepared','ObservedWithoutDispatch') -or $R.LastAck -cne 'None' -or $R.ApprovalSha256 -or $R.CommentId -or $R.RecoveryUntil -or $R.AuthoritySha256){throw 'Journal intent mismatch.'}
 for($i=0;$i -lt $R.Attempts.Count;$i++){
  $a=$R.Attempts[$i];Assert-TfCiKeys $a @('Number','StartedAt','Ack')
  if($a.Number -ne $i+1 -or $a.Ack -cnotin @('Unknown','Accepted','Rejected')){throw 'Journal attempt refused.'}
  $null=Read-TokenForgePublicationPlanTime $a.StartedAt
 }
 if($R.Attempts.Count -and $R.Attempts[-1].Ack -cne $R.LastAck){throw 'Journal acknowledgement mismatch.'}
 if($R.PolicySha256 -ceq $Policy.Digest -and ($R.Dispatches -gt $Policy.Value.MaxDispatches -or $R.Reads -gt $Policy.Value.MaxReads)){throw 'Journal policy limits changed.'}
}
function Get-TfLocalNow($Context){if($Context.Synthetic){if($Context.ClockFixture){& $Context.ClockFixture}else{$Context.FixedNow}}else{[DateTimeOffset]::UtcNow}}
function Invoke-TfLocalCharged($C,[string]$Operation,$Arguments=@{}){
 $now=Get-TfLocalNow $C
 if($now -ge $C.DeadlineUtc -or ($C.Stopwatch -and $C.Stopwatch.Elapsed.TotalSeconds -ge $C.MonotonicSeconds) -or $C.Record.Reads -ge $C.Policy.MaxReads){throw 'Local publication read/time budget exhausted.'}
 # Reserve the entire bounded response, retaining it even if the process dies.
 $limit=switch($Operation){'GetTree'{4MB};'GetComments'{512KB};'GetAdvertisement'{2MB};'PostUpdate'{8KB};'GetCommentEdit'{16KB};'GetRef'{16KB};'GetCommit'{64KB};'GetCompare'{1MB};'GetBlob'{
  $object=@($C.X.Git.Objects|Where-Object {$_.Type -ceq 'blob' -and $_.Sha -ceq $Arguments.Sha})
  if($object.Count -ne 1){throw 'Only approved blob reads are allowed.'}
  [int]([Math]::Ceiling($object[0].Bytes.Length*4/3)+4096)
 };default{128KB}}
 $send=if($Operation -ceq 'PostUpdate'){$Arguments.Body.Length}elseif($Operation -ceq 'GetCommentEdit'){1024}else{0}
 if($C.Record.BytesReserved+$limit+$send -gt 32MB){throw 'Local publication byte budget exhausted.'}
 $C.Record.Reads++;$C.Record.BytesReserved+=$limit+$send
 $C.Record.PendingRead=@{Operation=$Operation;ReservedBytes=$limit+$send;StartedAt=$now.ToUniversalTime().ToString('o')}
 Save-TfLocalPublicationState $C
 $C.MaxResponseBytes=$limit;$C.MaxBytes=32MB;$C.FixedNow=$now
 try{$reply=Invoke-TfLocalPublicationTransport $C $Operation $Arguments;$C.Record.PendingRead=$null;Save-TfLocalPublicationState $C;return ,$reply}
 catch{Save-TfLocalPublicationState $C;throw 'Local publication transport refused; retained intent and charges.'}
}
function Assert-TfLocalRemoteActor($C){
 $u=Invoke-TfLocalCharged $C GetUser
 if($u.type -cne 'User' -or (Get-TfPublicationId $u.id) -cne $C.Policy.UserId -or $u.login -isnot [string] -or $u.login -cnotmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'){throw 'Write/read credential principal mismatch.'}
 $repo=Invoke-TfLocalCharged $C GetRepository
 if((Get-TfPublicationId $repo.id) -cne $C.Policy.RepositoryId -or $repo.full_name -cne $C.Policy.Repository -or $repo.private -cne $true -or $repo.visibility -cne 'private' -or $repo.archived -cne $false -or $repo.disabled -cne $false){throw 'Repository identity/visibility changed.'}
 $permission=Invoke-TfLocalCharged $C GetPermission @{Login=$u.login}
 if((Get-TfPublicationId $permission.user.id) -cne $C.Policy.UserId -or $permission.permission -cne $C.Policy.ExpectedPermission){throw 'Credential permission snapshot changed.'}
}
function Assert-TfLocalAuthenticatedApproval($C,$A,[string]$Body,[string]$CommentId){
 Assert-TfLocalRemoteActor $C
 $pr=Invoke-TfLocalCharged $C GetPullRequest @{Number=$C.Policy.SourcePullRequest}
 if((Get-TfPublicationId $pr.number) -cne $C.Policy.SourcePullRequest -or $pr.state -cne 'open' -or $pr.merged -cne $false -or (Get-TfPublicationId $pr.head.repo.id) -cne $C.Policy.RepositoryId -or (Get-TfPublicationId $pr.base.repo.id) -cne $C.Policy.RepositoryId -or $pr.head.sha -cne $C.Policy.SourceCommit){throw 'Source PR identity/head changed.'}
 $comment=Invoke-TfLocalCharged $C GetComment @{CommentId=$CommentId}
 $comments=Invoke-TfLocalCharged $C GetComments @{Number=$C.Policy.SourcePullRequest}
 if($comments -isnot [array]){throw 'Complete comment array required.'}
 if($comments.Count -gt 100 -or $comment.user.type -cne 'User' -or (Get-TfPublicationId $comment.user.id) -cne $C.Policy.UserId -or (Get-TfPublicationId $comment.id) -cne $CommentId -or $comment.issue_url -cne ('https://api.github.com/repos/'+$C.Policy.Repository+'/issues/'+$C.Policy.SourcePullRequest) -or $comment.body -cne $Body -or $comment.updated_at -cne $comment.created_at){throw 'Authenticated exact unedited approval required.'}
 $matches=@($comments|Where-Object {([string]$_.id) -ceq $CommentId})
 if($matches.Count -ne 1){throw 'Incomplete comment stream.'}
 foreach($key in @('id','node_id','issue_url','body','created_at','updated_at')){if([string]$matches[0][$key] -cne [string]$comment[$key]){throw 'Inconsistent comment stream.'}}
 foreach($key in @('id','type','login')){if([string]$matches[0].user[$key] -cne [string]$comment.user[$key]){throw 'Inconsistent comment author.'}}
 foreach($other in $comments){if((Get-TfPublicationId $other.user.id) -ceq $C.Policy.UserId -and [long]$other.id -gt [long]$comment.id){throw 'Approval superseded by later author comment.'}}
 $edit=Invoke-TfLocalCharged $C GetCommentEdit @{NodeId=$comment.node_id}
 if($edit.id -cne $comment.node_id -or -not $edit.Contains('lastEditedAt') -or $null -ne $edit.lastEditedAt){throw 'Edited or unverifiable approval.'}
 $created=Read-TokenForgePublicationPlanTime $A.CreatedAt;$expiry=Read-TokenForgePublicationPlanTime $A.ExpiresAt
 $posted=[DateTimeOffset]::Parse($comment.created_at);$now=Get-TfLocalNow $C
 if($C.ServerDate -and ([DateTimeOffset]$C.ServerDate -lt $created -or [DateTimeOffset]$C.ServerDate -ge $expiry)){throw 'Approval not current at authenticated server time.'}
 if($posted -lt $created -or $posted -gt $expiry -or $now -lt $created -or $now -ge $expiry){throw 'Approval not current.'}
 $parent=Invoke-TfLocalCharged $C GetCommit @{Sha=$C.X.Packet.ExpectedParent}
 if($parent.sha -cne $C.X.Packet.ExpectedParent -or $parent.tree.sha -cne $C.X.Packet.BaseTree){throw 'Immutable parent/tree binding mismatch.'}
 $C.AuthoritySnapshot=[ordered]@{ApprovalComment=$comment;EditMetadata=$edit;Parent=$parent;ObservedAt=$now.ToUniversalTime().ToString('o')}
}
function Assert-TfLocalApprovalDocument($A,$X,$Review,[string]$ReviewSha,[string]$ExpectedSha,[string]$Body){
 $expected=@('SchemaVersion','Kind','Decision','Nonce','PacketSha256','ReviewSha256','ReviewInvocation','UserId','ExpectedPermission','CredentialSource','CreatedAt','ExpiresAt','RecoveryUntil','MaxDispatches','PolicySha256','Repository','RepositoryId','Ref','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256','EvidenceManifestSha256','SelectionSha256','CandidateHash','ContentInventorySha256','PackSha256','ObjectInventorySha256','ExpectedParent','ProposedCommit','ProposedTree')
 Assert-TfCiKeys $A $expected
 if((Get-TfLocalDigest ([Text.UTF8Encoding]::new($false,$true).GetBytes($Body))) -cne $ExpectedSha -or $A.SchemaVersion -ne 1 -or $A.Kind -cne 'TokenForgeSoleAdministratorApprovalV1' -or $A.Decision -cne 'ApproveExactTransaction' -or $A.PacketSha256 -cne $X.PacketSha256 -or $A.ReviewSha256 -cne $ReviewSha -or $A.ReviewInvocation -cne $Review.ReviewInvocation -or $A.Nonce -cnotmatch '^[a-f0-9]{32}$'){throw 'Approval body binding refused.'}
 foreach($n in @('UserId','ExpectedPermission','CredentialSource')){if($A[$n] -cne $X.Policy[$n]){throw 'Approval actor binding refused.'}}
 foreach($n in @('PolicySha256','Repository','RepositoryId','Ref','SourcePullRequest','SourceCommit','PackageManifestSha256','RuntimeInventorySha256','EvidenceManifestSha256','SelectionSha256','CandidateHash','ContentInventorySha256','PackSha256','ObjectInventorySha256','ExpectedParent','ProposedCommit','ProposedTree')){if($A[$n] -cne $X.Packet[$n]){throw 'Stale approval transaction.'}}
 $created=Read-TokenForgePublicationPlanTime $A.CreatedAt;$expires=Read-TokenForgePublicationPlanTime $A.ExpiresAt;$recovery=Read-TokenForgePublicationPlanTime $A.RecoveryUntil
 if(($A.MaxDispatches -isnot [int] -and $A.MaxDispatches -isnot [long]) -or $A.MaxDispatches -lt 1 -or $A.MaxDispatches -gt $X.Policy.MaxDispatches -or $expires -le $created -or ($expires-$created).TotalSeconds -gt 900 -or $recovery -lt $expires -or ($recovery-$created).TotalHours -gt 24){throw 'Approval time/attempt bounds refused.'}
}
function Get-TfLocalRemoteObservation($C){
 Assert-TfLocalRemoteActor $C
 $ref=Invoke-TfLocalCharged $C GetRef
 $p=$C.X.Packet
 if($ref.ref -cne $p.Ref -or $ref.object.type -cne 'commit'){throw 'Remote ref shape changed.'}
 Assert-TokenForgePublicationPlanHash $ref.object.sha -Length 40
 $C.Record.ObservedCommit=$ref.object.sha
 if($ref.object.sha -ceq $p.ExpectedParent){
  if($C.Record.State -cin @('AppliedVerified','AppliedAdvanced','Consumed')){return 'Consumed'}
  if($C.Record.Dispatches -eq 0){return 'Prepared'}
  if($C.Record.LastAck -ceq 'Rejected'){return 'Rejected'}
  return 'UnknownAtParent'
 }
 if($ref.object.sha -cne $p.ProposedCommit){
  $compare=Invoke-TfLocalCharged $C GetCompare @{Base=$p.ProposedCommit;Head=$ref.object.sha}
  if($compare.status -cne 'ahead' -or $compare.merge_base_commit.sha -cne $p.ProposedCommit){return 'Conflict'}
 }
 $commit=Invoke-TfLocalCharged $C GetCommit @{Sha=$p.ProposedCommit}
 if($commit.sha -cne $p.ProposedCommit -or $commit.tree.sha -cne $p.ProposedTree -or $commit.parents -isnot [array] -or $commit.parents.Count -ne 1 -or $commit.parents[0].sha -cne $p.ExpectedParent){throw 'Remote commit binding failed.'}
 $treeSha=$p.ProposedTree
 if($ref.object.sha -cne $p.ProposedCommit){$tip=Invoke-TfLocalCharged $C GetCommit @{Sha=$ref.object.sha};if($tip.sha -cne $ref.object.sha){throw 'Tip binding failed.'};$treeSha=$tip.tree.sha}
 $tree=Invoke-TfLocalCharged $C GetTree @{Sha=$treeSha}
 if($tree.sha -cne $treeSha -or $tree.truncated -cne $false -or $tree.tree -isnot [array] -or $tree.tree.Count -gt 10000){throw 'Complete remote tree required.'}
 if($ref.object.sha -ceq $p.ProposedCommit){
  if($tree.tree.Count -ne $C.X.Git.Entries.Count){throw 'Remote tree membership changed.'}
  foreach($row in $C.X.Git.Entries){$actual=@($tree.tree|Where-Object path -CEQ $row.path);if($actual.Count -ne 1 -or $actual[0].mode -cne $row.mode -or $actual[0].type -cne $row.type -or $actual[0].sha -cne $row.sha){throw 'Unrelated remote entry changed.'}}
 }
 $prefix='candidates/'+$p.CandidateHash+'/'
 $published=@($tree.tree|Where-Object {$_.path.StartsWith($prefix,[StringComparison]::Ordinal)})
 if($published.Count -ne 7){throw 'Remote candidate membership changed.'}
 foreach($n in $C.X.Files.Keys){
  $row=@($published|Where-Object path -CEQ ($prefix+$n))
  $expected=$C.X.Files[$n];$sha=Get-TfPublicationBlobHash $expected
  if($row.Count -ne 1 -or $row[0].mode -cne '100644' -or $row[0].type -cne 'blob' -or $row[0].sha -cne $sha){throw 'Remote candidate path/type changed.'}
  $blob=Invoke-TfLocalCharged $C GetBlob @{Sha=$sha}
  if($blob.sha -cne $sha -or $blob.encoding -cne 'base64' -or $blob.size -ne $expected.Length -or $blob.content -isnot [string]){throw 'Remote blob metadata changed.'}
  try{$bytes=[Convert]::FromBase64String($blob.content)}catch{throw 'Remote blob encoding refused.'}
  if($bytes.Length -ne $expected.Length -or (Get-TfLocalDigest $bytes) -cne (Get-TfLocalDigest $expected)){throw 'Remote content byte verification failed.'}
 }
 # Observe the ref and private repository again; do not assert permanence afterward.
 $again=Invoke-TfLocalCharged $C GetRef
 if($again.ref -cne $p.Ref -or $again.object.type -cne 'commit' -or $again.object.sha -cne $ref.object.sha){throw 'Ref changed during readback; reconcile again.'}
 $repo=Invoke-TfLocalCharged $C GetRepository
 if((Get-TfPublicationId $repo.id) -cne $C.Policy.RepositoryId -or $repo.full_name -cne $C.Policy.Repository -or $repo.private -cne $true -or $repo.visibility -cne 'private'){throw 'Repository changed during readback.'}
 $C.Record.ObjectTransfer='ContentVerified'
 $C.Record.VerifiedAt=(Get-TfLocalNow $C).ToUniversalTime().ToString('o')
 if($C.Record.Dispatches -eq 0){return 'ObservedWithoutDispatch'}
 if($ref.object.sha -ceq $p.ProposedCommit){return 'AppliedVerified'}else{return 'AppliedAdvanced'}
}
function Invoke-TfLocalPublicationOperation {
 [CmdletBinding(DefaultParameterSetName='Synthetic')]param(
  [ValidateSet('Publish','Reconcile')][string]$Action='Publish',[Parameter(Mandatory)][string]$PacketPath,[Parameter(Mandatory)][string]$PacketSha256,
  [string]$ReviewPath,[string]$ApprovalBodyPath,[string]$ApprovedApprovalSha256,[string]$ApprovalCommentId,[switch]$Retry,
  [Parameter(Mandatory,ParameterSetName='Live')][switch]$Live,[Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$GitFixture,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][DateTimeOffset]$FixtureTime,[Parameter(ParameterSetName='Synthetic')][scriptblock]$ClockFixture
 )
 $ErrorActionPreference='Stop';$lock=$null;$ownedToken=$null;$context=$null;$row=$null
 try{
  $x=Read-TfLocalPacket $PacketPath $PacketSha256;$policy=$x.Policy
  if($policy.Synthetic -cne [bool]$Synthetic){throw 'Synthetic policy cannot authorize live execution.'}
  $root=Join-Path $policy.JournalRoot ($policy.RepositoryId+'-'+$policy.DataBranch)
  $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.private'),$true)
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $root '.local-publication.lock'),(-not(Test-Path (Join-Path $root '.local-publication.lock'))))
  foreach($n in @('writer.json','publication.json','.writer.initialized')){if(Test-Path (Join-Path $root $n)){throw 'Separate local-mode custody required; do not bypass legacy history.'}}
  $path=Join-Path $root local-publication.json;$marker=Join-Path $root .local-publication.initialized
  if((Test-Path $marker) -xor (Test-Path $path)){throw 'Missing initialized journal or marker; do not reset.'}
  $ledger=if(Test-Path $path){(Read-TfLocalDocument $path 16KB).Value}else{@{SchemaVersion=1;Mode='LocalSoleAdministratorV1';Synthetic=[bool]$Synthetic;RepositoryId=$policy.RepositoryId;Ref=$x.Packet.Ref;Records=@()}}
  Assert-TfCiKeys $ledger @('SchemaVersion','Mode','Synthetic','RepositoryId','Ref','Records')
  if($ledger.SchemaVersion -ne 1 -or $ledger.Mode -cne 'LocalSoleAdministratorV1' -or $ledger.Synthetic -cne [bool]$Synthetic -or $ledger.RepositoryId -cne $policy.RepositoryId -or $ledger.Ref -cne $x.Packet.Ref -or $ledger.Records -isnot [array] -or $ledger.Records.Count -gt 100){throw 'Journal domain or schema changed.'}
  $seenRecords=@{};foreach($record in $ledger.Records){Assert-TfLocalJournalRecord $record @{Digest=$x.Packet.PolicySha256;Value=$policy};if($seenRecords.ContainsKey($record.PacketSha256)){throw 'Duplicate journal packet.'};$seenRecords[$record.PacketSha256]=$true}
  $found=@($ledger.Records|Where-Object PacketSha256 -CEQ $PacketSha256)
  if($found.Count -gt 1){throw 'Duplicate transaction.'}
  foreach($r in $ledger.Records){if($r.PacketSha256 -cne $PacketSha256 -and $r.State -cin @('DispatchStarted','Unknown','UnknownAtParent','Consumed','Conflict')){throw 'Unresolved repository/ref transaction; recovery only.'}}
  $now=if($Synthetic){if($ClockFixture){&$ClockFixture}else{$FixtureTime}}else{[DateTimeOffset]::UtcNow}
  if($found.Count){$row=$found[0];if($row.PolicySha256 -cne $x.Packet.PolicySha256){throw 'Policy changed; do not reset.'}}
  else{
   if($Action -ceq 'Reconcile'){throw 'Retained transaction intent required.'}
   if($ledger.Records.Count -ge 100){throw 'Journal retention bound; do not reset.'}
   $row=@{PacketSha256=$PacketSha256;PolicySha256=$x.Packet.PolicySha256;State='Prepared';Dispatches=0;Reads=0;BytesReserved=0L;LastAck='None';ObservedCommit=$x.Packet.ExpectedParent;VerifiedAt=$null;PendingRead=$null;ApprovalSha256=$null;CommentId=$null;RecoveryUntil=$null;ExecutionDeadline=$now.AddSeconds($policy.MaxSeconds).ToUniversalTime().ToString('o');Attempts=@();ObjectTransfer='NotAttempted';AuthoritySha256=$null};$ledger.Records+=@($row)
  }
  if($Live){$ownedToken=$AccessToken.Copy()}
  $context=@{X=$x;Policy=$policy;Root=$root;Ledger=$ledger;Record=$row;Synthetic=[bool]$Synthetic;Token=$ownedToken;FixtureRead=$ReadFixture;FixtureGit=$GitFixture;ClockFixture=$ClockFixture;FixedNow=$now;Bytes=0L;ServerDate=$null;DeadlineUtc=if($Action -ceq 'Reconcile'){$now.AddSeconds(60)}else{[DateTimeOffset]::Parse($row.ExecutionDeadline)};MaxResponseBytes=4MB;MaxBytes=32MB}
  if($row.Dispatches -gt 0){
   $retained=Read-TfLocalDocument (Join-Path $root ($PacketSha256+'.authority.json')) 64KB
   if($retained.Sha256 -cne $row.AuthoritySha256 -or (Get-TfLocalDigest ([Text.Encoding]::UTF8.GetBytes([string]$retained.Value.ApprovalBody))) -cne $row.ApprovalSha256 -or [string]$retained.Value.Authority.ApprovalComment.id -cne $row.CommentId){throw 'Missing or changed retained authority.'}
  }
  $context.Stopwatch=[Diagnostics.Stopwatch]::StartNew();$context.MonotonicSeconds=[Math]::Max(0,($context.DeadlineUtc-$now).TotalSeconds)
  Save-TfLocalPublicationState $context
  if(-not(Test-Path $marker)){$f=[TokenForge.Core.V0220.PrivateFiles]::Open($marker,$true);$f.Flush($true);$f.Dispose()}
  if($Action -ceq 'Reconcile' -or $row.State -cin @('AppliedVerified','AppliedAdvanced','Consumed')){
   if(-not $row.RecoveryUntil -or $now -ge [DateTimeOffset]::Parse($row.RecoveryUntil)){throw 'No current recovery-read allowance.'}
   $row.State=Get-TfLocalRemoteObservation $context;Save-TfLocalPublicationState $context
  }else{
   $review=Read-TfLocalDocument $ReviewPath 16KB;Assert-TfLocalIndependentReview $review.Value $x.Packet $PacketSha256
   $approval=Read-TfLocalDocument $ApprovalBodyPath 16KB;$body=[Text.UTF8Encoding]::new($false,$true).GetString($approval.Bytes)
   Assert-TfLocalApprovalDocument $approval.Value $x $review.Value $review.Sha256 $ApprovedApprovalSha256 $body
   $a=$approval.Value;$null=Get-TfPublicationId $ApprovalCommentId
   if($row.ApprovalSha256 -and ($row.ApprovalSha256 -cne $ApprovedApprovalSha256 -or $row.CommentId -cne $ApprovalCommentId)){throw 'Transaction approval cannot be replaced.'}
   if($row.Dispatches -gt 0){
    $row.State=Get-TfLocalRemoteObservation $context;Save-TfLocalPublicationState $context
    if($row.State -cin @('AppliedVerified','AppliedAdvanced','Consumed','Conflict','ObservedWithoutDispatch')){return @{Status=$row.State;PacketSha256=$PacketSha256;ProposedCommit=$x.Packet.ProposedCommit;ObservedCommit=$row.ObservedCommit;VerifiedAt=$row.VerifiedAt;Dispatches=$row.Dispatches;ChargedRequests=$row.Reads;ObjectTransfer=$row.ObjectTransfer;ReservedBytes=$row.BytesReserved;AuthorizationEstablished=(-not $Synthetic -and $null -ne $row.ApprovalSha256);Synthetic=[bool]$Synthetic;Publication=if($row.State -cin @('AppliedVerified','AppliedAdvanced')){if($Synthetic){'SyntheticOnly'}else{'VerifiedRemoteContent'}}else{'UnresolvedOrNotApplied'}}}
    if(-not $Retry -or $row.State -cnotin @('Rejected','UnknownAtParent')){throw 'Explicit reconciled retry required.'}
   }elseif($Retry){throw 'No dispatch to retry.'}
   if($row.Dispatches -ge $a.MaxDispatches){throw 'Approved dispatch allowance exhausted.'}
   Assert-TfLocalAuthenticatedApproval $context $a $body $ApprovalCommentId
   $ref=Invoke-TfLocalCharged $context GetRef
   if($ref.ref -cne $x.Packet.Ref -or $ref.object.type -cne 'commit' -or $ref.object.sha -cne $x.Packet.ExpectedParent){throw 'Stale expected parent; prepare a new review/approval from retained content.'}
   $advertisement=Invoke-TfLocalCharged $context GetAdvertisement
   Assert-TfGitAdvertisement $advertisement $x.Packet.Ref $x.Packet.ExpectedParent
   # Verify actual pinned assets as well as authority immediately before dispatch.
   if(-not $Synthetic){Assert-TfLocalRuntimeInventory (Read-TfLocalDocument (Join-Path $PacketPath runtime-inventory.json) 4MB) $policy}
   Assert-TfLocalAuthenticatedApproval $context $a $body $ApprovalCommentId
   if((Get-TfLocalNow $context) -ge [DateTimeOffset]::Parse($a.ExpiresAt)){throw 'Approval expired before dispatch.'}
   if($row.Dispatches -eq 0){
    $authority=[ordered]@{PacketSha256=$PacketSha256;ApprovalBody=$body;Review=$review.Value;Authority=$context.AuthoritySnapshot}
    $authorityPath=Join-Path $root ($PacketSha256+'.authority.json')
    if(Test-Path $authorityPath){
     $retained=Read-TfLocalDocument $authorityPath 64KB
     if($retained.Value.PacketSha256 -cne $PacketSha256 -or $retained.Value.ApprovalBody -cne $body -or [string]$retained.Value.Authority.ApprovalComment.id -cne $ApprovalCommentId -or $retained.Value.Authority.ApprovalComment.node_id -cne $context.AuthoritySnapshot.ApprovalComment.node_id -or $retained.Value.Authority.ApprovalComment.created_at -cne $context.AuthoritySnapshot.ApprovalComment.created_at -or (Get-TfLocalDigest (ConvertTo-TfLocalJsonBytes $retained.Value.Review)) -cne (Get-TfLocalDigest (ConvertTo-TfLocalJsonBytes $review.Value))){throw 'Conflicting retained authority; do not reset.'}
    }else{Write-TfLocalDocument $authorityPath $authority}
    $row.AuthoritySha256=Get-TfCandidateFileHash $authorityPath
   }
   $row.ApprovalSha256=$ApprovedApprovalSha256;$row.CommentId=$ApprovalCommentId;$row.RecoveryUntil=$a.RecoveryUntil
   $row.Dispatches++;$row.ObjectTransfer='Unknown';$row.State='DispatchStarted';$row.LastAck='Unknown';$row.Attempts+=@{Number=$row.Dispatches;StartedAt=(Get-TfLocalNow $context).ToUniversalTime().ToString('o');Ack='Unknown'}
   Save-TfLocalPublicationState $context
   $bodyBytes=[byte[]]((ConvertTo-TfGitPacket ($x.Packet.ExpectedParent+' '+$x.Packet.ProposedCommit+' '+$x.Packet.Ref+"`0report-status`n"))+[Text.Encoding]::ASCII.GetBytes('0000')+$x.Pack)
   try{$reply=Invoke-TfLocalCharged $context PostUpdate @{Body=$bodyBytes};$row.LastAck=Read-TfGitAcknowledgement $reply $x.Packet.Ref;$row.Attempts[-1].Ack=$row.LastAck}catch{$row.State='Unknown'}
   # Reconcile regardless of ACK status, including definite rejection or local parse failure.
   try{$row.State=Get-TfLocalRemoteObservation $context}catch{$row.State='Unknown'}
   Save-TfLocalPublicationState $context
  }
  @{Status=$row.State;PacketSha256=$PacketSha256;ProposedCommit=$x.Packet.ProposedCommit;ObservedCommit=$row.ObservedCommit;VerifiedAt=$row.VerifiedAt;Dispatches=$row.Dispatches;ChargedRequests=$row.Reads;ObjectTransfer=$row.ObjectTransfer;ReservedBytes=$row.BytesReserved;AuthorizationEstablished=(-not $Synthetic -and $null -ne $row.ApprovalSha256);Synthetic=[bool]$Synthetic;Publication=if($row.State -cin @('AppliedVerified','AppliedAdvanced')){if($Synthetic){'SyntheticOnly'}else{'VerifiedRemoteContent'}}else{'UnresolvedOrNotApplied'}}
 }catch{if($context){try{Save-TfLocalPublicationState $context}catch{}};throw 'Local publication refused; inspect retained local state. No automatic retry, sign-in or recollection.'}
 finally{if($ownedToken){$ownedToken.Dispose()};if($lock){$lock.Dispose()}}
}
function Invoke-TokenForgeLocalPublication {
 [CmdletBinding(DefaultParameterSetName='Synthetic')]param([Parameter(Mandatory)][string]$PacketPath,[Parameter(Mandatory)][string]$PacketSha256,[Parameter(Mandatory)][string]$ReviewPath,[Parameter(Mandatory)][string]$ApprovalBodyPath,[Parameter(Mandatory)][string]$ApprovedApprovalSha256,[Parameter(Mandatory)][string]$ApprovalCommentId,[switch]$Retry,[Parameter(Mandatory,ParameterSetName='Live')][switch]$Live,[Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,[Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$GitFixture,[Parameter(Mandatory,ParameterSetName='Synthetic')][DateTimeOffset]$FixtureTime,[Parameter(ParameterSetName='Synthetic')][scriptblock]$ClockFixture)
 Invoke-TfLocalPublicationOperation -Action Publish @PSBoundParameters
}
function Get-TokenForgeLocalPublicationStatus {
 [CmdletBinding(DefaultParameterSetName='Synthetic')]param([Parameter(Mandatory)][string]$PacketPath,[Parameter(Mandatory)][string]$PacketSha256,[Parameter(Mandatory,ParameterSetName='Live')][switch]$Live,[Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,[Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,[Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$GitFixture,[Parameter(Mandatory,ParameterSetName='Synthetic')][DateTimeOffset]$FixtureTime,[Parameter(ParameterSetName='Synthetic')][scriptblock]$ClockFixture)
 Invoke-TfLocalPublicationOperation -Action Reconcile @PSBoundParameters
}
