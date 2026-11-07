BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeLocalPublication.ps1"
 . "$PSScriptRoot/fixtures/publication/LocalPublicationFixture.ps1"
}
Describe 'Synthetic local publication packet' {
 BeforeEach {$f=New-LocalPublicationFixture $TestDrive}
 It 'round trips a complete seven-file local-origin packet and creates only a bounded draft' {
  $f.Synthetic | Should -BeTrue
  $f.AuthorizationEstablished | Should -BeFalse
  $f.Publication | Should -BeExactly 'NotAttempted'
  $f.Validation.SelectedPairs | Should -Be 1
  $f.Validation.TerminalCells | Should -Be 1
  $f.Validation.ScopeObservations | Should -Be 1
  $f.Validation.FlowObservations | Should -Be 1
  $f.Validation.PendingCells | Should -Be 0
  $f.Packet.Kind | Should -BeExactly 'TokenForgeLocalPublicationPacketV1'
  $f.Packet.SourceCommit | Should -BeExactly ('a'*40)
  $f.Packet.EvidenceManifestSha256 | Should -BeExactly (Get-TfCandidateFileHash $f.EvidenceManifestPath)
  $f.Packet.SelectionSha256 | Should -BeExactly (Get-TfCandidateFileHash $f.SelectionPath)
  $f.Packet.ExpectedParent | Should -BeExactly ('d'*40)
  $f.Packet.Ref | Should -BeExactly 'refs/heads/data'
  @(Get-ChildItem -LiteralPath (Join-Path $f.PacketPath candidate) -File).Count | Should -Be 7
  $x=Read-TfLocalPacket $f.PacketPath $f.PacketSha256
  $x.Git.ProposedCommit | Should -BeExactly $f.Packet.ProposedCommit
  $x.Pack.Length | Should -BeGreaterThan 100
  $freshScript=Join-Path $f.Root 'fresh-read.ps1'
  [IO.File]::WriteAllText($freshScript,@'
param($SourcePath,$PacketPath,$PacketSha,$CommitSha)
$ErrorActionPreference='Stop'
. $SourcePath
$again=Read-TfLocalPacket $PacketPath $PacketSha
if($again.Git.ProposedCommit -cne $CommitSha){exit 2}
'@)
  $start=[Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
  $start.UseShellExecute=$false
  foreach($arg in @('-NoProfile','-File',$freshScript,(Join-Path $PSScriptRoot '../scripts/TokenForgeLocalPublication.ps1'),$f.PacketPath,$f.PacketSha256,$f.Packet.ProposedCommit)){$start.ArgumentList.Add($arg)}
  $child=[Diagnostics.Process]::Start($start)
  try{if(-not $child.WaitForExit(30000)){$child.Kill($true);throw 'Fresh packet read timeout.'};$child.ExitCode|Should -Be 0}finally{$child.Dispose()}
  $draft=$f.Draft.Body|ConvertFrom-Json -AsHashtable -DateKind String
  $f.Draft.AuthorizationEstablished | Should -BeFalse
  $draft.Decision | Should -BeExactly 'ApproveExactTransaction'
  $draft.MaxDispatches | Should -Be 2
  $draft.CreatedAt | Should -BeExactly '2026-11-06T12:00:00.0000000+00:00'
  $draft.ExpiresAt | Should -BeExactly '2026-11-06T12:15:00.0000000+00:00'
  $draft.RecoveryUntil | Should -BeExactly '2026-11-06T13:00:00.0000000+00:00'
  $draft.PacketSha256 | Should -BeExactly $f.PacketSha256
  $draft.ReviewSha256 | Should -BeExactly (Get-TfCandidateFileHash $f.ReviewPath)
  $text=(@(Get-ChildItem -LiteralPath $f.Candidate -File|ForEach-Object {Get-Content -LiteralPath $_.FullName -Raw}) -join '')+(Get-Content -LiteralPath (Join-Path $f.PacketPath 'packet.json') -Raw)+$f.Draft.Body
  $text | Should -Not -Match 'ProducerRunId|ProducerAttempt|ArtifactId|HostedExecutionProof|AccessToken|TenantFingerprint|PrincipalFingerprint|private-cookie'
  $m=Read-TfCandidateJson (Join-Path $f.Candidate 'manifest.json')
  $m.Origin.Kind | Should -BeExactly 'LocalSnapshotV1'
  @($m.Origin.Keys|Sort-Object) | Should -Be @('EvidenceCompilationSource','EvidenceManifestSha256','EvidencePackageManifestSha256','EvidenceSourceCommit','ExportId','Kind','SelectionSha256')
 }
 It 'refuses a structurally valid but pending candidate before writing a packet' {
  $p=New-LocalPublicationFixture $TestDrive -Partial
  $p.Validation.PendingCells | Should -Be 1
  $options=$p.Options;{New-TokenForgeLocalPublicationPacket @options} | Should -Throw '*Partial candidate refused*'
  Test-Path $p.PacketPath | Should -BeFalse
 }
 It 'refuses wrong source and policy pins before creating a packet' {
  $p=New-LocalPublicationFixture $TestDrive -NoPacket
  $p.Options.PolicySha256='0'*64
  $options=$p.Options;{New-TokenForgeLocalPublicationPacket @options} | Should -Throw '*Policy pin mismatch*'
  $p.Options.PolicySha256=$p.PolicySha256
  $policy=Read-TfCandidateJson $p.PolicyPath;$policy.SourceCommit='f'*40
  Write-TfCandidateJson $policy $p.PolicyPath
  {New-TokenForgeLocalPublicationPacket @options} | Should -Throw
  $p.Options.PolicySha256=Get-TfCandidateFileHash $p.PolicyPath
  {New-TokenForgeLocalPublicationPacket @options} | Should -Throw '*Local candidate/source binding*'
  Test-Path $p.PacketPath | Should -BeFalse
 }
 It 'refuses changed candidate bytes, semantic diff, pack objects and policy custody' {
  $candidateFile=Join-Path $f.PacketPath 'candidate/coverage.json'
  $original=[IO.File]::ReadAllBytes($candidateFile)
  [IO.File]::WriteAllBytes($candidateFile,[byte[]]($original+[Text.Encoding]::ASCII.GetBytes(' ')))
  {Read-TfLocalPacket $f.PacketPath $f.PacketSha256} | Should -Throw
  [IO.File]::WriteAllBytes($candidateFile,$original)
  $diff=Join-Path $f.PacketPath 'semantic-diff.md';$saved=[IO.File]::ReadAllBytes($diff)
  [IO.File]::WriteAllBytes($diff,[byte[]]($saved+[Text.Encoding]::ASCII.GetBytes(' ')))
  {Read-TfLocalPacket $f.PacketPath $f.PacketSha256} | Should -Throw '*Review diff changed*'
  [IO.File]::WriteAllBytes($diff,$saved)
  $packPath=Join-Path $f.PacketPath 'pack.bin';$pack=[IO.File]::ReadAllBytes($packPath)
  $x=Read-TfLocalPacket $f.PacketPath $f.PacketSha256
  $extra=Get-TfLocalGitObject blob ([Text.Encoding]::ASCII.GetBytes('surplus'))
  [IO.File]::WriteAllBytes($packPath,(New-TfLocalGitPack @($x.Git.Objects+$extra|Sort-Object Sha)))
  {Read-TfLocalPacket $f.PacketPath $f.PacketSha256} | Should -Throw
  [IO.File]::WriteAllBytes($packPath,$pack)
  $policyPath=Join-Path $f.PacketPath 'policy.json'
  [IO.File]::WriteAllBytes($policyPath,[byte[]]([IO.File]::ReadAllBytes($policyPath)+[Text.Encoding]::ASCII.GetBytes(' ')))
  {Read-TfLocalPacket $f.PacketPath $f.PacketSha256} | Should -Throw '*Packet policy changed*'
 }
 It 'binds a synthetic review and refuses stale findings or draft durations beyond 15 minutes' {
  $bad=Read-TfCandidateJson $f.ReviewPath;$bad.CandidateHash='f'*64
  Write-TfCandidateJson $bad $f.ReviewPath
  $draftOptions=$f.DraftOptions;{New-TokenForgeLocalPublicationApprovalDraft @draftOptions} | Should -Throw '*Stale independent review*'
  Write-TfCandidateJson $f.Review $f.ReviewPath
  $f.DraftOptions.ExpiresAt=$f.DraftOptions.CreatedAt.AddMinutes(16)
  {New-TokenForgeLocalPublicationApprovalDraft @draftOptions} | Should -Throw '*Approval draft bounds*'
  $f.DraftOptions.ExpiresAt=$f.DraftOptions.CreatedAt.AddMinutes(15)
  $f.DraftOptions.RecoveryUntil=$f.DraftOptions.CreatedAt.AddHours(25)
  {New-TokenForgeLocalPublicationApprovalDraft @draftOptions} | Should -Throw '*Approval draft bounds*'
 }
}
