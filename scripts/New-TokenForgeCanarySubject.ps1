#Requires -Version 7.6
# Initial closed synthetic producer only; no saved archive is normalized/replaced.
[CmdletBinding()]param(
 [Parameter(Mandatory)][string]$Parent,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$Source,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$RunId,
 [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$Attempt
)
$ErrorActionPreference='Stop'
try {
 $dll=Join-Path $PSScriptRoot '../src/TokenForge/lib/net8.0/TokenForge.Credentials.dll'
 if(-not (Test-Path -LiteralPath $dll -PathType Leaf) -or (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant() -cne '30d5d1268223c806e8c6d26fd138ef2f1db58dd23f067f59ac38387e2d7bad32'){throw 'Approved existing runtime required; no source compilation.'}
 . (Join-Path $PSScriptRoot TokenForgeSealer.ps1)
 $parentPath=[IO.Path]::GetFullPath($Parent);Assert-TfCandidateUnlinked $parentPath
 $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $parentPath 'unused'),$false)
 if([int][IO.File]::GetUnixFileMode($parentPath) -ne 448){throw 'Private parent required.'}
 $root=Join-Path $parentPath subject
 if(Test-Path -LiteralPath $root){throw 'New subject required.'}
 $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
 $candidate=Join-Path $root candidate;$null=[IO.Directory]::CreateDirectory($candidate,[IO.UnixFileMode]448)
 # All evidence is fixed synthetic data; no environment, tenant or saved sessions.
 $recipe=@{SchemaVersion=1;Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;Pairs=@(@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';MatrixKnown=$false;Excluded=$false;Cells=@()})}
 $coverage=@{SchemaVersion=1;Pairs=@(@{CellOutcomes=@()})}
 $scopes=@{SchemaVersion=1;Observations=@();Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'}
 $flows=@{Format='TokenForgeAnonymousFlows';SchemaVersion=1;Observations=@();Disclaimer='Account/session/tenant-dependent observations, not universal support or consent.'}
 $validation=Get-TfCandidateValidation $recipe $coverage $scopes $flows
 foreach($entry in @(@{Name='recipe.json';Value=$recipe},@{Name='coverage.json';Value=$coverage},@{Name='scopes.json';Value=$scopes},@{Name='flows.json';Value=$flows},@{Name='validation.json';Value=$validation})){Write-TfCandidateJson $entry.Value (Join-Path $candidate $entry.Name)}
 [IO.File]::WriteAllText((Join-Path $candidate review.md),(Get-TfCandidateReviewText $validation))
 $files=@(Get-ChildItem $candidate -File|Sort-Object Name|ForEach-Object {@{Path=$_.Name;Sha256=(Get-TfCandidateFileHash $_.FullName)}})
 $manifest=@{SchemaVersion=1;SourceCommit=$Source;ProducerRunId=$RunId;ProducerAttempt=$Attempt;RecipeSha256=(Get-TfCandidateFileHash (Join-Path $candidate recipe.json));FrozenRecipeSha256=('1'*64);ScopeEvidenceSha256=('2'*64);FlowEvidenceSha256=('3'*64);Files=$files}
 Write-TfCandidateJson $manifest (Join-Path $candidate manifest.json)
 foreach($file in Get-ChildItem $candidate -File){[IO.File]::SetUnixFileMode($file.FullName,[IO.UnixFileMode]384)}
 $null=Assert-TfDiscoveryCandidate $candidate (Get-TfCandidateFileHash (Join-Path $candidate manifest.json))
 $zip=Join-Path $root original.zip
 $bytes=Get-TfSealerCanonicalZipBytes $candidate
 if($bytes.Length -gt 65536){throw 'Canary subject bound.'}
 [IO.File]::WriteAllBytes($zip,$bytes);[IO.File]::SetUnixFileMode($zip,[IO.UnixFileMode]256)
 $profile=Assert-TfSealerCompleteOriginalZip $zip $candidate
 [ordered]@{Kind='SyntheticCanarySubject';Sha256=(Get-TfCandidateFileHash $zip);Bytes=$bytes.Length;ArchiveProfile=$profile;CompleteOriginalZipPrivacyValidated=$true;BusinessSchemasValidated=$true;OperationalApproval=$false}|ConvertTo-Json -Compress
} catch {Write-Error 'SyntheticCanarySubjectRefused' -ErrorAction Continue;exit 1}
