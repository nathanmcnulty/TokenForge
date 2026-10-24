#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ArtifactId)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgeSealer.ps1)
$invocation=@{Repository=$env:TF_REPOSITORY;RepositoryId=$env:TF_REPOSITORY_ID;SourceCommit=$env:TF_SOURCE_COMMIT;RunId=$env:TF_RUN_ID;RunAttempt=$env:TF_RUN_ATTEMPT;Ref=$env:TF_REF;EventName=$env:TF_EVENT;WorkflowRef=$env:TF_WORKFLOW_REF}
if([string]::IsNullOrWhiteSpace($env:TF_READ_TOKEN)){throw 'Explicit hosted read token required.'}
$readToken=ConvertTo-SecureString $env:TF_READ_TOKEN -AsPlainText -Force
Remove-Item Env:TF_READ_TOKEN
$outputPath=New-TfSealerOutputPath $env:RUNNER_TEMP
$result=Get-TokenForgeSealingSubject -Invocation $invocation -ArtifactId $ArtifactId -OutputDirectory $outputPath -AccessToken $readToken
$result|Select-Object Kind,SubjectSha256,CandidateHash,SubjectCount,StructuralValidation,SemanticApproval,SigningPerformed
