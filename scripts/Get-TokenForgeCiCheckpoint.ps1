#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory,ParameterSetName='Research')][ValidatePattern('^[a-f0-9]{64}$')][string]$PlanId,[Parameter(ParameterSetName='Research')][ValidateRange(0,100000)][int]$Index,[Parameter(Mandatory,ParameterSetName='Maintenance')][switch]$Maintenance,[Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference='Stop'
$name=if($Maintenance){'maintenance-snapshot-v1'}else{"checkpoint-$PlanId-$Index"}
$fileName=if($Maintenance){'maintenance.sealed'}else{'checkpoint.sealed'}
# Artifact identity is checked before download; encryption additionally binds account/plan/partition.
$response=gh api "repos/$env:GITHUB_REPOSITORY/actions/artifacts?name=$name&per_page=100"
if($LASTEXITCODE -ne 0){throw 'Checkpoint lookup failed.'}
$artifacts=($response|ConvertFrom-Json).artifacts
$latest=@($artifacts|Where-Object {$_.name -ceq $name -and -not $_.expired -and $_.workflow_run.head_branch -ceq 'main'}|Sort-Object created_at -Descending|Select-Object -First 1)
if(-not $latest.Count){return}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-download-'+[guid]::NewGuid())
try{
 gh run download $latest[0].workflow_run.id --repo $env:GITHUB_REPOSITORY --name $name --dir $temp
 if($LASTEXITCODE -ne 0){throw 'Checkpoint download failed.'}
 $files=@(Get-ChildItem $temp -File -Force -Recurse)
 if($files.Count -ne 1 -or $files[0].Name -cne $fileName -or ($files[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -or $files[0].Length -gt 134217757){throw 'Invalid checkpoint artifact.'}
 Copy-Item -LiteralPath $files[0].FullName -Destination $OutputPath
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force}}
