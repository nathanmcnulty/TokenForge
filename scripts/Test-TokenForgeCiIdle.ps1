#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$DataPath,
 [Parameter(Mandatory)][string]$EventName,
 [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow
)
$ErrorActionPreference='Stop'
# Manual runs always refresh sources and use the normal publication validators.
if($EventName -cne 'schedule'){return $false}
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
$week=Get-TfCiWeek $Now
foreach($mode in @('Shallow','Deep')){
 $path=Join-Path $DataPath ('weekly-'+$mode.ToLowerInvariant()+'.json')
 if(-not(Test-Path -LiteralPath $path)){return $false}
 $file=Get-Item -LiteralPath $path
 if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 134217728){throw 'Invalid idle-check state file.'}
 $state=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -AsHashtable -Depth 100
 $report=Get-TfCiReport $state -Now $Now
 if($report.Mode -cne $mode){throw 'Idle-check state mode mismatch.'}
 $created=[DateTimeOffset]::Parse($state.Recipe.CreatedAt)
 if($created -gt $Now.AddMinutes(5) -or (Get-TfCiWeek $created) -cne $report.Week){throw 'Invalid idle-check recipe date.'}
 if($report.Week -cne $week -or -not $report.Complete){return $false}
}
$metadata=Join-Path $DataPath applications.json
if(-not(Test-Path -LiteralPath $metadata)){return $false}
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
$catalog=Get-TokenForgeApplicationMetadata $metadata -PublicOnly
if(-not $catalog.Origins.Contains('Discovery///')){return $false}
$origin=$catalog.Origins['Discovery///']
# Require a matching completed source observation, not merely today's import date.
$run=@($catalog.Runs|Where-Object {$_.Id -ceq $origin.LastRunId -and $_.Kind -ceq 'Discovery'})
if($run.Count -ne 1){throw 'Idle-check discovery run mismatch.'}
$observed=[DateTimeOffset]::Parse($origin.LastObservedAt)
if($observed -ne [DateTimeOffset]::Parse($run[0].ObservedAt) -or $observed -gt $Now){throw 'Invalid idle-check discovery date.'}
$observed.UtcDateTime.Date -eq $Now.UtcDateTime.Date
