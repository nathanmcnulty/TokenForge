#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputPath,[string]$Dotnet='dotnet')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$project=Join-Path $repo 'native/TokenForge.Credentials/TokenForge.Credentials.csproj'
$names=Get-Content (Join-Path $repo 'src/TokenForge/Core/CredentialSources.json') -Raw|ConvertFrom-Json
$xml=[xml](Get-Content $project -Raw)
$compiled=@($xml.Project.ItemGroup.Compile|ForEach-Object {[IO.Path]::GetFileName($_.Include)})
if(@(Compare-Object $names $compiled).Count){throw 'Credential project and source bootstrap disagree.'}
& $Dotnet build $project --configuration Release '-p:RestoreLockedMode=true' '-p:DebugType=None' '-p:DebugSymbols=false' --nologo
if($LASTEXITCODE){throw 'Credential runtime build failed.'}
$null=New-Item -ItemType Directory $OutputPath -Force
$destination=Join-Path $OutputPath 'TokenForge.Credentials.dll'
Copy-Item (Join-Path $repo 'native/TokenForge.Credentials/bin/Release/net10.0/TokenForge.Credentials.dll') $destination -Force
[pscustomobject]@{Path=$destination;Sha256=(Get-FileHash $destination).Hash.ToLowerInvariant();TargetFramework='net10.0';CredentialDependencies='BCL only'}
