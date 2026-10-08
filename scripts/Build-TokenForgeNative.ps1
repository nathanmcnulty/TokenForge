#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('linux-x64','linux-arm64','win-x64','win-arm64','osx-x64','osx-arm64')][string]$Runtime,
 [string]$OutputPath=(Join-Path $PSScriptRoot '../dist/native'),[string]$Dotnet='dotnet')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$destination=Join-Path $OutputPath $Runtime
if(Test-Path $destination){Remove-Item $destination -Recurse -Force}
& $Dotnet publish (Join-Path $repo 'native/TokenForge.Cli/TokenForge.Cli.csproj') --configuration Release --runtime $Runtime --self-contained true --output $destination '-p:RestoreLockedMode=true' '-p:IncludeNativeLibrariesForSelfExtract=true' '-p:EnableCompressionInSingleFile=true' '-p:DebugType=None' '-p:DebugSymbols=false' --nologo
if($LASTEXITCODE){throw 'Native publish failed.'}
$null=New-Item -ItemType Directory (Join-Path $destination src),(Join-Path $destination scripts) -Force
Copy-Item (Join-Path $repo src/TokenForge) (Join-Path $destination src) -Recurse
Copy-Item (Join-Path $PSScriptRoot tokenforge.ps1) (Join-Path $destination scripts)
Copy-Item (Join-Path $PSScriptRoot TokenForgeCiState.ps1) (Join-Path $destination scripts)
Copy-Item (Join-Path $PSScriptRoot Export-TokenForgeMaintenanceBackup.ps1) (Join-Path $destination scripts)
Copy-Item (Join-Path $repo docs/native-cli.md) (Join-Path $destination README.md)
foreach($name in @('native-cli.md','native-architecture.md','os-backed-vault.md','profiles-and-cli.md','research-catalog.md','sqlite-flow-evidence.md','sqlite-application-catalog.md','sqlite-scope-history.md','research-cohorts.md','weekly-ci.md','private-maintenance.md')){Copy-Item (Join-Path $repo "docs/$name") (Join-Path $destination $name)}
foreach($name in @('weekly-catalog-cycle-2026-10-07.json','weekly-ci-validation-2026-10-07.json','private-maintenance-validation-2026-10-07.json','native-oauth-validation-2026-10-08.json','vault-core-validation-2026-10-08.json')){Copy-Item (Join-Path $repo "docs/$name") $destination}
$exe=Join-Path $destination $(if($Runtime.StartsWith('win-')){'tokenforge.exe'}else{'tokenforge'})
[pscustomobject]@{Runtime=$Runtime;Path=$exe;Sha256=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant();AuthenticationDependency='Profile login and storage: PowerShell 7.4+; token acquire: native';EvidenceDependency='Bundled SQLite'}
