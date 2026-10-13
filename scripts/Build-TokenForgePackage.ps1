#Requires -Version 7.4
[CmdletBinding()]
param([string]$OutputPath=(Join-Path $PSScriptRoot '../dist'),[string]$Dotnet='dotnet')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $PSScriptRoot Copy-TokenForgePackageSource.ps1)
$manifest=Test-ModuleManifest (Join-Path $root 'src/TokenForge/TokenForge.psd1')
$null=New-Item -ItemType Directory -Path $OutputPath -Force
$stage=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-package-'+[guid]::NewGuid())
try {
 $null=New-Item -ItemType Directory -Path $stage
 # Tracked source excludes untracked credentials, local state and build caches.
 foreach($prefix in @('src/TokenForge','manifests','docs')) {Copy-TokenForgePackageSource -SourceRoot $root -DestinationRoot $stage -Prefix $prefix}
 foreach($name in @('README.md','SECURITY.md','THIRD-PARTY-NOTICES.md')) {
  Copy-Item -LiteralPath (Join-Path $root $name) -Destination $stage -Recurse
 }
 $null=New-Item -ItemType Directory -Path (Join-Path $stage 'scripts')
 foreach($name in @('tokenforge.ps1','TokenForgeCiState.ps1','Invoke-TokenForge.ps1','Invoke-TokenForgeInventory.ps1','Invoke-TokenForgeLiveComparison.ps1','Export-TokenForgeMaintenanceBackup.ps1')) {Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage 'scripts')}
 $null=New-Item -ItemType Directory -Path (Join-Path $stage 'docs') -Force
 foreach($name in @('native-oauth-validation-2026-10-08.json','vault-core-validation-2026-10-08.json','profile-core-validation-2026-10-10.json','native-profile-validation-2026-10-10.json','vault-file-validation-2026-10-10.json','native-forget-key-validation-2026-10-10.json','timestamp-policy-validation-2026-10-11.json','vault-record-validation-2026-10-11.json','native-vault-inspection-validation-2026-10-11.json','native-logout-validation-2026-10-11.json','native-profile-lifecycle-validation-2026-10-11.json','native-scope-planning-validation-2026-10-11.json','native-request-planning-validation-2026-10-11.json','native-fresh-acquisition-validation-2026-10-11.json','browser-service-validation-2026-10-11.json','native-browser-cli-validation-2026-10-11.json','native-maintenance-backup-validation-2026-10-11.json','native-backup-publication-validation-2026-10-11.json','native-token-policy-validation-2026-10-11.json','private-file-publication-validation-2026-10-11.json','native-profile-browser-validation-2026-10-11.json','native-profile-os-validation-2026-10-11.json','native-software-passkey-validation-2026-10-11.json','native-profile-passkey-validation-2026-10-13.json','native-memory-passkey-validation-2026-10-13.json','native-authentication-validation-2026-10-13.json','native-authentication-hosted-validation-2026-10-13.json','native-passkey-enrollment-validation-2026-10-13.json','weekly-catalog-cycle-2026-10-07.json','weekly-catalog-cycle-2026-10-13.json','private-maintenance-validation-2026-10-07.json','weekly-ci-validation-2026-10-07.json','weekly-usage-observation-2026-10-13.json','research-cohort-validation-2026-10-07.json','sqlite-scope-validation-2026-10-07.json','sqlite-catalog-validation-2026-10-07.json','sqlite-flow-validation-2026-10-06.json','research-catalog-validation-2026-10-06.json','os-vault-validation-2026-10-04.json','native-validation-2026-10-04.json','profile-workflow-validation-2026-10-04.json','live-validation-2026-10-02.json','browser-validation-2026-10-03.json','session-validation-2026-10-03.json','passkey-validation-2026-10-03.json','scope-workflow-validation-2026-10-04.json','preconsent-validation-2026-10-04.json','vault-validation-2026-10-04.json','signin-sweep-validation-2026-10-04.json','application-metadata-validation-2026-10-04.json')) {Copy-Item -LiteralPath (Join-Path $root "docs/$name") -Destination (Join-Path $stage 'docs')}
 $null=& (Join-Path $PSScriptRoot 'Build-TokenForgeCredentials.ps1') -OutputPath (Join-Path $stage 'src/TokenForge/lib/net8.0') -Dotnet $Dotnet
 $archive=Join-Path $OutputPath "TokenForge-$($manifest.Version).zip"
 Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
 $hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
 [IO.File]::WriteAllText("$archive.sha256", "$hash  $([IO.Path]::GetFileName($archive))`n")
 [pscustomobject]@{Path=$archive;Sha256=$hash;Version=$manifest.Version.ToString();Runtime='PowerShell 7.4+'}
} finally {Remove-Item -LiteralPath $stage -Recurse -Force}
