#Requires -Version 7.4
[CmdletBinding()]
param([string]$OutputPath=(Join-Path $PSScriptRoot '../dist'))
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$manifest=Test-ModuleManifest (Join-Path $root 'src/TokenForge/TokenForge.psd1')
$null=New-Item -ItemType Directory -Path $OutputPath -Force
$stage=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-package-'+[guid]::NewGuid())
try {
 $null=New-Item -ItemType Directory -Path $stage
 # Explicit paths exclude caches, Git history, test artifacts, and assessment state.
 foreach($name in @('src','manifests','README.md','SECURITY.md')) {
  Copy-Item -LiteralPath (Join-Path $root $name) -Destination $stage -Recurse
 }
 $null=New-Item -ItemType Directory -Path (Join-Path $stage 'scripts')
 foreach($name in @('Invoke-TokenForge.ps1','Invoke-TokenForgeInventory.ps1','Invoke-TokenForgeLiveComparison.ps1')) {Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage 'scripts')}
 $null=New-Item -ItemType Directory -Path (Join-Path $stage 'docs')
 Get-ChildItem -LiteralPath (Join-Path $root 'docs') -File -Filter '*.md'|Copy-Item -Destination (Join-Path $stage 'docs')
 foreach($name in @('live-validation-2026-10-02.json','browser-validation-2026-10-03.json','session-validation-2026-10-03.json','passkey-validation-2026-10-03.json','scope-workflow-validation-2026-10-04.json','preconsent-validation-2026-10-04.json')) {Copy-Item -LiteralPath (Join-Path $root "docs/$name") -Destination (Join-Path $stage 'docs')}
 $archive=Join-Path $OutputPath "TokenForge-$($manifest.Version).zip"
 Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
 $hash=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
 [IO.File]::WriteAllText("$archive.sha256", "$hash  $([IO.Path]::GetFileName($archive))`n")
 [pscustomobject]@{Path=$archive;Sha256=$hash;Version=$manifest.Version.ToString();Runtime='PowerShell 7.4+'}
} finally {Remove-Item -LiteralPath $stage -Recurse -Force}
