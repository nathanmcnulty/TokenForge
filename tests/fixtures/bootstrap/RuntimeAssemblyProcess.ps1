param([string]$Case,[string]$Root,[string]$Source,[string]$OldNative,[string]$NewNative)
$ErrorActionPreference='Stop'
$moduleRoot=Join-Path $Root module
Copy-Item (Join-Path $Source src/TokenForge) $moduleRoot -Recurse
$lib=Join-Path $moduleRoot lib/net10.0;$null=New-Item -ItemType Directory $lib -Force
$newDll=Join-Path (Split-Path $NewNative -Parent) src/TokenForge/lib/net10.0/TokenForge.Credentials.dll
$oldDll=Join-Path (Split-Path $OldNative -Parent) src/TokenForge/lib/net10.0/TokenForge.Credentials.dll
$dll=Join-Path $lib TokenForge.Credentials.dll
$expectedFailure=$Case -match 'OldThenNew|NewThenOld|SourceThenNew|Replacement'
$direct=$Case.StartsWith('Direct')
$targetNative=$NewNative
if($Case -match 'NewThenOld'){$targetNative=$OldNative}
Copy-Item $(if($Case -match 'NewThenOld'){$oldDll}else{$newDll}) $dll
$scriptDir=Join-Path $Root scripts;$null=New-Item -ItemType Directory $scriptDir
Copy-Item (Join-Path $Source scripts/TokenForgePublicHealth.ps1) $scriptDir
Copy-Item (Join-Path $Source scripts/Invoke-TokenForgePublicHealth.ps1) $scriptDir
# Health expects its module beside scripts. The disk pair can be located elsewhere.
$src=Join-Path $Root src;$null=New-Item -ItemType Directory $src
Move-Item $moduleRoot (Join-Path $src TokenForge);$moduleRoot=Join-Path $src TokenForge;$dll=Join-Path $moduleRoot lib/net10.0/TokenForge.Credentials.dll
if($Case -match 'OldThenNew'){Add-Type -Path $oldDll}
elseif($Case -match 'NewThenOld'){Add-Type -Path $newDll}
elseif($Case -match 'SourceThenNew'){. (Join-Path $Source src/TokenForge/Core/Initialize-Credentials.ps1)}
elseif($Case -match 'IdenticalCopy'){$copy=Join-Path $Root same.dll;Copy-Item $newDll $copy;Add-Type -Path $copy}
elseif($Case -match 'Replacement'){
 Copy-Item $oldDll $dll;Add-Type -Path $dll
 $replacement=Join-Path $Root replacement.dll;Copy-Item $newDll $replacement
 [IO.File]::Move($replacement,$dll,$true)
}
# Warm utility commands before instrumenting real module imports. No identity/hash mocks.
$null=Get-FileHash $dll; $null=@{}|ConvertTo-Json
$global:RuntimeImports=0
$bp=Set-PSBreakpoint -Command Import-Module -Action {$global:RuntimeImports++}
$output=Join-Path $Root output;$failure=$null
try{
 if($direct){Import-Module (Join-Path $moduleRoot TokenForge.psd1) -Force}
 else{
  . (Join-Path $scriptDir TokenForgePublicHealth.ps1)
  if($Case -match 'Replacement'){
   # Use the real new executable and replaced DLL at the SAME package location.
   $targetNative=Join-Path $Root tokenforge;Copy-Item $NewNative $targetNative
  }
  if($expectedFailure){$null=& (Join-Path $scriptDir Invoke-TokenForgePublicHealth.ps1) -OutputPath $output -NativeExecutablePath $targetNative -SourceRevision ('a'*40) -FixturePath (Join-Path $Source tests/fixtures/public-health)}
  else{Initialize-TokenForgeHealthRuntime $targetNative}
 }
 if($Case -match 'Repeated'){
  if($direct){Import-Module (Join-Path $moduleRoot TokenForge.psd1) -Force}else{Initialize-TokenForgeHealthRuntime $targetNative}
 }
 $null=[IO.Directory]::CreateDirectory($output)
}catch{$failure=$_.Exception.Message}
finally{Remove-PSBreakpoint $bp}
$moduleCount=@(Get-Module TokenForge).Count
$r=@{Case=$Case;ExpectedFailure=$expectedFailure;Refused=($null -ne $failure);FreshProcessInstruction=($failure -match 'fresh PowerShell process');OutputExists=(Test-Path $output);ModuleCount=$moduleCount;ModuleImports=$global:RuntimeImports;Version=[TokenForge.Core.CredentialRuntime]::Version;AssemblyName=[TokenForge.Core.CredentialRuntime].Assembly.GetName().Name;Direct=$direct}
$r|ConvertTo-Json -Compress
if($expectedFailure){if(-not $r.Refused -or -not $r.FreshProcessInstruction -or $r.OutputExists -or $moduleCount -ne 0 -or (-not $direct -and $r.ModuleImports -ne 0)){exit 1}}
elseif($r.Refused -or -not $r.OutputExists -or $moduleCount -ne 1){[Console]::Error.WriteLine($failure);exit 1}
