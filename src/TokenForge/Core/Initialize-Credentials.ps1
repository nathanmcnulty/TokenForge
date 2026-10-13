# Shared bootstrap for module and CI state. Credentials never cross a process boundary.
& {
 $expectedVersion='0.39.0'
 $types=@('TokenForge.Core.DiscoverySourceClaims','TokenForge.Core.SoftwarePasskey','TokenForge.Core.SoftwarePasskeySession','TokenForge.Core.CredentialRuntime','TokenForge.Core.ProfileLogin','TokenForge.Core.ProfileLoginResult','TokenForge.Core.MaintenanceBackup','TokenForge.Core.MaintenanceBackupResult','TokenForge.Core.OAuthBrowserAuthorization','TokenForge.Core.BrowserAuthorization','TokenForge.Core.ScopePlanning','TokenForge.Core.ProfileScopeAcquisition','TokenForge.Core.ProfileTokenApi','TokenForge.Core.ProfileTokenLifecycle','TokenForge.Core.ProfileCredentialToken','TokenForge.Core.ProfileStore','TokenForge.Core.VaultInspection',
  'TokenForge.Core.V0250.VaultRecordPolicy','TokenForge.Core.V0240.TimestampPolicy','TokenForge.Core.V0230.ProfileKeyIdentity',
  'TokenForge.Core.V0220.PrivateFiles','TokenForge.Core.V0220.VaultFileTransaction','TokenForge.Core.V0200.ProfilePolicy',
  'TokenForge.Core.V0190.VaultEnvelope','TokenForge.Core.V0100.TokenPolicy','TokenForge.Core.V0110.PlatformVaultKey','TokenForge.Core.V0180.OAuthTransport')
 $dll=Join-Path $PSScriptRoot '../lib/net8.0/TokenForge.Credentials.dll'
 if(Test-Path -LiteralPath $dll){
  try{$identity=[Reflection.AssemblyName]::GetAssemblyName($dll);if($identity.Name -cne 'TokenForge.Credentials' -or $identity.Version.ToString() -cne ($expectedVersion+'.0')){throw 'Identity mismatch.'}}
  catch{throw 'Bundled TokenForge credential runtime is invalid. Reinstall the package; source fallback is disabled for an existing DLL.'}
 }
 $marker='TokenForge.Core.CredentialRuntime' -as [type]
 if($marker -and (Test-Path -LiteralPath $dll) -and $marker.Assembly.GetName().Name -cne 'TokenForge.Credentials'){throw 'A source-compiled credential runtime is already loaded. Start a fresh PowerShell process to use the packaged DLL.'}
 if(-not $marker){
  if(@($types|Where-Object {$_ -as [type]}).Count){throw 'An incompatible TokenForge credential runtime is already loaded. Start a fresh PowerShell process.'}
  if(Test-Path -LiteralPath $dll){
   try{Add-Type -Path $dll -ErrorAction Stop}catch{throw 'Bundled TokenForge credential runtime could not load. Reinstall the package; source fallback is disabled for an existing DLL.'}
  }else{
   $names=Get-Content (Join-Path $PSScriptRoot CredentialSources.json) -Raw|ConvertFrom-Json
   $actual=@(Get-ChildItem $PSScriptRoot -File -Filter '*.cs'|ForEach-Object Name|Sort-Object)
   if(@(Compare-Object $names $actual).Count){throw 'TokenForge credential source list is incomplete.'}
   $paths=@($names|ForEach-Object {Join-Path $PSScriptRoot $_})
   Add-Type -Path $paths -CompilerOptions '/nullable:enable' -ErrorAction Stop
  }
  $marker='TokenForge.Core.CredentialRuntime' -as [type]
 }
 if(-not $marker -or $marker::Version -cne $expectedVersion -or @($types|Where-Object {$t=$_ -as [type];-not $t -or $t.Assembly -ne $marker.Assembly}).Count){
  throw 'An incompatible TokenForge credential runtime is already loaded. Start a fresh PowerShell process.'
 }
}
