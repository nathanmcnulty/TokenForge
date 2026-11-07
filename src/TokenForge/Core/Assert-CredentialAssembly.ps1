# Shared BCL-only check before module import and during direct module initialization.
# This binds loaded module identity to disk bytes; it is not an attestation against
# hostile code already executing in the same process.
function Assert-TokenForgeCredentialAssembly {
 param([Parameter(Mandatory)][Reflection.Assembly]$Assembly,[Parameter(Mandatory)][string]$DllPath,[string]$ExpectedSha256)
 $streams=[Collections.Generic.List[IO.FileStream]]::new()
 try {
  if($Assembly.IsDynamic -or -not $Assembly.Location -or [Runtime.Loader.AssemblyLoadContext]::GetLoadContext($Assembly) -ne [Runtime.Loader.AssemblyLoadContext]::Default){throw 'Unverifiable assembly.'}
  $identity=$Assembly.GetName()
  if($identity.Name -cne 'TokenForge.Credentials' -or $identity.Version.ToString() -cne '0.48.0.0'){throw 'Unexpected identity.'}
  $expected=[IO.Path]::GetFullPath($DllPath)
  $loaded=[IO.Path]::GetFullPath($Assembly.Location)
  foreach($path in @($expected,$loaded)){
   $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
   if($item.PSIsContainer){throw 'Not a file.'}
   for($cursor=$item;$null -ne $cursor;$cursor=if($cursor -is [IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}){if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked runtime path.'}}
   $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$streams.Add($stream)
   $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)).ToLowerInvariant()
   if(-not $ExpectedSha256){$ExpectedSha256=$hash}
   if($hash -cne $ExpectedSha256){throw 'Runtime bytes differ.'}
   $stream.Position=0
   $pe=[Reflection.PortableExecutable.PEReader]::new($stream,[Reflection.PortableExecutable.PEStreamOptions]::LeaveOpen)
   try{
    $reader=[Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe)
    if($Assembly.ManifestModule.ModuleVersionId -ne $reader.GetGuid($reader.GetModuleDefinition().Mvid)){throw 'Loaded module differs.'}
   }finally{$pe.Dispose()}
   # A rename can replace a path while the original inode remains open.
   if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ExpectedSha256){throw 'Runtime path changed.'}
  }
  foreach($type in $Assembly.GetExportedTypes()){
   if($type.FullName.StartsWith('TokenForge.',[StringComparison]::Ordinal)){
    $resolved=$type.FullName -as [type]
    if(-not $resolved -or $resolved.Assembly -ne $Assembly){throw 'Mixed runtime types.'}
   }
  }
 }catch{throw 'The loaded TokenForge credential runtime cannot be verified against the bundled DLL. Start a fresh PowerShell process and use the complete reviewed package.'}
 finally{foreach($stream in $streams){$stream.Dispose()}}
}
