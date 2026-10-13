#Requires -Version 7.4
# Build input is a Git checkout. Copy tracked source files, never local state.
function Copy-TokenForgePackageSource {
 [CmdletBinding()]
 param([Parameter(Mandatory)][string]$SourceRoot,[Parameter(Mandatory)][string]$DestinationRoot,
  [Parameter(Mandatory)][ValidateSet('src/TokenForge','manifests','docs')][string]$Prefix)
 $ErrorActionPreference='Stop'
 $source=[IO.Path]::GetFullPath($SourceRoot)
 $destination=[IO.Path]::GetFullPath($DestinationRoot)
 $start=[Diagnostics.ProcessStartInfo]::new('git')
 $start.StandardOutputEncoding=[Text.UTF8Encoding]::new($false,$true)
 $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 foreach($argument in @('-C',$source,'ls-files','--cached','-z','--',"$Prefix/")){$start.ArgumentList.Add($argument)}
 $process=[Diagnostics.Process]::Start($start)
 try{
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Package source discovery timed out.'}
  if($process.ExitCode){throw 'Package source requires a readable Git checkout.'}
  try{$tracked=$stdout.GetAwaiter().GetResult()}catch{throw 'Package source listing must use valid UTF-8.'}
  if($tracked.Length -gt 4194304){throw 'Package source listing exceeded its bound.'}
 }finally{$process.Dispose()}
 $paths=@($tracked.Split([char]0,[StringSplitOptions]::RemoveEmptyEntries))
 if(-not $paths.Count){throw 'Required package source files are missing.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($relative in $paths){
  if(-not $relative.StartsWith("$Prefix/",[StringComparison]::Ordinal) -or $relative -match '[\\\x00-\x1f\x7f]' -or ($relative.Split('/') | Where-Object {$_ -in @('','.', '..')}).Count -gt 0 -or -not $seen.Add($relative)){throw 'Invalid package source path.'}
  if($Prefix -eq 'docs' -and -not $relative.EndsWith('.md',[StringComparison]::Ordinal)){continue}
  $sourceFile=Join-Path $source $relative
  for($part=$sourceFile;$part;$part=[IO.Path]::GetDirectoryName($part)){
   $item=Get-Item -LiteralPath $part -Force
   if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Package source paths must not contain links.'}
   if($part -eq $source){break}
  }
  if(-not [IO.File]::Exists($sourceFile)){throw 'Required package source must be a regular file.'}
  $targetFile=Join-Path $destination $relative
  $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($targetFile)) -Force
  Copy-Item -LiteralPath $sourceFile -Destination $targetFile
 }
}
