#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$AssetPath,[Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
 [ValidateSet('linux-x64','linux-arm64','win-x64','win-arm64','osx-x64','osx-arm64')][string[]]$Runtime=@('linux-x64','linux-arm64','win-x64','win-arm64','osx-x64','osx-arm64'))
$ErrorActionPreference='Stop'
$root=(Get-Item -LiteralPath $AssetPath -Force)
if(-not $root.PSIsContainer -or $root.LinkType){throw 'Release assets must be a regular directory.'}
$runtimes=@($Runtime|ForEach-Object ToLowerInvariant)
if(-not $runtimes.Count -or @($runtimes|Sort-Object -Unique).Count -ne $runtimes.Count){throw 'Choose a nonempty unique runtime set.'}
$expected=@($runtimes|ForEach-Object { $extension=if($_.StartsWith('win-')){'zip'}else{'tar.gz'}; "TokenForge-$Version-$_.${extension}"; "TokenForge-$Version-$_.${extension}.json" })
$files=@(Get-ChildItem -LiteralPath $root.FullName -Force)
if($files.Count -ne $expected.Count){if($runtimes.Count -eq 6){throw 'Release must contain exactly six archives and six receipts.'};throw 'Release must contain exactly the selected archives and receipts.'}
foreach($file in $files){if($file.PSIsContainer -or $file.LinkType -or $file.Name -cnotin $expected){throw 'Unexpected release asset.'}}
$entries=@(foreach($selectedRuntime in $runtimes){
 $extension=if($selectedRuntime.StartsWith('win-')){'zip'}else{'tar.gz'}
 $name="TokenForge-$Version-$selectedRuntime.$extension"
 $file=Get-Item -LiteralPath (Join-Path $root.FullName $name)
 if($file.Length -le 0 -or $file.Length -gt 512MB){throw 'Release archive size is outside its bound.'}
 $receipt=Get-Item -LiteralPath "$($file.FullName).json"
 if($receipt.Length -gt 16KB){throw 'Release receipt is too large.'}
 $text=[Text.UTF8Encoding]::new($false,$true).GetString([IO.File]::ReadAllBytes($receipt.FullName))
 if($text.StartsWith([string][char]0xfeff,[StringComparison]::Ordinal)){$text=$text.Substring(1)}
 $document=[Text.Json.JsonDocument]::Parse([string]$text,[Text.Json.JsonDocumentOptions]::new())
 try{
  if($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object){throw 'Invalid release receipt JSON.'}
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($property in $document.RootElement.EnumerateObject()){if(-not $seen.Add($property.Name)){throw 'Duplicate release receipt field.'}}
 }finally{$document.Dispose()}
 $record=$text|ConvertFrom-Json
 $fields=@($record.PSObject.Properties.Name)
 if($fields.Count -ne 6 -or @('SchemaVersion','Runtime','Version','SourceCommit','Archive','Sha256'|Where-Object {$_ -cnotin $fields}).Count){throw 'Unexpected release receipt schema.'}
 if($record.SchemaVersion -isnot [long] -or @('Runtime','Version','SourceCommit','Archive','Sha256'|Where-Object {$record.$_ -isnot [string]}).Count){throw 'Unexpected release receipt field types.'}
 $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
 if($record.SchemaVersion -ne 1 -or $record.Runtime -cne $selectedRuntime -or $record.Version -cne $Version -or $record.SourceCommit -cne $SourceCommit -or $record.Archive -cne $name -or $record.Sha256 -cne $hash){throw 'Release receipt does not match its expected source and archive.'}
 [pscustomobject]@{Runtime=$selectedRuntime;Archive=$name;Sha256=$hash;Bytes=$file.Length}
})
[pscustomobject]@{SchemaVersion=1;Version=$Version;SourceCommit=$SourceCommit;Archives=$entries}
