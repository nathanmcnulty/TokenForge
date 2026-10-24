#Requires -Version 7.6
# CanonicalStoredOriginalZipV1: validation reconstruction only. Never substitute
# these bytes for the original service artifact or silently change its identity.
function Get-TfSealerCanonicalZipBytes([string]$CandidatePath) {
 if(-not $IsLinux){throw 'Canonical ZIP profile supports Linux only.'}
 Assert-TfCandidateUnlinked $CandidatePath
 $names=@('coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json')
 $entries=@(Get-ChildItem -LiteralPath $CandidatePath -Force)
 if($entries.Count -ne 7 -or @($entries|Where-Object {$_.PSIsContainer -or $_.Name -cnotin $names}).Count){throw 'Canonical ZIP file set.'}
 $memory=[IO.MemoryStream]::new();$zip=$null;$total=0L
 $records=[Collections.Generic.List[object]]::new()
 try{
  $zip=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true,[Text.Encoding]::UTF8)
  $zip.Comment=''
  foreach($name in $names){
   $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $CandidatePath $name),$false)
   $source=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
   try{
    if($source.Length -lt 1 -or ($total+=$source.Length) -gt 8MB){throw 'Canonical ZIP content bound.'}
    $bytes=[byte[]]::new($source.Length);$source.ReadExactly($bytes,0,$bytes.Length)
    if($source.ReadByte() -ne -1){throw 'Canonical ZIP input changed.'}
   }finally{$source.Dispose()}
   # Reject decoders that could discard/replace input bytes or honor another BOM.
   $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
   if($name.EndsWith('.json',[StringComparison]::Ordinal)){$null=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($text)}
   $entry=$zip.CreateEntry($name,[IO.Compression.CompressionLevel]::NoCompression)
   $entry.LastWriteTime=[DateTimeOffset]::new(1980,1,1,0,0,0,[TimeSpan]::Zero)
   $entry.ExternalAttributes=0;$entry.Comment=''
   $output=$entry.Open();try{$output.Write($bytes,0,$bytes.Length)}finally{$output.Dispose()}
   $records.Add(@{Name=[Text.Encoding]::ASCII.GetBytes($name);Bytes=$bytes;Crc=[uint32]$entry.Crc32;Offset=0})
  }
  $zip.Dispose();$zip=$null
  # Use the trusted BCL only for CRC32 computation. Write the profile ourselves
  # from fixed constants, so writer/library metadata changes cannot widen V1.
  $memory.Dispose();$memory=[IO.MemoryStream]::new()
  $writer=[IO.BinaryWriter]::new($memory,[Text.Encoding]::ASCII,$true)
  function Write-U16([uint16]$Value){$writer.Write($Value)}
  function Write-U32([uint32]$Value){$writer.Write($Value)}
  try{
   foreach($record in $records){
    $record.Offset=[uint32]$memory.Position
    Write-U32 0x04034b50;Write-U16 20;Write-U16 2048;Write-U16 0;Write-U16 0;Write-U16 33
    Write-U32 $record.Crc;Write-U32 $record.Bytes.Length;Write-U32 $record.Bytes.Length
    Write-U16 $record.Name.Length;Write-U16 0;$writer.Write([byte[]]$record.Name);$writer.Write([byte[]]$record.Bytes)
   }
   $central=[uint32]$memory.Position
   foreach($record in $records){
    Write-U32 0x02014b50;Write-U16 788;Write-U16 20;Write-U16 2048;Write-U16 0;Write-U16 0;Write-U16 33
    Write-U32 $record.Crc;Write-U32 $record.Bytes.Length;Write-U32 $record.Bytes.Length
    Write-U16 $record.Name.Length;Write-U16 0;Write-U16 0;Write-U16 0;Write-U16 0;Write-U32 0;Write-U32 $record.Offset
    $writer.Write([byte[]]$record.Name)
   }
   $centralSize=[uint32]($memory.Position-$central)
   Write-U32 0x06054b50;Write-U16 0;Write-U16 0;Write-U16 7;Write-U16 7
   Write-U32 $centralSize;Write-U32 $central;Write-U16 0;$writer.Flush()
   if($memory.Length -gt 8MB){throw 'Canonical ZIP archive bound.'}
   return ,$memory.ToArray()
  }finally{$writer.Dispose()}

 }finally{if($zip){$zip.Dispose()};$memory.Dispose()}
}

function Assert-TfSealerCompleteOriginalZip([string]$Archive,[string]$CandidatePath) {
 $expected=Get-TfSealerCanonicalZipBytes $CandidatePath
 $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve($Archive,$false)
 $input=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 try{
  if($input.Length -ne $expected.Length -or $input.Length -gt 8MB){throw 'Unsupported original ZIP representation.'}
  $actual=[byte[]]::new($input.Length);$input.ReadExactly($actual,0,$actual.Length)
  if($input.ReadByte() -ne -1 -or -not [Linq.Enumerable]::SequenceEqual[byte]($actual,$expected)){throw 'Unsupported original ZIP representation.'}
 }finally{$input.Dispose()}
 'CanonicalStoredOriginalZipV1'
}
