#Requires -Version 7.4
<# .SYNOPSIS
Create a compact gzip download from a validated public application catalog.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][string]$InputPath,
 [Parameter(Mandatory)][string]$OutputPath,
 [string]$NativeExecutablePath
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
$target=[IO.Path]::GetFullPath($OutputPath)
if(-not $target.EndsWith('.json.gz',[StringComparison]::OrdinalIgnoreCase)){throw 'OutputPath must end in .json.gz.'}
if(Test-Path -LiteralPath $target){throw 'OutputPath already exists; downloads are never overwritten.'}
# Validate once and serialize the same document; never reread an unvalidated source.
$document=Get-TokenForgeApplicationMetadata -Path $InputPath -PublicOnly -NativeExecutablePath $NativeExecutablePath
$json=ConvertTo-Json -InputObject $document -Depth 100 -Compress
$bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($json)
if($bytes.Length -gt 134217728){throw 'Compact catalog exceeds the supported size.'}
if(-not $PSCmdlet.ShouldProcess($target,'Create a public catalog download')){return}
$output=$null;$gzip=$null;$created=$false
try{
 $options=[IO.FileStreamOptions]::new()
 $options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write;$options.Share=[IO.FileShare]::None
 if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite}
 $output=[IO.FileStream]::new($target,$options);$created=$true
 $gzip=[IO.Compression.GZipStream]::new($output,[IO.Compression.CompressionLevel]::SmallestSize,$true)
 $gzip.Write($bytes,0,$bytes.Length);$gzip.Dispose();$gzip=$null
 $output.Flush($true);$size=$output.Length
 $output.Dispose();$output=$null
 [pscustomobject]@{SchemaVersion=1;Applications=$document.Applications.Count;UncompressedBytes=$bytes.Length;CompressedBytes=$size;ContentSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant();CredentialOutput=$false}
}catch{
 if($gzip){$gzip.Dispose();$gzip=$null}
 if($output){$output.Dispose();$output=$null}
 if($created){Remove-Item -LiteralPath $target -Force -ErrorAction SilentlyContinue}
 throw 'Catalog download could not be created; details suppressed.'
}finally{if($gzip){$gzip.Dispose()};if($output){$output.Dispose()}}
