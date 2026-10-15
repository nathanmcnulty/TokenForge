#Requires -Version 7.4
<# .SYNOPSIS
Compare a public application catalog with Graph permission identifiers offline.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$CatalogPath,
 [Parameter(Mandatory)][string]$PermissionSnapshotPath,
 [string]$NativeExecutablePath,
 [switch]$IncludeMatches
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicPermissions.ps1)
try{
 $catalogFile=Resolve-TokenForgePermissionPath $CatalogPath
 if(-not (Test-Path -LiteralPath $catalogFile -PathType Leaf)){throw 'Catalog must be an existing regular file.'}
 $snapshot=Read-TokenForgePermissionFile $PermissionSnapshotPath
 Assert-TokenForgePermissionSnapshot $snapshot
 Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -Verbose:$false -WarningAction SilentlyContinue
 # Validate the complete ledger, including history, before selecting or returning identifiers.
 $catalog=Get-TokenForgeApplicationMetadata -Path $catalogFile -PublicOnly -NativeExecutablePath $NativeExecutablePath
 $matches=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
 $delegated=0;$application=0
 foreach($kind in @('Delegated','Application')){
  $key=if($kind -ceq 'Delegated'){'delegatedScopesList'}else{'applicationScopesList'}
  foreach($definition in $snapshot.Permissions[$key]){
   if(-not $catalog.Applications.Contains($definition.id)){continue}
   if(-not $matches.ContainsKey($definition.id)){$matches.Add($definition.id,[Collections.Generic.List[object]]::new())}
   $matches[$definition.id].Add([ordered]@{PermissionType=$kind;Value=$definition.value})
   if($kind -ceq 'Delegated'){$delegated++}else{$application++}
  }
 }
 $hash={param($value)
  $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $value -Depth 100 -Compress))
  [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
 }
 $result=[ordered]@{
  Format='TokenForgePermissionIdentifierComparison';SchemaVersion=1;Evidence='PublicIdentifierOverlap'
  Catalog=[ordered]@{UpdatedAt=$catalog.UpdatedAt;Identifiers=$catalog.Applications.Count;ContentSha256=(& $hash $catalog);HashKind='ValidatedCompactJson'}
  PermissionSnapshot=[ordered]@{ResourceId=$snapshot.ResourceId;RetrievedAt=$snapshot.RetrievedAt;Source=$snapshot.Source;ContentSha256=(& $hash $snapshot);HashKind='ValidatedCompactJson'}
  Counts=[ordered]@{MatchedIdentifiers=$matches.Count;UnmatchedCatalogIdentifiers=($catalog.Applications.Count-$matches.Count);MatchedDefinitions=($delegated+$application);DelegatedDefinitions=$delegated;ApplicationDefinitions=$application}
 }
 if($IncludeMatches){
  $rows=[Collections.Generic.List[object]]::new()
  foreach($pair in $matches.GetEnumerator()){
   $definitions=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
   foreach($row in $pair.Value){$definitions.Add($row.PermissionType+[char]0+$row.Value,$row)}
   $rows.Add([ordered]@{Id=$pair.Key;Definitions=@($definitions.Values)})
  }
  $result.Matches=$rows.ToArray()
 }
 [pscustomobject]$result
}catch{throw 'Public permission identifier comparison failed; details suppressed.'}
