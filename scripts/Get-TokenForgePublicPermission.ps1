#Requires -Version 7.6
<# .SYNOPSIS
Summarize or filter a public permission snapshot offline; this does not establish consent.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Path,
 [ValidateSet('Delegated','Application')][string]$PermissionType,
 [ValidatePattern('\A[A-Za-z0-9_.:/-]{1,256}\z')][string]$Value,
 [guid]$Id=[guid]::Empty
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicPermissions.ps1)
try{
 $snapshot=Read-TokenForgePermissionFile $Path
 Assert-TokenForgePermissionSnapshot $snapshot
 if(-not $PermissionType -and -not $Value -and $Id -eq [guid]::Empty){
  return [pscustomobject]@{ResourceId=$snapshot.ResourceId;Evidence=$snapshot.Evidence;SourceCommit=$snapshot.Source.Commit;RetrievedAt=$snapshot.RetrievedAt;DelegatedPermissions=$snapshot.Permissions.delegatedScopesList.Count;ApplicationPermissions=$snapshot.Permissions.applicationScopesList.Count}
 }
 foreach($kind in @('Delegated','Application')){
  if($PermissionType -and $PermissionType -ine $kind){continue}
  $key=if($kind -ceq 'Delegated'){'delegatedScopesList'}else{'applicationScopesList'}
  foreach($row in $snapshot.Permissions[$key]){
   if($Value -and $row.value -cne $Value -or $Id -ne [guid]::Empty -and $row.id -cne $Id.ToString()){continue}
   [pscustomobject]@{ResourceId=$snapshot.ResourceId;PermissionType=$kind;SourceCommit=$snapshot.Source.Commit;Definition=[pscustomobject]$row}
  }
 }
}catch{throw 'Public permission snapshot could not be read; details suppressed.'}
