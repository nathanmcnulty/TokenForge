#Requires -Version 7.6
<# .SYNOPSIS
Download a pinned public Graph permission definition snapshot without authentication.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][string]$OutputPath,
 [ValidatePattern('\A[a-f0-9]{40}\z')][string]$SourceCommit='b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a'
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot TokenForgePublicPermissions.ps1)
$temporary=$null;$temporaryCreated=$false
try{
 $target=Resolve-TokenForgePermissionPath $OutputPath
 if(-not $target.EndsWith('.json',[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $target)){throw 'Use a new .json output path.'}
 if(-not $PSCmdlet.ShouldProcess($target,'Download and save a pinned public Graph permission snapshot')){return}
 $source=Get-TokenForgePermissionSourceBytes $SourceCommit
 $permissions=Read-TokenForgePermissionJson $source
 Assert-TokenForgePermissionSource $permissions
 foreach($kind in @('delegatedScopesList','applicationScopesList')){
  $sorted=[Collections.Generic.SortedDictionary[string,object]]::new([StringComparer]::Ordinal)
  foreach($row in $permissions[$kind]){$sorted.Add($row.value+[char]0+$row.id,$row)}
  $permissions[$kind]=@($sorted.Values|ForEach-Object {$_})
 }
 $snapshot=[ordered]@{Format='TokenForgePublicPermissions';SchemaVersion=1;Evidence='PublicSourceDefinitions';ResourceId='00000003-0000-0000-c000-000000000000';RetrievedAt=[DateTimeOffset]::UtcNow.ToString('o');Source=[ordered]@{Repository='https://github.com/microsoftgraph/microsoft-graph-devx-content';Path='permissions/permissions-descriptions.json';Commit=$SourceCommit;RawSha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($source)).ToLowerInvariant()};Permissions=$permissions}
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes((ConvertTo-Json -InputObject $snapshot -Depth 16 -Compress))
 Assert-TokenForgePermissionSnapshot (Read-TokenForgePermissionJson $bytes)
 $temporary=Join-Path ([IO.Path]::GetDirectoryName($target)) ([guid]::NewGuid().ToString()+'.permissions.tmp')
 $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write;$options.Share=[IO.FileShare]::None
 if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
 $output=[IO.FileStream]::new($temporary,$options);$temporaryCreated=$true
 try{$output.Write($bytes);$output.Flush($true)}finally{$output.Dispose()}
 [IO.File]::Move($temporary,$target);$temporary=$null
 [pscustomobject]@{SchemaVersion=1;ResourceId=$snapshot.ResourceId;DelegatedPermissions=$permissions.delegatedScopesList.Count;ApplicationPermissions=$permissions.applicationScopesList.Count;SourceCommit=$SourceCommit;RawSha256=$snapshot.Source.RawSha256;Bytes=$bytes.Length;CredentialOutput=$false}
}catch{throw 'Public Graph permission snapshot could not be created; details suppressed.'}
finally{if($temporaryCreated -and $temporary -and [IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
