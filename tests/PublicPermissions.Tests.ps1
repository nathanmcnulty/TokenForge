BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicPermissions.ps1"
 $save="$PSScriptRoot/../scripts/Save-TokenForgeGraphPermissions.ps1"
 $query="$PSScriptRoot/../scripts/Get-TokenForgePublicPermission.ps1"
 Add-Type -TypeDefinition @'
using System;
using System.IO;
public sealed class PublicPermissionNonseekableStream : MemoryStream {
 public PublicPermissionNonseekableStream(byte[] bytes):base(bytes){}
 public override bool CanSeek => false;
}
'@
}
Describe 'Pinned public permission snapshots' {
 BeforeEach {
  $row=[ordered]@{id='11111111-1111-1111-1111-111111111111';value='User.Read';isAdmin=$false;isEnabled=$true;consentDescription=$null;consentDisplayName='';adminConsentDescription='Public description';adminConsentDisplayName='Public name'}
  $app=[ordered]@{id=$row.id;value=$row.value;isAdmin=$false;isEnabled=$false;consentDescription=$null;consentDisplayName=$null;allowedMemberTypes=@('Application')}
  $permissions=[ordered]@{delegatedScopesList=@($row);applicationScopesList=@($app)}
  $bytes=[Text.Encoding]::UTF8.GetBytes(($permissions|ConvertTo-Json -Depth 10 -Compress))
  $path=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json')
  Mock Get-TokenForgePermissionSourceBytes {return ,$bytes}
 }
 It 'preserves literal flags, nullable labels, omitted fields, and same-name cross-kind permissions' {
  $r=& $save -OutputPath $path
  $r.DelegatedPermissions|Should -Be 1
  $r.ApplicationPermissions|Should -Be 1
  $r.RawSha256|Should -BeExactly ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant())
  $d=Read-TokenForgePermissionFile $path
  $d.Permissions.applicationScopesList[0].isAdmin|Should -BeFalse
  $d.Permissions.applicationScopesList[0].isEnabled|Should -BeFalse
  $d.Permissions.applicationScopesList[0].Contains('adminConsentDescription')|Should -BeFalse
  $d.Permissions.delegatedScopesList[0].consentDescription|Should -BeNullOrEmpty
  $d.Permissions.delegatedScopesList[0].consentDisplayName|Should -BeExactly ''
  @(& $query -Path $path -Value User.Read).Count|Should -Be 2
  @(& $query -Path $path -Value User.Read -PermissionType Application).Count|Should -Be 1
  @(& $query -Path $path -Id $row.id).Count|Should -Be 2
  @(& $query -Path $path -Value user.read).Count|Should -Be 0
  (& $query -Path $path).Evidence|Should -BeExactly PublicSourceDefinitions
 }
 It 'preserves date-looking publisher strings literally' {
  $row.adminConsentDescription='2026-10-15T01:02:03.0000000+05:00'
  $bytes=[Text.Encoding]::UTF8.GetBytes(($permissions|ConvertTo-Json -Depth 10 -Compress))
  $null=& $save -OutputPath $path
  $r=@(& $query -Path $path -Value User.Read -PermissionType delegated)
  $r.Count|Should -Be 1
  $r[0].Definition.adminConsentDescription|Should -BeOfType ([string])
  $r[0].Definition.adminConsentDescription|Should -BeExactly $row.adminConsentDescription
 }
 It 'does not overwrite an existing output or fetch under WhatIf' {
  [IO.File]::WriteAllText($path,'keep')
  {& $save -OutputPath $path}|Should -Throw
  [IO.File]::ReadAllText($path)|Should -BeExactly keep
  Should -Invoke Get-TokenForgePermissionSourceBytes -Times 0
  $null=& $save -OutputPath ($path+'.json') -WhatIf
  Should -Invoke Get-TokenForgePermissionSourceBytes -Times 0
 }
 It 'does not publish malformed, private, mistyped, duplicate, or oversized definitions (<Case>)' -ForEach @(
  @{Case='unknown field';Change={$row.AccessToken='synthetic-private'}},
  @{Case='missing field';Change={$row.Remove('isEnabled')}},
  @{Case='wrong field case';Change={$v=$row.isEnabled;$row.Remove('isEnabled');$row.ISENABLED=$v}},
  @{Case='string flag';Change={$row.isEnabled='true'}},
  @{Case='duplicate ID';Change={$copy=[ordered]@{};foreach($k in $row.Keys){$copy[$k]=$row[$k]};$copy.value='Other.Read';$permissions.delegatedScopesList+=@($copy)}},
  @{Case='duplicate value';Change={$copy=[ordered]@{};foreach($k in $row.Keys){$copy[$k]=$row[$k]};$copy.id='22222222-2222-2222-2222-222222222222';$permissions.delegatedScopesList+=@($copy)}},
  @{Case='unknown member';Change={$app.allowedMemberTypes=@('Tenant')}},
  @{Case='oversized text';Change={$row.consentDescription='a'*8193}},
  @{Case='incomplete labels';Change={$app.adminConsentDescription='partial'}},
  @{Case='ID newline';Change={$row.id+="`n"}},
  @{Case='value newline';Change={$row.value+="`n"}}
 ) {
  . $Change
  $bytes=[Text.Encoding]::UTF8.GetBytes(($permissions|ConvertTo-Json -Depth 10 -Compress))
  {& $save -OutputPath $path}|Should -Throw '*details suppressed*'
  Test-Path $path|Should -BeFalse
  @(Get-ChildItem $TestDrive -Filter '*.permissions.tmp').Count|Should -Be 0
 }
 It 'rejects duplicate JSON properties, bad UTF8, and byte bounds' {
  {Read-TokenForgePermissionJson ([Text.Encoding]::UTF8.GetBytes('{"x":1,"x":2}'))}|Should -Throw
  {Read-TokenForgePermissionJson ([byte[]]@(255))}|Should -Throw
  {Read-TokenForgePermissionJson ([byte[]]::new(4194305))}|Should -Throw
 }
 It 'cleans only its own temporary output when publication fails' {
  Mock Get-TokenForgePermissionSourceBytes {[IO.File]::WriteAllText($path,'racing writer');return ,$bytes}
  {& $save -OutputPath $path}|Should -Throw '*details suppressed*'
  [IO.File]::ReadAllText($path)|Should -BeExactly 'racing writer'
  @(Get-ChildItem $TestDrive -Filter '*.permissions.tmp').Count|Should -Be 0
 }
 It 'rejects linked input and output paths' -Skip:$IsWindows {
  $null=& $save -OutputPath $path
  $link=$path+'.link';$null=New-Item -ItemType SymbolicLink -Path $link -Target $path
  {& $query -Path $link}|Should -Throw
  {& $save -OutputPath $link}|Should -Throw
 }
 It 'rejects provenance arrays and trailing line terminators' {
  $null=& $save -OutputPath $path
  $d=Read-TokenForgePermissionFile $path
  foreach($field in @('Format','Evidence','ResourceId')){
   $original=$d[$field];$d[$field]=@($original,$original)
   {Assert-TokenForgePermissionSnapshot $d}|Should -Throw
   $d[$field]=$original
  }
  foreach($field in @('Repository','Path')){
   $original=$d.Source[$field];$d.Source[$field]=@($original,$original)
   {Assert-TokenForgePermissionSnapshot $d}|Should -Throw
   $d.Source[$field]=$original
  }
  foreach($field in @('Commit','RawSha256')){
   $original=$d.Source[$field];$d.Source[$field]+="`n"
   {Assert-TokenForgePermissionSnapshot $d}|Should -Throw
   $d.Source[$field]=$original
  }
  {& $save -OutputPath ($path+'.json') -SourceCommit (('a'*40)+"`n")}|Should -Throw
 }
 It 'rejects forged provenance and private snapshot fields on read' {
  $null=& $save -OutputPath $path
  $d=Read-TokenForgePermissionFile $path;$d.Source.Repository='https://example.invalid/private'
  $d|ConvertTo-Json -Depth 16 -Compress|Set-Content $path
  {& $query -Path $path}|Should -Throw '*details suppressed*'
  $d.Source.Repository='https://github.com/microsoftgraph/microsoft-graph-devx-content';$d.TenantFingerprint='a'*64
  $d|ConvertTo-Json -Depth 16 -Compress|Set-Content $path
  {& $query -Path $path}|Should -Throw '*details suppressed*'
 }
}
Describe 'Public permission HTTP body bounds' {
 It 'rejects redirects and error statuses (<Status>)' -ForEach @(@{Status=302},@{Status=429},@{Status=500}) {
  param($Status)
  $r=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]$Status)
  try{{Read-TokenForgePermissionHttpBody $r ([Threading.CancellationToken]::None)}|Should -Throw}finally{$r.Dispose()}
 }
 It 'enforces streamed byte limits without Content-Length' {
  $stream=[PublicPermissionNonseekableStream]::new([byte[]]::new(4194305))
  $r=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK);$r.Content=[Net.Http.StreamContent]::new($stream)
  try{
   $r.Content.Headers.ContentLength|Should -BeNullOrEmpty
   {Read-TokenForgePermissionHttpBody $r ([Threading.CancellationToken]::None)}|Should -Throw '*exceeds*'
  }finally{$r.Dispose()}
 }
 It 'honors cancellation while reading the body' {
  $r=[Net.Http.HttpResponseMessage]::new([Net.HttpStatusCode]::OK);$r.Content=[Net.Http.ByteArrayContent]::new([byte[]]@(123,125))
  $cancel=[Threading.CancellationTokenSource]::new();$cancel.Cancel()
  try{{Read-TokenForgePermissionHttpBody $r $cancel.Token}|Should -Throw}finally{$cancel.Dispose();$r.Dispose()}
 }
}
