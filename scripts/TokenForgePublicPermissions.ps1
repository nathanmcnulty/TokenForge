# Shared, offline validation for the fixed public Graph source and its snapshots.
# No TokenForge module, authentication provider, or native executable is loaded.
function ConvertFrom-TokenForgePermissionElement {
 param([Text.Json.JsonElement]$Element)
 switch($Element.ValueKind){
  Object {
   $value=[Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
   foreach($property in $Element.EnumerateObject()){
    if($value.Contains($property.Name)){throw 'Duplicate public permission JSON field.'}
    $value.Add($property.Name,(ConvertFrom-TokenForgePermissionElement $property.Value))
   }
   return $value
  }
  Array {
   $value=[Collections.Generic.List[object]]::new()
   foreach($item in $Element.EnumerateArray()){$value.Add((ConvertFrom-TokenForgePermissionElement $item))}
   return ,$value.ToArray()
  }
  String {return $Element.GetString()}
  Number {return $Element.GetInt64()}
  True {return $true}
  False {return $false}
  Null {return $null}
  default {throw 'Invalid public permission JSON value.'}
 }
}
function Read-TokenForgePermissionJson {
 param([byte[]]$Bytes)
 if($Bytes.Length -gt 4194304){throw 'Public permission input exceeds 4 MiB.'}
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
 $options=[Text.Json.JsonDocumentOptions]::new();$options.MaxDepth=16
 $doc=[Text.Json.JsonDocument]::Parse($text,$options)
 try{ConvertFrom-TokenForgePermissionElement $doc.RootElement}finally{$doc.Dispose()}
}
function Assert-TokenForgePermissionFields {
 param($Object,[string[]]$Required,[string[]]$Optional=@())
 if($Object -isnot [Collections.IDictionary]){throw 'Expected a public permission object.'}
 $keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($key in $Required+$Optional){$null=$keys.Add($key)}
 foreach($key in $Object.Keys){if(-not $keys.Contains($key)){throw 'Unknown public permission field.'}}
 foreach($key in $Required){if(-not $Object.Contains($key)){throw 'Missing public permission field.'}}
}
function Assert-TokenForgePermissionSource {
 param($Permissions)
 Assert-TokenForgePermissionFields $Permissions @('delegatedScopesList','applicationScopesList')
 foreach($kind in @('delegatedScopesList','applicationScopesList')){
  $rows=$Permissions[$kind]
  if($rows -isnot [array] -or $rows.Count -lt 1 -or $rows.Count -gt 10000){throw 'Invalid public permission collection.'}
  $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $values=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($row in $rows){
   $required=@('id','value','isAdmin','isEnabled','consentDescription','consentDisplayName')
   if($kind -ceq 'delegatedScopesList'){$required+=@('adminConsentDescription','adminConsentDisplayName')}
   else{$required+='allowedMemberTypes'}
   $optional=if($kind -ceq 'applicationScopesList'){@('adminConsentDescription','adminConsentDisplayName')}else{@()}
   Assert-TokenForgePermissionFields $row $required $optional
   if($row.id -isnot [string] -or $row.id -cnotmatch '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' -or $row.id -ceq [guid]::Empty.ToString()){throw 'Invalid public permission ID.'}
   if($row.value -isnot [string] -or $row.value -cnotmatch '\A[A-Za-z0-9_.:/-]{1,256}\z'){throw 'Invalid public permission value.'}
   if(-not $ids.Add($row.id) -or -not $values.Add($row.value)){throw 'Duplicate public permission ID or value within a kind.'}
   foreach($field in @('isAdmin','isEnabled')){if($row[$field] -isnot [bool]){throw 'Invalid public permission flag.'}}
   foreach($field in @('adminConsentDescription','adminConsentDisplayName','consentDescription','consentDisplayName')){
    if($row.Contains($field) -and $null -ne $row[$field] -and ($row[$field] -isnot [string] -or $row[$field].Length -gt 8192 -or $row[$field] -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')){throw 'Invalid public permission text.'}
   }
   if($kind -ceq 'applicationScopesList'){
    if($row.Contains('adminConsentDescription') -ne $row.Contains('adminConsentDisplayName')){throw 'Incomplete public permission labels.'}
    if($row.allowedMemberTypes -isnot [array] -or $row.allowedMemberTypes.Count -lt 1 -or $row.allowedMemberTypes.Count -gt 2){throw 'Invalid public permission member types.'}
    $members=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($member in $row.allowedMemberTypes){if($member -isnot [string] -or $member -cnotin @('Application','User') -or -not $members.Add($member)){throw 'Invalid public permission member type.'}}
   }
  }
 }
}
function Assert-TokenForgePermissionSnapshot {
 param($Snapshot)
 Assert-TokenForgePermissionFields $Snapshot @('Format','SchemaVersion','Evidence','ResourceId','RetrievedAt','Source','Permissions')
 foreach($field in @('Format','Evidence','ResourceId')){if($Snapshot[$field] -isnot [string]){throw 'Invalid public permission snapshot field type.'}}
 if($Snapshot.Format -cne 'TokenForgePublicPermissions' -or $Snapshot.SchemaVersion -isnot [long] -and $Snapshot.SchemaVersion -isnot [int] -or $Snapshot.SchemaVersion -ne 1 -or $Snapshot.Evidence -cne 'PublicSourceDefinitions' -or $Snapshot.ResourceId -cne '00000003-0000-0000-c000-000000000000'){throw 'Unsupported public permission snapshot.'}
 Assert-TokenForgePermissionFields $Snapshot.Source @('Repository','Path','Commit','RawSha256')
 foreach($field in @('Repository','Path')){if($Snapshot.Source[$field] -isnot [string]){throw 'Invalid public permission source field type.'}}
 if($Snapshot.Source.Repository -cne 'https://github.com/microsoftgraph/microsoft-graph-devx-content' -or $Snapshot.Source.Path -cne 'permissions/permissions-descriptions.json' -or $Snapshot.Source.Commit -isnot [string] -or $Snapshot.Source.Commit -cnotmatch '\A[a-f0-9]{40}\z' -or $Snapshot.Source.RawSha256 -isnot [string] -or $Snapshot.Source.RawSha256 -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Invalid public permission provenance.'}
 $date=[DateTimeOffset]::MinValue
 if($Snapshot.RetrievedAt -isnot [string] -or -not [DateTimeOffset]::TryParseExact($Snapshot.RetrievedAt,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date) -or $date.Offset -ne [TimeSpan]::Zero){throw 'Invalid public permission retrieval date.'}
 Assert-TokenForgePermissionSource $Snapshot.Permissions
}
function Resolve-TokenForgePermissionPath {
 param([string]$Path)
 $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
 $entry=[IO.FileInfo]::new($full)
 if($entry.LinkTarget){throw 'Public permission paths cannot be links.'}
 $directory=$entry.Directory
 if(-not $directory.Exists){throw 'Public permission parent directory must exist.'}
 while($directory){if($directory.LinkTarget){throw 'Public permission paths cannot contain links.'};$directory=$directory.Parent}
 $full
}
function Read-TokenForgePermissionFile {
 param([string]$Path)
 $full=Resolve-TokenForgePermissionPath $Path
 $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  if($stream.Length -gt 4194304){throw 'Public permission input exceeds 4 MiB.'}
  $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
  if($stream.ReadByte() -ne -1){throw 'Public permission input changed during reading.'}
  Read-TokenForgePermissionJson $bytes
 }finally{$stream.Dispose()}
}
function Read-TokenForgePermissionHttpBody {
 param([Net.Http.HttpResponseMessage]$Response,[Threading.CancellationToken]$CancellationToken)
 if([int]$Response.StatusCode -ne 200 -or $Response.Content.Headers.ContentLength -gt 4194304){throw 'Public permission download failed.'}
 $stream=$null;$memory=[IO.MemoryStream]::new()
 try{
  $stream=$Response.Content.ReadAsStreamAsync($CancellationToken).GetAwaiter().GetResult();$buffer=[byte[]]::new(8192)
  while(($count=$stream.ReadAsync($buffer,0,$buffer.Length,$CancellationToken).GetAwaiter().GetResult()) -gt 0){
   if($memory.Length+$count -gt 4194304){throw 'Public permission download exceeds 4 MiB.'}
   $memory.Write($buffer,0,$count)
  }
  return ,$memory.ToArray()
 }finally{if($stream){$stream.Dispose()};$memory.Dispose()}
}
function Get-TokenForgePermissionSourceBytes {
 param([ValidatePattern('\A[a-f0-9]{40}\z')][string]$Commit)
 $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseDefaultCredentials=$false
 $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[Threading.Timeout]::InfiniteTimeSpan
 $cancel=[Threading.CancellationTokenSource]::new(30000);$response=$null
 try{
  $client.DefaultRequestHeaders.UserAgent.ParseAdd('TokenForge-PublicPermissions')
  $uri="https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-devx-content/$Commit/permissions/permissions-descriptions.json"
  $response=$client.GetAsync($uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
  Read-TokenForgePermissionHttpBody $response $cancel.Token
 }finally{if($response){$response.Dispose()};$cancel.Dispose();$client.Dispose()}
}
