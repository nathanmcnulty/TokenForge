# Project only planner metadata. Never serialize arbitrary token or inventory object properties.
function ConvertTo-TokenForgePlanningDatabase {
 param($Database)
 $fields=@('ClientId','ResourceId','TenantFingerprint','PrincipalFingerprint','ObservedAt','Outcome','NamespaceVerification','RequestVerification','ScpScopes','RedirectFingerprint','Protocol','Spa','RequestedScopes')
 @{SchemaVersion=$Database.SchemaVersion;Observations=@($Database.Observations|Select-Object -Property $fields)}|ConvertTo-Json -Depth 8 -Compress
}
function ConvertTo-TokenForgePlanningInventory {
 param($Inventory)
 $apps=@(foreach($app in $Inventory.Applications){
  $row=$app|Select-Object AppId,Name,Registration,Ownership,AccountEnabled,RedirectUris,PublishedGrants,DelegatedScopeDefinitions
  $row.DelegatedScopeDefinitions=@($row.DelegatedScopeDefinitions|Where-Object {$null -ne $_}|Select-Object Value,Enabled)
  $row.PublishedGrants=@($row.PublishedGrants|Where-Object {$null -ne $_}|Select-Object ResourceId,Scopes)
  $row
 })
 $enumeration=if($Inventory.PSObject.Properties['GrantEnumeration']){$Inventory.GrantEnumeration}else{'Unknown'}
 $grants=if($Inventory.PSObject.Properties['TenantGrants']){@($Inventory.TenantGrants|Select-Object ClientId,ResourceId,PrincipalFingerprint,ConsentType,Scopes)}else{@()}
 $document=@{CapturedAt=$Inventory.CapturedAt;TenantFingerprint=$Inventory.TenantFingerprint;GrantEnumeration=$enumeration;Applications=$apps;TenantGrants=@($grants)}
 if($Inventory.PSObject.Properties['SchemaVersion']){$document.SchemaVersion=$Inventory.SchemaVersion}
 $document|ConvertTo-Json -Depth 10 -Compress
}
function ConvertFrom-TokenForgePlanningResult {
 param([string]$Json)
 # PowerShell 7.5+ can turn JSON timestamps into local DateTime values. Keep the core's strings.
 $rows=@($Json|ConvertFrom-Json);$document=[Text.Json.JsonDocument]::Parse($Json)
 try{
  for($i=0;$i -lt $rows.Count;$i++){
   foreach($field in @('ObservedAt','InventoryCapturedAt')){
    if($rows[$i].PSObject.Properties[$field]){
     $value=$document.RootElement[$i].GetProperty($field)
     $rows[$i].$field=if($value.ValueKind -eq [Text.Json.JsonValueKind]::Null){$null}else{$value.GetString()}
    }
   }
   $rows[$i]
  }
 }finally{$document.Dispose()}
}

function New-TokenForgePlannedScopeRequests {
 param($Inventory,$Database,[string]$ResourceId,[string[]]$Scope,[string]$PrincipalFingerprint,[string]$Tenant,
  [bool]$Warm,[bool]$Browser=$false,[bool]$OfflineAccess=$false,[int]$MaxCandidates=8,[int]$MaxRedirects=2,[int]$MaxAgeHours=24)
 $json=[TokenForge.Core.ScopePlanning]::BuildRequests((ConvertTo-TokenForgePlanningInventory $Inventory),(ConvertTo-TokenForgePlanningDatabase $Database),
  $ResourceId,$Scope,$PrincipalFingerprint,$Tenant,$Warm,$Browser,$OfflineAccess,$MaxCandidates,$MaxRedirects,$MaxAgeHours)
 foreach($request in @(ConvertFrom-TokenForgePlanningResult $json)){
  $request.PSObject.TypeNames.Insert(0,'TokenForge.Request')
  if($null -eq $request.ObservedAt){$request.PSObject.Properties.Remove('ObservedAt')}
  $request
 }
}
