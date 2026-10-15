# Project only planner metadata. Never serialize arbitrary token or inventory object properties.
function ConvertTo-TokenForgePlanningDatabase {
 param($Database)
 $fields=@('ClientId','ResourceId','TenantFingerprint','PrincipalFingerprint','ObservedAt','Outcome','NamespaceVerification','RequestVerification','ScpScopes','RedirectFingerprint','Protocol','Spa','RequestedScopes')
 @{SchemaVersion=$Database.SchemaVersion;Observations=@($Database.Observations|Select-Object -Property $fields)}|ConvertTo-Json -Depth 8 -Compress
}
# Select-Object does not project BCL OrderedDictionary keys. Preserve its
# ordered allowlist and missing-member-as-null behavior for saved snapshots.
function Select-TokenForgePlanningFields {
 param($InputObject,[string[]]$Property)
 $selected=[ordered]@{}
 foreach($field in $Property){
  $selected[$field]=$null
  if($null -eq $InputObject){continue}
  if($InputObject -is [Collections.IDictionary]){
   if($InputObject.Contains($field)){$selected[$field]=$InputObject[$field]}
  }else{
   $member=$InputObject.PSObject.Properties[$field]
   if($null -ne $member){$selected[$field]=$member.Value}
  }
 }
 [pscustomobject]$selected
}
function ConvertTo-TokenForgePlanningInventory {
 param($Inventory)
 $apps=@(foreach($app in $Inventory.Applications){
  $row=Select-TokenForgePlanningFields $app @('AppId','Name','Registration','Ownership','AccountEnabled','RedirectUris','PublishedGrants','DelegatedScopeDefinitions')
  $row.DelegatedScopeDefinitions=@($row.DelegatedScopeDefinitions|Where-Object {$null -ne $_}|ForEach-Object {Select-TokenForgePlanningFields $_ @('Value','Enabled')})
  $row.PublishedGrants=@($row.PublishedGrants|Where-Object {$null -ne $_}|ForEach-Object {Select-TokenForgePlanningFields $_ @('ResourceId','Scopes')})
  $row
 })
 $enumeration=if(($Inventory.PSObject.Properties['GrantEnumeration'] -or ($Inventory -is [Collections.IDictionary] -and $Inventory.Contains('GrantEnumeration')))){$Inventory.GrantEnumeration}else{'Unknown'}
 $grants=if(($Inventory.PSObject.Properties['TenantGrants'] -or ($Inventory -is [Collections.IDictionary] -and $Inventory.Contains('TenantGrants')))){@($Inventory.TenantGrants|ForEach-Object {Select-TokenForgePlanningFields $_ @('ClientId','ResourceId','PrincipalFingerprint','ConsentType','Scopes')})}else{@()}
 $document=@{CapturedAt=$Inventory.CapturedAt;TenantFingerprint=$Inventory.TenantFingerprint;GrantEnumeration=$enumeration;Applications=$apps;TenantGrants=@($grants)}
 if(($Inventory.PSObject.Properties['SchemaVersion'] -or ($Inventory -is [Collections.IDictionary] -and $Inventory.Contains('SchemaVersion')))){$document.SchemaVersion=$Inventory.SchemaVersion}
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
