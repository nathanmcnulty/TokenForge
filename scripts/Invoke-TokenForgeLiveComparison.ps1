#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$InventoryPath,
 [Parameter(Mandatory)][object[]]$Observers,
 [Parameter(Mandatory)][string]$XdrModulePath,
 [string]$Tenant='organizations',
 [string]$ManifestPath=(Join-Path $PSScriptRoot '../manifests/core-readonly.json'),
 [ValidateRange(1,100)][int]$MaxGroups=50
)
$ErrorActionPreference='Stop';$WarningPreference='SilentlyContinue'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
$module=Get-Module TokenForge
$inventory=Get-Content -LiteralPath $InventoryPath -Raw|ConvertFrom-Json
$results=foreach($observer in $Observers){
 if($observer.Alias -notmatch '^[A-Za-z0-9_-]{1,32}$'){throw 'Observer aliases must be short simple names.'}
 $database=Get-TokenForgeScopeDatabase -Path $observer.DatabasePath
 $cookie=$null;$contextToken=$null;$token=$null
 try{
  $cookie=Get-TokenForgeEstsCookie -PasskeyPath $observer.PasskeyPath -XdrModulePath $XdrModulePath
  $request=New-TokenForgeTenantRequest -Inventory $inventory -ClientId 14d82eec-204b-4c2f-b7e8-296a70dab67e -ResourceId 00000003-0000-0000-c000-000000000000 -Scope User.Read -RedirectUri https://login.microsoftonline.com/common/oauth2/nativeclient -Tenant $Tenant
  $contextToken=Get-TokenForgeToken -Request $request -EstsAuth $cookie
  $identity=& $module {param($s)Invoke-TokenForgeGraph -AccessToken $s -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'} $contextToken.AccessToken
  $payload=& $module {param($s)ConvertFrom-TokenForgeJwtPayload -AccessToken $s} $contextToken.AccessToken
  $oid=[guid]::Empty
  if(-not [guid]::TryParse([string]$identity['id'],[ref]$oid) -or [string]$payload['oid'] -ine $oid.ToString() -or $contextToken.TokenClaims.TenantFingerprint -ne $inventory.TenantFingerprint){throw 'Observer context mismatch.'}
  $report=[ordered]@{Observer=$observer.Alias;Checks=@();Context=[ordered]@{HiddenMembershipVisibility='NotEstablished';AzureRbacCoverage='NotChecked'}}
  $plan=Get-TokenForgeAssessmentPlan -ManifestPath $ManifestPath -Database $database -TenantFingerprint $contextToken.TokenClaims.TenantFingerprint -PrincipalFingerprint $contextToken.TokenClaims.PrincipalFingerprint
  foreach($check in $plan.Checks){
   try{
    $token=Get-TokenForgeScopedToken -Inventory $inventory -Database $database -ResourceId $check.ResourceId -Scope $check.RequiredScopes -EstsAuth $cookie -Tenant $Tenant -ApiUri $check.ApiUri -MaxCandidates 4 -MaxRedirects 2
    if($token.TokenClaims.PrincipalFingerprint -ne $contextToken.TokenClaims.PrincipalFingerprint){throw 'Observer changed during comparison.'}
    $report.Checks+=@{Id=$check.Id;TokenOutcome='Succeeded';ClientId=$token.ClientId;AdditionalScopeCount=$token.ObservedAdditionalScopeCount;ApiStatus=$token.ApiCheck.Status;ApiAccepted=$token.ApiCheck.Accepted}
   }catch{
    $report.Checks+=@{Id=$check.Id;TokenOutcome=if($check.ScopeStatus -eq 'NeedsObservation'){'NeedsObservation'}else{'RequestRejected'};ApiStatus=$null;EntraCodes=@([regex]::Matches($_.Exception.Message,'\bAADSTS[0-9]+\b')|ForEach-Object Value)}
   }finally{if($token){$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()};$token=$null}}
  }
  $queries=@(
   @{Name='DirectActiveRoles';Uri="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$oid'"},
   @{Name='DirectEligibleRoles';Uri="https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$oid'"},
   @{Name='EligiblePimGroupMemberships';Uri="https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=principalId eq '$oid'"},
   @{Name='Licenses';Uri='https://graph.microsoft.com/v1.0/me/licenseDetails'},
   @{Name='TransitiveMemberships';Uri='https://graph.microsoft.com/v1.0/me/transitiveMemberOf'}
  )
  $members=$null
  foreach($query in $queries){
   try{
    $data=& $module {param($s,$u)Get-TokenForgeGraphCollection -AccessToken $s -Uri $u -MaxPages 100} $contextToken.AccessToken $query.Uri
    $report.Context[$query.Name]=@{Status=200;Count=@($data).Count;Complete=$true}
    if($query.Name -eq 'TransitiveMemberships'){$members=$data}
    if($query.Name -eq 'Licenses'){
     $plans=@($data|ForEach-Object {$_.servicePlans}|Where-Object {$_.provisioningStatus -eq 'Success' -and $_.servicePlanName -in @('AAD_PREMIUM','AAD_PREMIUM_P2')}|Select-Object -ExpandProperty servicePlanName -Unique)
     $report.Context.Licenses.EnabledEntraPremiumPlans=$plans
    }
   }catch{
    $m=[regex]::Match($_.Exception.Message,'HTTP ([0-9]{3})')
    $report.Context[$query.Name]=@{Status=if($m.Success){[int]$m.Groups[1].Value}else{'Failed'};Count=$null;Complete=$false}
   }
   $data=$null
  }
  $groups=@($members|Where-Object {$_['@odata.type'] -eq '#microsoft.graph.group'})
  $groupActive=0;$groupEligible=0;$queriedGroups=0;$complete=$null -ne $members -and $groups.Count -le $MaxGroups
  $statuses=@()
  if($complete){foreach($group in $groups){
   $groupId=[guid]::Empty
   if(-not [guid]::TryParse([string]$group['id'],[ref]$groupId)){$complete=$false;continue}
   $queriedGroups++
   foreach($kind in @('roleAssignments','roleEligibilityScheduleInstances')){
    try{$data=& $module {param($s,$u)Get-TokenForgeGraphCollection -AccessToken $s -Uri $u -MaxPages 100} $contextToken.AccessToken "https://graph.microsoft.com/v1.0/roleManagement/directory/${kind}?`$filter=principalId eq '$groupId'";if($kind -eq 'roleAssignments'){$groupActive+=@($data).Count}else{$groupEligible+=@($data).Count}}
    catch{$complete=$false;$m=[regex]::Match($_.Exception.Message,'HTTP ([0-9]{3})');$statuses+=if($m.Success){[int]$m.Groups[1].Value}else{'Failed'}}
   }
  }}
  $report.Context.GroupDerivedRoles=@{Complete=$complete;VisibleGroupCount=$groups.Count;QueriedGroupCount=$queriedGroups;ActiveCount=if($complete){$groupActive}else{$null};EligibleCount=if($complete){$groupEligible}else{$null};FailureStatuses=@($statuses|Sort-Object -Unique);Coverage='Visible transitive groups; hidden memberships not independently established'}
  $report
 }finally{
  if($cookie){$cookie.Dispose()};if($contextToken){$contextToken.AccessToken.Dispose();if($contextToken.RefreshToken){$contextToken.RefreshToken.Dispose()}}
  $identity=$null;$payload=$null;$members=$null;$Error.Clear()
 }
}
[pscustomobject]@{SchemaVersion=1;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Platform=if($IsWindows){'Windows'}elseif($IsMacOS){'macOS'}else{'Linux'};Observers=@($results);AuthenticationPolicyChanged=$false;PermissionGrantsChanged=$false;SignatureValidated=$false}
