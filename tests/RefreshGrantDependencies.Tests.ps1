BeforeAll {
 . "$PSScriptRoot/fixtures/refresh/RefreshFixture.ps1"
 function New-RefreshGrant([string]$Client=$script:rfClient,[string]$Principal=('b'*64),[string]$Consent='Principal',[string[]]$Scopes=@('User.Read')) {
  @{ClientId=$Client;ResourceId=$script:rfGraph;Scopes=$Scopes;PrincipalFingerprint=$(if($Consent -eq 'AllPrincipals'){$null}else{$Principal});ConsentType=$Consent;AppliesToCurrentPrincipal=($Consent -eq 'AllPrincipals' -or $Principal -ceq ('b'*64));Evidence='TenantConfiguredGrant'}
 }
 function New-GrantedWarmInput {
  $i=New-RefreshInput;$i.Inventory.TenantGrants=@((New-RefreshGrant));$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$s=New-RefreshObservation $p;$i.History=Capture-Refresh $p $s $i.History;$i.Snapshot=$s;$i
 }
}
Describe 'Goal 4 relevant visible grant compatibility' {
 It 'invalidates relevant grant removal, extra scopes and bootstrap grant changes without claiming root cause' -ForEach @(@{Case='Removal'},@{Case='Extras'},@{Case='Bootstrap'},@{Case='AllPrincipals'},@{Case='QualifiedExtra'}) {
  $i=New-GrantedWarmInput
  switch($Case){Removal {$i.Inventory.TenantGrants=@()} Extras {$i.Inventory.TenantGrants[0].Scopes+=@('Mail.Read')} Bootstrap {$i.Inventory.TenantGrants+=@((New-RefreshGrant -Client $script:rfBoot))} AllPrincipals {$i.Inventory.TenantGrants+=@((New-RefreshGrant -Consent AllPrincipals))} QualifiedExtra {$i.Inventory.TenantGrants[0].Scopes+=@('api://resource/Scope')}}
  $p=Plan-Refresh $i;$p.ReusedCount|Should -Be 0;$p.Candidates[0].Reason|Should -Be ToolCriticalRelevantChange;$p.Candidates[0].FailureStreak|Should -Be 0;$p.AuthorizationEstablished|Should -BeFalse
  $i.History.Entries[0].ObservationReferences[0].ObservedAt|Should -Be $script:rfNow.AddMinutes(-9).ToString('o')
 }
 It 'invalidates visibility or grant-query changes while retaining original successful evidence' -ForEach @(@{Case='Visibility'},@{Case='Query'}) {
  $i=New-GrantedWarmInput
  if($Case -eq 'Visibility'){$i.Inventory.GrantEnumeration='Forbidden'}else{$i.Inventory.EvidenceCoverage=@{SchemaVersion=1;InventoryQueryFingerprint=('8'*64);GrantQueryFingerprint=('9'*64)}}
  $p=Plan-Refresh $i;$p.ReusedCount|Should -Be 0;$p.Candidates[0].Reason|Should -Be ToolCriticalRelevantChange;$i.History.Entries.Count|Should -Be 1
 }
 It 'preserves reuse for unrelated pairs and other principals even if an applicability flag is misleading' -ForEach @(@{Case='OtherPrincipal'},@{Case='OtherClient'}) {
  $i=New-GrantedWarmInput
  if($Case -eq 'OtherPrincipal'){$g=New-RefreshGrant -Principal ('c'*64);$g.AppliesToCurrentPrincipal=$true}else{$g=New-RefreshGrant -Client '44444444-4444-4444-4444-444444444444'}
  $i.Inventory.TenantGrants+=@($g);(Plan-Refresh $i).ReusedCount|Should -Be 1
 }
 It 'canonicalizes reordered scopes, duplicate semantic edges and edge order' {
  $i=New-RefreshInput;$i.Inventory.TenantGrants=@((New-RefreshGrant -Scopes @('Mail.Read','User.Read')),(New-RefreshGrant -Consent AllPrincipals))
  $initial=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$snapshot=New-RefreshObservation $initial;$i.History=Capture-Refresh $initial $snapshot $i.History;$i.Snapshot=$snapshot;$original=Plan-Refresh $i
  $i.Inventory.TenantGrants[0].Scopes=@('User.Read','Mail.Read');[array]::Reverse($i.Inventory.TenantGrants);$i.Inventory.TenantGrants+=@((New-RefreshGrant))
  $i.Inventory.Applications[0].Name='Unrelated display name'
  $p=Plan-Refresh $i;$p.Candidates[0].CompatibilityKey|Should -Be $original.Candidates[0].CompatibilityKey;$p.ReusedCount|Should -Be 1
 }

}
