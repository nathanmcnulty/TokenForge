BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native acquisition input boundary' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  $native=$env:TOKENFORGE_TEST_NATIVE
  function Set-PrivateTestPath($Path,[switch]$Directory) {
   if($IsWindows){
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl=if($Directory){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
    $acl.SetOwner($sid);$acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    if($Directory){[IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path),$acl)}else{[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path),$acl)}
   }else{[IO.File]::SetUnixFileMode($Path,$(if($Directory){[IO.UnixFileMode]448}else{[IO.UnixFileMode]384}))}
  }
  function Invoke-NativeReject($Path) {
   $start=[Diagnostics.ProcessStartInfo]::new($native)
   $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   foreach($arg in @('token','acquire','--plan',$Path,'--credential','cookie','--stdin')){$start.ArgumentList.Add($arg)}
   $start.Environment['PATH']=Join-Path $root no-pwsh
   # A broken validation guard must fail the stage assertion, without reaching Entra.
   $start.Environment['HTTPS_PROXY']='http://127.0.0.1:1'
   $start.Environment['NO_PROXY']=''
   $p=[Diagnostics.Process]::Start($start)
   try {
    $output=$p.StandardOutput.ReadToEndAsync();$errors=$p.StandardError.ReadToEndAsync()
    $p.StandardInput.Write('synthetic-private-credential');$p.StandardInput.Close()
    if(-not $p.WaitForExit(20000)){$p.Kill($true);throw 'Native input validation timed out.'}
    $p.ExitCode|Should -Be 1
    $output.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $errorText=$errors.GetAwaiter().GetResult();$errorText|Should -Not -Match 'synthetic-private|ExpectedPrincipalFingerprint'
    $failure=$errorText|ConvertFrom-Json
    $failure.Code|Should -Be InvalidPlan
    $failure.Succeeded|Should -BeFalse
   }finally{$p.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
  $null=New-Item -ItemType Directory $root;Set-PrivateTestPath $root -Directory
  $path=Join-Path $root plan.json
  $plan=@{SchemaVersion=1;ExpectedTenantFingerprint=('a'*64);ExpectedPrincipalFingerprint=('b'*64);MaximumAdditionalScopes=0;Request=@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='https://graph.microsoft.com';Tenant='organizations';RedirectUri='https://example.test/callback';Scopes=@('User.Read');OAuthScopes=@('https://graph.microsoft.com/User.Read');Protocol='OAuth2V2Pkce'}}
  $plan|ConvertTo-Json -Depth 8|Set-Content $path;Set-PrivateTestPath $path
 }
 It 'rejects invalid input before network access with no PowerShell on PATH: <Case>' -ForEach @(@{Case='Protocol'},@{Case='DuplicateKeys'},@{Case='CredentialField'},@{Case='ScopeMismatch'}) {
  switch($Case){
   Protocol {$plan.Request.Protocol='INVALID';$plan|ConvertTo-Json -Depth 8|Set-Content $path}
   DuplicateKeys {($plan|ConvertTo-Json -Depth 8) -replace '^\{','{"SchemaVersion":1,'|Set-Content $path}
   CredentialField {$plan.PrivateCredential='synthetic-private-credential';$plan|ConvertTo-Json -Depth 8|Set-Content $path}
   ScopeMismatch {$plan.Request.Protocol='OAuth2V2Pkce';$plan.Request.OAuthScopes=@('https://evil.test/.default');$plan|ConvertTo-Json -Depth 8|Set-Content $path}
  }
  Invoke-NativeReject $path
 }
 It 'does not create a missing context plan' {
  $missing=Join-Path $root missing.json;Invoke-NativeReject $missing;Test-Path $missing|Should -BeFalse
 }
 It 'rejects a linked plan' -Skip:$IsWindows {
  $link=Join-Path $root linked.json;$null=New-Item -ItemType SymbolicLink -Path $link -Target $path;Invoke-NativeReject $link
 }
 It 'rejects shared file permissions' -Skip:$IsWindows {
  [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]420);Invoke-NativeReject $path
 }
 It 'rejects a shared parent directory' -Skip:$IsWindows {
  [IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]493);Invoke-NativeReject $path
 }
 It 'rejects a Windows ACL permitting another principal' -Skip:(-not $IsWindows) {
  $file=[IO.FileInfo]::new($path);$acl=[IO.FileSystemAclExtensions]::GetAccessControl($file)
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow))
  [IO.FileSystemAclExtensions]::SetAccessControl($file,$acl);Invoke-NativeReject $path
 }
}
