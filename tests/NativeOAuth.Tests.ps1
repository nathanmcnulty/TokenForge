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
  function Invoke-NativeBrowserFixture($Path,$Browser) {
   $start=[Diagnostics.ProcessStartInfo]::new($native)
   $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   foreach($arg in @('token','acquire','--plan',$Path,'--credential','browser','--timeout-seconds','30')){$start.ArgumentList.Add($arg)}
   $start.Environment['BROWSER']=$Browser;$start.Environment['XDG_CURRENT_DESKTOP']='X-Generic';$start.Environment['XDG_RUNTIME_DIR']=$root
   $start.Environment.Remove('DISPLAY');$start.Environment.Remove('WAYLAND_DISPLAY')
   $p=[Diagnostics.Process]::Start($start);$watch=[Diagnostics.Stopwatch]::StartNew()
   try{
    $p.StandardInput.Close();$output=$p.StandardOutput.ReadToEndAsync();$errors=$p.StandardError.ReadToEndAsync()
    if(-not $p.WaitForExit(20000)){$p.Kill($true);throw 'Browser fixture timed out.'}
    $p.ExitCode|Should -Be 1;$output.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $errorText=$errors.GetAwaiter().GetResult();$errorText|Should -Not -Match 'synthetic-private|ExpectedPrincipalFingerprint'
    [pscustomobject]@{Failure=($errorText|ConvertFrom-Json);Seconds=$watch.Elapsed.TotalSeconds}
   }finally{$p.Dispose()}
  }
  function Invoke-NativeReject($Path,[string[]]$Options=@("--credential","cookie","--stdin")) {
   $start=[Diagnostics.ProcessStartInfo]::new($native)
   $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   foreach($arg in (@('token','acquire','--plan',$Path)+$Options)){$start.ArgumentList.Add($arg)}
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
 It 'rejects browser options before launching: <Case>' -ForEach @(
  @{Case='Stdin';Options=@('--stdin')},@{Case='Unknown';Options=@('--credential-file','synthetic-private-credential')},
  @{Case='Duplicate';Options=@('--interactive','--interactive')},@{Case='MissingHint';Options=@('--login-hint')},
  @{Case='Timeout';Options=@('--timeout-seconds','29')},@{Case='HintControl';Options=@('--login-hint',"synthetic-private`n")}) {
  $plan.Request.RedirectUri='http://localhost';$plan|ConvertTo-Json -Depth 8|Set-Content $path
  Invoke-NativeReject $path (@('--credential','browser')+$Options)
 }
 It 'rejects unsupported native browser callbacks before launching' {
  Invoke-NativeReject $path @('--credential','browser')
 }
 It 'rejects a SPA browser plan before launching' {
  $plan.Request.Spa=$true;$plan|ConvertTo-Json -Depth 8|Set-Content $path
  Invoke-NativeReject $path @('--credential','browser')
 }
 It 'receives a real loopback decline after the launcher exits while its child retains output streams' -Skip:(-not $IsLinux) {
  $plan.Request.RedirectUri='http://localhost';$plan|ConvertTo-Json -Depth 8|Set-Content $path
  $browser=Join-Path $root browser
  @'
#!/usr/bin/python3
import os,sys,time,urllib.parse,urllib.request
query=urllib.parse.parse_qs(urllib.parse.urlsplit(sys.argv[1]).query)
print('synthetic-private-launcher-output',flush=True)
print('synthetic-private-launcher-error',file=sys.stderr,flush=True)
if os.fork():sys.exit(0)
time.sleep(0.3)
callback=urllib.parse.urlsplit(query['redirect_uri'][0])
target='http://127.0.0.1:'+str(callback.port)+'/?'+urllib.parse.urlencode({'state':query['state'][0],'error':'access_denied','error_description':'synthetic-private-identity AADSTS53003'})
request=urllib.request.Request(target,headers={'Host':callback.netloc})
try:urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=5).close()
finally:os._exit(0)
'@|Set-Content $browser
  [IO.File]::SetUnixFileMode($browser,[IO.UnixFileMode]448)
  $result=Invoke-NativeBrowserFixture $path $browser
  $result.Failure.Code|Should -Be TokenAcquisitionFailed
  @($result.Failure.IdentityErrorCodes)|Should -Be @('53003')
  $result.Seconds|Should -BeLessThan 10
 }
 It 'suppresses failed launcher stdout and stderr' -Skip:(-not $IsLinux) {
  $plan.Request.RedirectUri='http://localhost';$plan|ConvertTo-Json -Depth 8|Set-Content $path
  $browser=Join-Path $root browser
  "#!/bin/sh`nprintf 'synthetic-private-output\n'`nprintf 'synthetic-private-error\n' >&2`nexit 17"|Set-Content $browser
  [IO.File]::SetUnixFileMode($browser,[IO.UnixFileMode]448)
  $result=Invoke-NativeBrowserFixture $path $browser
  $result.Failure.Code|Should -Be TokenAcquisitionFailed
  $result.Failure.IdentityErrorCodes|Should -BeNullOrEmpty
 }
 It 'rejects passkey options and invalid plans before credential file access: <Case>' -ForEach @(
  @{Case='MissingPath';Options=@('--credential','passkey','--passkey-file')},
  @{Case='Stdin';Options=@('--credential','passkey','--stdin')},
  @{Case='Duplicate';Options=@('--credential','passkey','--passkey-file','synthetic-private-key','--passkey-file','synthetic-private-key')},
  @{Case='InvalidPlan';Options=@('--credential','passkey','--passkey-file','synthetic-private-key')}) {
  if($Case -eq 'InvalidPlan'){$plan.Request.Protocol='INVALID';$plan|ConvertTo-Json -Depth 8|Set-Content $path}
  Invoke-NativeReject $path $Options
 }
 It 'does not create a missing context plan'  {
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
