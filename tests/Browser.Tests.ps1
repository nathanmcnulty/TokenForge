Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'System-browser PKCE callback' {
 InModuleScope TokenForge {
  BeforeEach {
   $request=[pscustomobject]@{ClientId='11111111-1111-1111-1111-111111111111';RedirectUri='http://localhost';Spa=$false;OAuthScopes=@('https://graph.microsoft.com/User.Read')}
  }
  It 'rejects unsupported callback platforms before launching' {
   Mock Open-TokenForgeBrowser {throw 'must not launch'}
   foreach($uri in @('https://localhost','http://127.0.0.1','http://localhost/path')) {
    $request.RedirectUri=$uri
    {Invoke-TokenForgeBrowserAuthorization $request 'https://login.microsoftonline.com/organizations/oauth2/v2.0' '' 1}|Should -Throw '*published*'
   }
   Should -Invoke Open-TokenForgeBrowser -Times 0
  }
  It 'accepts the matched callback and returns only secure code material' {
   Mock Open-TokenForgeBrowser {
    param($Uri)
    $q=[System.Web.HttpUtility]::ParseQueryString($Uri.Query)
    $q['prompt']|Should -Be select_account
    $q['login_hint']|Should -Be 'observer@example.test'
    $q['code_challenge_method']|Should -Be S256
    $script:challenge=$q['code_challenge']
    $script:job=Start-ThreadJob -ArgumentList $q['redirect_uri'],$q['state'] -ScriptBlock {
     param($callback,$state)
     Invoke-WebRequest -Headers @{Host=([uri]$callback).Authority} -Uri "$($callback.Replace('http://localhost','http://127.0.0.1'))?code=synthetic-code&state=$state" -TimeoutSec 5|Out-Null
    }
   }
   $result=Invoke-TokenForgeBrowserAuthorization $request 'https://login.microsoftonline.com/organizations/oauth2/v2.0' 'observer@example.test' 5
   try {
    $result.Code|Should -BeOfType securestring
    $result.Verifier|Should -BeOfType securestring
    $plain=[Net.NetworkCredential]::new('', $result.Verifier).Password
    $hash=[Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($plain))).TrimEnd('=').Replace('+','-').Replace('/','_')
    $hash|Should -BeExactly $script:challenge
    [Net.NetworkCredential]::new('', $result.Code).Password|Should -Be synthetic-code
    $result.RedirectUri|Should -Match '^http://localhost:[0-9]+/$'
   } finally {$result.Code.Dispose();$result.Verifier.Dispose();$script:job|Wait-Job|Receive-Job; $script:job|Remove-Job}
  }
  It 'ignores wrong state and duplicate code or error fields' {
   Mock Open-TokenForgeBrowser {
    param($Uri)
    $q=[System.Web.HttpUtility]::ParseQueryString($Uri.Query)
    $script:job=Start-ThreadJob -ArgumentList $q['redirect_uri'],$q['state'] -ScriptBlock {
     param($callback,$state)
     foreach($query in @('code=bad&state=wrong',"code=a&code=b&state=$state","code=bad&error=a&error=b&state=$state")) {
      $r=Invoke-WebRequest -Headers @{Host=([uri]$callback).Authority} -Uri "$($callback.Replace('http://localhost','http://127.0.0.1'))?$query" -SkipHttpErrorCheck -TimeoutSec 5
      if($r.StatusCode -ne 400){throw 'Invalid callback accepted'}
     }
     Invoke-WebRequest -Headers @{Host=([uri]$callback).Authority} -Uri "$($callback.Replace('http://localhost','http://127.0.0.1'))?code=good&state=$state" -TimeoutSec 5|Out-Null
    }
   }
   $result=Invoke-TokenForgeBrowserAuthorization $request 'https://login.microsoftonline.com/organizations/oauth2/v2.0' '' 5
   try {[Net.NetworkCredential]::new('', $result.Code).Password|Should -Be good}
   finally {$result.Code.Dispose();$result.Verifier.Dispose();$script:job|Wait-Job|Receive-Job;$script:job|Remove-Job}
  }
  It 'sanitizes an identity decline' {
   Mock Open-TokenForgeBrowser {
    param($Uri)
    $q=[System.Web.HttpUtility]::ParseQueryString($Uri.Query)
    $script:job=Start-ThreadJob -ArgumentList $q['redirect_uri'],$q['state'] -ScriptBlock {
     param($callback,$state)
     Invoke-WebRequest -Headers @{Host=([uri]$callback).Authority} -Uri "$($callback.Replace('http://localhost','http://127.0.0.1'))?error=access_denied&error_description=AADSTS53003%20synthetic-secret&state=$state" -TimeoutSec 5|Out-Null
    }
   }
   {Invoke-TokenForgeBrowserAuthorization $request 'https://login.microsoftonline.com/organizations/oauth2/v2.0' '' 5}|Should -Throw 'Browser authorization was declined. Identity response details suppressed. Identity error codes: AADSTS53003.'
   $script:job|Wait-Job|Receive-Job;$script:job|Remove-Job
  }
  It 'bounds a slow partial header by the authorization deadline' {
   Mock Open-TokenForgeBrowser {
    param($Uri)
    $q=[System.Web.HttpUtility]::ParseQueryString($Uri.Query)
    $script:job=Start-ThreadJob -ArgumentList $q['redirect_uri'] -ScriptBlock {
     param($callback)
     $c=[Net.Sockets.TcpClient]::new('127.0.0.1',([uri]$callback).Port)
     try {for($i=0;$i -lt 10;$i++){try{$c.GetStream().WriteByte(71)}catch{break};Start-Sleep -Milliseconds 200}}finally{$c.Dispose()}
    }
   }
   $watch=[Diagnostics.Stopwatch]::StartNew()
   {Invoke-TokenForgeBrowserAuthorization $request 'https://login.microsoftonline.com/organizations/oauth2/v2.0' '' 1}|Should -Throw '*timed out*'
   $watch.Elapsed.TotalSeconds|Should -BeLessThan 2
   $script:job|Wait-Job|Receive-Job;$script:job|Remove-Job
  }
 }
}
Describe 'Browser code redemption shares the token validation boundary' {
 It 'redeems the captured code with the actual loopback URI and validates issued scopes' {
  $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
  $catalog.Applications[0].RedirectUris=@('http://localhost')
  $plan=New-TokenForgeRequest -Catalog $catalog -ClientId $catalog.Applications[0].ClientId -ResourceId '00000003-0000-0000-c000-000000000000' -Scope User.Read -RedirectUri http://localhost
  Mock Invoke-TokenForgeBrowserAuthorization -ModuleName TokenForge {
   [pscustomobject]@{Code=ConvertTo-SecureString 'synthetic-code' -AsPlainText -Force;Verifier=ConvertTo-SecureString ('a'*43) -AsPlainText -Force;RedirectUri='http://localhost:45678/'}
  }
  Mock Invoke-TokenForgeHttp -ModuleName TokenForge {
   param($Client,$Uri,$Form,$Origin)
   $Uri.Host|Should -Be login.microsoftonline.com
   $Uri.AbsolutePath|Should -Be '/organizations/oauth2/v2.0/token'
   $Form.code|Should -Be synthetic-code
   $Form.code_verifier|Should -Be ('a'*43)
   $Form.redirect_uri|Should -Be 'http://localhost:45678/'
   $Form.grant_type|Should -Be authorization_code
   @{Status=200;Content='{"access_token":"synthetic-access","token_type":"Bearer","scope":"User.Read"}'}
  }
  $token=Get-TokenForgeToken -Request $plan -Browser
  try{$token.AccessToken|Should -BeOfType securestring;$token.GrantedScopes|Should -Contain User.Read}
  finally{$token.AccessToken.Dispose()}
  Should -Invoke Invoke-TokenForgeHttp -ModuleName TokenForge -Times 1
 }
}
