function Open-TokenForgeBrowser {
    param([uri]$Uri)
    try {
        $info = [Diagnostics.ProcessStartInfo]::new($Uri.AbsoluteUri)
        $info.UseShellExecute = $true
        $null = [Diagnostics.Process]::Start($info)
    } catch { throw 'Unable to open the system browser. Browser request details suppressed.' }
}

function Invoke-TokenForgeBrowserAuthorization {
    param($Request, [string]$Authority, [string]$LoginHint, [int]$TimeoutSeconds)
    $published = [uri]$Request.RedirectUri
    if ($Request.Spa -or $published.Scheme -cne 'http' -or $published.Host -cne 'localhost' -or $published.AbsolutePath -cne '/' -or $published.Query -or $published.Fragment -or $published.UserInfo) {
        throw 'Browser authentication requires a published http://localhost root redirect for a public native client.'
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $connection = $null
    $verifier = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_')
    $state = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $challenge = [Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+','-').Replace('/','_')
    try {
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $callback = "http://localhost:$port/"
        $query = @{
            client_id = $Request.ClientId; redirect_uri = $callback; scope = ($Request.OAuthScopes -join ' ')
            response_type = 'code'; response_mode = 'query'; prompt = 'select_account'
            code_challenge = $challenge; code_challenge_method = 'S256'; state = $state
        }
        if ($LoginHint) { $query.login_hint = $LoginHint }
        $encoded = ($query.Keys | ForEach-Object { "$([uri]::EscapeDataString($_))=$([uri]::EscapeDataString([string]$query[$_]))" }) -join '&'
        Open-TokenForgeBrowser -Uri "$Authority/authorize?$encoded"
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while ([DateTimeOffset]::UtcNow -lt $deadline) {
            if (-not $listener.Pending()) { Start-Sleep -Milliseconds 100; continue }
            $connection = $listener.AcceptTcpClient()
            try {
                $stream = $connection.GetStream()
                $stream.ReadTimeout = 1000
                # A bounded HTTP header parser; no request body, credentials, or URL is logged.
                $bytes = [Collections.Generic.List[byte]]::new()
                $headerDeadline = [DateTimeOffset]::UtcNow.AddSeconds(2)
                if ($headerDeadline -gt $deadline) { $headerDeadline = $deadline }
                while ($bytes.Count -lt 8192 -and [DateTimeOffset]::UtcNow -lt $headerDeadline) {
                    $stream.ReadTimeout = [math]::Max(1,[int]($headerDeadline - [DateTimeOffset]::UtcNow).TotalMilliseconds)
                    $byte = $stream.ReadByte()
                    if ($byte -lt 0) { break }
                    $bytes.Add([byte]$byte)
                    if ($bytes.Count -ge 4 -and [Text.Encoding]::ASCII.GetString($bytes.GetRange($bytes.Count - 4,4).ToArray()) -ceq "`r`n`r`n") { break }
                }
                $header = [Text.Encoding]::ASCII.GetString($bytes.ToArray())
                $lines = $header -split "`r`n"
                $valid = $header.EndsWith("`r`n`r`n") -and $lines[0] -cmatch '^GET (/\?[^ ]+) HTTP/1\.[01]$'
                $target = if ($valid) { $Matches[1] } else { '' }
                $hosts = @($lines | Where-Object { $_ -imatch '^Host:' })
                $valid = $valid -and $hosts.Count -eq 1 -and $hosts[0] -ieq "Host: localhost:$port"
                $values = [System.Web.HttpUtility]::ParseQueryString($(if ($valid) { $target.Substring(2) } else { '' }))
                $valid = $valid -and @($values.GetValues('state')).Count -eq 1 -and $values['state'] -ceq $state
                $hasCode = @($values.GetValues('code')).Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($values['code'])
                $hasError = @($values.GetValues('error')).Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($values['error'])
                $valid = $valid -and (($hasCode -and $null -eq $values.GetValues('error')) -or ($hasError -and $null -eq $values.GetValues('code')))
                $status = if ($valid) { '200 OK' } else { '400 Bad Request' }
                $body = if ($valid) { 'Sign-in callback received. You can close this tab.' } else { 'Invalid sign-in callback.' }
                $reply = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 $status`r`nContent-Type: text/plain`r`nCache-Control: no-store`r`nReferrer-Policy: no-referrer`r`nConnection: close`r`nContent-Length: $($body.Length)`r`n`r`n$body")
                $stream.Write($reply,0,$reply.Length)
                if (-not $valid) { continue }
                if ($hasError) { throw 'Browser authorization was declined. Identity response details suppressed.' }
                return [pscustomobject]@{
                    Code = ConvertTo-SecureString $values['code'] -AsPlainText -Force
                    Verifier = ConvertTo-SecureString $verifier -AsPlainText -Force
                    RedirectUri = $callback
                }
            } catch [IO.IOException] { continue }
            finally { $connection.Dispose(); $connection = $null }
        }
        throw 'Browser authorization timed out. No token returned.'
    } finally {
        if ($connection) { $connection.Dispose() }
        $listener.Stop()
        $verifier = $null; $state = $null; $header = $null; $values = $null
    }
}
