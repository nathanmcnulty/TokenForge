# Shared private-path and exclusive-file policy used by all vault operations.
function Resolve-TokenForgeVaultPath {
    param([string]$Path,[switch]$CreateDirectory)
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [TokenForge.Core.V0220.PrivateFiles]::Resolve($full,[bool]$CreateDirectory)
}
function Open-TokenForgeVaultFile {
    param([string]$Path,[switch]$Create)
    [TokenForge.Core.V0220.PrivateFiles]::Open($Path,[bool]$Create)
}

function Invoke-TokenForgeVaultTransaction {
    param([string]$Path,[securestring]$Password,[ValidateSet('Read','Create','Update')][string]$Mode='Read',[scriptblock]$Update)
    $transaction=$null;$plainBytes=$null;$document=$null
    try{
        if(-not $Password -or $Password.Length -lt 12 -or $Password.Length -gt 1024){throw 'Vault passphrase must contain 12 to 1024 characters.'}
        if(-not [Security.Cryptography.AesGcm]::IsSupported){throw 'Authenticated vault encryption is unavailable on this platform.'}
        $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $transaction=[TokenForge.Core.V0220.VaultFileTransaction]::Begin($full,$Mode)
        if($Mode -eq 'Create'){
            $document=@{SchemaVersion=1;Sessions=@{}}
        }else{
            $bytes=$transaction.ReadEnvelope()
            $plainBytes=[TokenForge.Core.V0190.VaultEnvelope]::Decrypt($bytes,$Password)
            [TokenForge.Core.V0250.VaultRecordPolicy]::Validate($plainBytes)
            $document=[Text.Encoding]::UTF8.GetString($plainBytes)|ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
            [Array]::Clear($plainBytes);$plainBytes=$null
        }
        if($Mode -eq 'Read'){return $document}
        if($Update){$null=& $Update $document}
        $plainBytes=[Text.Encoding]::UTF8.GetBytes(($document|ConvertTo-Json -Depth 32 -Compress))
        [TokenForge.Core.V0250.VaultRecordPolicy]::Validate($plainBytes)
        $encoded=[TokenForge.Core.V0190.VaultEnvelope]::Encrypt($plainBytes,$Password)
        $transaction.Commit($encoded)
    }catch{
        # Never forward JSON parser/crypto/IO exceptions, which can retain credential content.
        throw 'Vault operation failed; check passphrase, format, private path permissions, size, and writer availability. Details suppressed.'
    }finally{
        if($plainBytes){[Array]::Clear($plainBytes)}
        if($transaction){$transaction.Dispose()}
        $document=$null
    }
}

# Called only after ScopedToken has matched issued context and confirmed the observer through Graph.
function Save-TokenForgeScopedCredential {
    param([string]$Path,[securestring]$Password,[string]$SessionName,[securestring]$Cookie,[string]$CookieName,$Token,[int]$RetentionHours,$ExpectedRevision,[switch]$ReuseSession)
    $now=[DateTimeOffset]::UtcNow;$claims=$Token.TokenClaims;$request=$Token.Request
    $id=Get-TokenForgeFingerprint -Value (@($claims.TenantFingerprint,$claims.PrincipalFingerprint,$request.Tenant,$request.ClientId,$request.ResourceId,(@($request.Scopes|Sort-Object -Unique) -join ' '),$request.RedirectUri,[string]$request.Spa,$Token.Protocol,(@($request.OAuthScopes) -ccontains 'offline_access')) -join '|')
    Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password -Mode Update -Update {
        param($document)
        $old=$document.Sessions[$SessionName]
        if($ExpectedRevision -and (-not $old -or $old.Revision -ne $ExpectedRevision)){throw 'Saved session changed during token acquisition.'}
        if($old -and ($old.TenantFingerprint -ne $claims.TenantFingerprint -or $old.PrincipalFingerprint -ne $claims.PrincipalFingerprint)){throw 'Session name already belongs to another account or tenant.'}
        $retainCookie=$old -and $old.Cookie -and [TokenForge.Core.V0240.TimestampPolicy]::Parse($old.RetainUntil) -gt $now
        $expiry=@($Token.ExpiresAt,$claims.ExpiresAt|Where-Object {$_}|ForEach-Object {[TokenForge.Core.V0240.TimestampPolicy]::Parse($_)}|Sort-Object|Select-Object -First 1)
        $session=@{
            TenantFingerprint=$claims.TenantFingerprint;PrincipalFingerprint=$claims.PrincipalFingerprint;Revision=[guid]::NewGuid().ToString()
            CreatedAt=if($old){$old.CreatedAt}else{$now.ToString('o')};LastConfirmedAt=$now.ToString('o')
            RetainUntil=if($ReuseSession -or ($retainCookie -and -not $Cookie)){$old.RetainUntil}else{$now.AddHours($RetentionHours).ToString('o')}
            Cookie=if($Cookie){[Net.NetworkCredential]::new('', $Cookie).Password}else{if($retainCookie){$old.Cookie}else{$null}}
            CookieName=if($Cookie){$CookieName}else{if($retainCookie){$old.CookieName}else{$null}}
            Tokens=if($old){$old.Tokens}else{@{}}
        }
        $session.Tokens[$id]=@{
            Id=$id;ClientId=$request.ClientId;ResourceId=$request.ResourceId;Tenant=$request.Tenant;Audience=$claims.Audience
            Scopes=@($request.Scopes);IssuedScopes=@($claims.Scopes);AdditionalScopeCount=$Token.ObservedAdditionalScopeCount
            RedirectUri=$request.RedirectUri;Spa=[bool]$request.Spa;OfflineAccess=@($request.OAuthScopes) -ccontains 'offline_access';Protocol=$Token.Protocol
            AcquiredAt=$now.ToString('o');ExpiresAt=if($expiry.Count){$expiry[0].ToString('o')}else{$null}
            AccessToken=[Net.NetworkCredential]::new('', $Token.AccessToken).Password
            RefreshToken=if($Token.RefreshToken){[Net.NetworkCredential]::new('', $Token.RefreshToken).Password}else{$null}
            ConsentEvidence=$Token.ConsentEvidence
        }
        $document.Sessions[$SessionName]=$session
    }
    $id
}
