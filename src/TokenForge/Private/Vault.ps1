# These helpers share the private-path and encrypted transaction boundary used by all vault operations.
function Resolve-TokenForgeVaultPath {
    param([string]$Path,[switch]$CreateDirectory)
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    if($full.StartsWith('\\')){throw 'Vaults require a local filesystem path.'}
    $parent=[IO.Path]::GetDirectoryName($full)
    for($part=$full;$part;$part=[IO.Path]::GetDirectoryName($part)){
        $item=Get-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        if($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Vault paths must not contain links or reparse points.'}
    }
    if(-not [IO.Directory]::Exists($parent)){
        if(-not $CreateDirectory){throw 'Vault directory does not exist.'}
        if($IsWindows){
            $security=[Security.AccessControl.DirectorySecurity]::new()
            $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
            $security.SetOwner($sid);$security.SetAccessRuleProtection($true,$false)
            $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
            [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($parent),$security)
        }else{$null=[IO.Directory]::CreateDirectory($parent,[IO.UnixFileMode]448)}
    }
    foreach($part in @($parent,$full)){
        $item=Get-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
        if(-not $item){continue}
        if($part -eq $full -and $item.PSIsContainer){throw 'Vault path must be a regular file.'}
        if(-not $IsWindows){
            if(([int]$item.UnixFileMode -band 63)){throw 'Vault files and their directory must exclude group and other access.'}
        }else{
            $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            $acl=Get-Acl -LiteralPath $part
            if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'Vault path is owned by another identity.'}
            foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
                if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($sid,'S-1-5-18','S-1-5-32-544')){throw 'Vault ACL permits another identity.'}
            }
        }
    }
    $full
}

function Open-TokenForgeVaultFile {
    param([string]$Path,[switch]$Create)
    if($Create -and $IsWindows){
        $security=[Security.AccessControl.FileSecurity]::new()
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.SetOwner($sid);$security.SetAccessRuleProtection($true,$false)
        $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow'))
        return [IO.FileSystemAclExtensions]::Create([IO.FileInfo]::new($Path),[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$security)
    }
    $options=[IO.FileStreamOptions]::new()
    $options.Mode=if($Create){[IO.FileMode]::CreateNew}else{[IO.FileMode]::Open}
    $options.Access=[IO.FileAccess]::ReadWrite;$options.Share=[IO.FileShare]::None
    if($Create -and -not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
    [IO.FileStream]::new($Path,$options)
}

function Invoke-TokenForgeVaultTransaction {
    param([string]$Path,[securestring]$Password,[ValidateSet('Read','Create','Update')][string]$Mode='Read',[scriptblock]$Update)
    $lock=$null;$stream=$null;$plainBytes=$null;$temporary=$null;$document=$null
    try{
        if(-not $Password -or $Password.Length -lt 12 -or $Password.Length -gt 1024){throw 'Vault passphrase must contain 12 to 1024 characters.'}
        if(-not [Security.Cryptography.AesGcm]::IsSupported){throw 'Authenticated vault encryption is unavailable on this platform.'}
        $full=Resolve-TokenForgeVaultPath -Path $Path -CreateDirectory:($Mode -eq 'Create')
        $lockPath=Resolve-TokenForgeVaultPath -Path "$full.lock"
        if(-not [IO.File]::Exists($lockPath)){
            try{$lock=Open-TokenForgeVaultFile -Path $lockPath -Create}catch [IO.IOException]{}
        }
        if(-not $lock){try{$lock=Open-TokenForgeVaultFile -Path $lockPath}catch{throw 'Vault is unavailable or in use by another operation.'}}
        if($Mode -eq 'Create'){
            if([IO.File]::Exists($full)){throw 'Vault already exists; refusing to overwrite.'}
            $document=@{SchemaVersion=1;Sessions=@{}}
        }else{
            if(-not [IO.File]::Exists($full)){throw 'Vault does not exist; initialize it explicitly.'}
            $stream=Open-TokenForgeVaultFile -Path $full
            if($stream.Length -gt 16777216 -or $stream.Length -lt 100){throw 'Invalid vault envelope size.'}
            $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes);$stream.Dispose();$stream=$null
            $plainBytes=[TokenForge.Core.V0190.VaultEnvelope]::Decrypt($bytes,$Password)
            $document=[Text.Encoding]::UTF8.GetString($plainBytes)|ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
            [Array]::Clear($plainBytes);$plainBytes=$null
            if($document.SchemaVersion -ne 1 -or $document.Sessions -isnot [Collections.IDictionary]){throw 'Invalid vault records.'}
        }
        if($Mode -eq 'Read'){return $document}
        if($Update){$null=& $Update $document}
        $plainBytes=[Text.Encoding]::UTF8.GetBytes(($document|ConvertTo-Json -Depth 32 -Compress))
        if($plainBytes.Length -gt 8388608){throw 'Vault exceeds its 8 MiB record limit.'}
        $encoded=[TokenForge.Core.V0190.VaultEnvelope]::Encrypt($plainBytes,$Password)
        $temporary=Join-Path ([IO.Path]::GetDirectoryName($full)) ([guid]::NewGuid().ToString()+'.tmp')
        $stream=Open-TokenForgeVaultFile -Path $temporary -Create
        $stream.Write($encoded);$stream.Flush($true);$stream.Dispose();$stream=$null
        [IO.File]::Move($temporary,$full,($Mode -eq 'Update'));$temporary=$null
    }catch{
        # Never forward JSON parser/crypto/IO exceptions, which can retain credential content.
        throw 'Vault operation failed; check passphrase, format, private path permissions, size, and writer availability. Details suppressed.'
    }finally{
        if($stream){$stream.Dispose()};if($lock){$lock.Dispose()}
        if($plainBytes){[Array]::Clear($plainBytes)}
        if($temporary){Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
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
        $retainCookie=$old -and $old.Cookie -and [DateTimeOffset]::Parse($old.RetainUntil) -gt $now
        $expiry=@($Token.ExpiresAt,$claims.ExpiresAt|Where-Object {$_}|ForEach-Object {[DateTimeOffset]::Parse([string]$_)}|Sort-Object|Select-Object -First 1)
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
