function Export-TokenForgeVaultView {
    <# .SYNOPSIS
    Create an offline teaching viewer from whitelisted vault metadata; no credential values or backend.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][securestring]$Password,[Parameter(Mandatory)][string]$OutputPath)
    $full=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    if([IO.Path]::GetExtension($full) -ine '.html' -or (Test-Path -LiteralPath $full)){throw 'Choose a new HTML output file; existing files are never overwritten.'}
    $metadata=Get-TokenForgeVault -Path $Path -Password $Password
    $json=($metadata|ConvertTo-Json -Depth 16 -Compress).Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
    $template=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../viewer/vault.html') -Raw
    $html=$template.Replace('@DATA@',$json).Replace("`r`n","`n").Replace("`r","`n")
    foreach($part in @(@{Tag='script';Marker='@SCRIPT_HASH@'},@{Tag='style';Marker='@STYLE_HASH@'})){
        $content=[regex]::Match($html,"(?s)<$($part.Tag)>(.*?)</$($part.Tag)>").Groups[1].Value
        $hash=[Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($content)))
        $html=$html.Replace($part.Marker,$hash)
    }
    # CreateNew prevents a check/write race from overwriting another file.
    $stream=$null
    try{
        $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write;$options.Share=[IO.FileShare]::None
        if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
        $stream=[IO.FileStream]::new($full,$options);$bytes=[Text.Encoding]::UTF8.GetBytes($html);$stream.Write($bytes)
    }finally{if($stream){$stream.Dispose()}}
    [pscustomobject]@{Created=$true;SessionCount=$metadata.Sessions.Count;Evidence='MetadataOnlyOfflineTeachingView'}
}
