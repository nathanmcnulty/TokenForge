function Get-TokenForgeDiscoveryRunId {
    param([string]$Path)
    $stream=$null
    try{
        $full=Resolve-TokenForgeVaultPath $Path
        $stream=[IO.File]::OpenRead($full)
        if($stream.Length -lt 1 -or $stream.Length -gt 1024){throw 'Invalid size.'}
        $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
        if($stream.ReadByte() -ne -1){throw 'Manifest changed.'}
        $saved=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
        if($saved.Count -ne 2 -or -not $saved.Contains('SchemaVersion') -or -not $saved.Contains('CohortId') -or ($saved.SchemaVersion -isnot [int] -and $saved.SchemaVersion -isnot [long]) -or $saved.SchemaVersion -ne 1 -or $saved.CohortId -isnot [string] -or $saved.CohortId -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid fields.'}
        $saved.CohortId
    }catch{throw 'Invalid discovery run manifest.'}finally{if($stream){$stream.Dispose()}}
}
