function Find-TokenForgeApplicationEvidence {
    <#
    .SYNOPSIS
    Search public application metadata and optional anonymous scope exports without authentication.
    .DESCRIPTION
    Returns separate ledger and observation records without combining their scopes. All requested scopes
    must occur in one row for one resource (case-sensitive). Freshness describes the source date,
    not current token availability. Anonymous observations cannot establish consent for your account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$ObservationPath=@(),
        [string]$Name,
        [guid]$AppId=[guid]::Empty,
        [guid]$ResourceId=[guid]::Empty,
        [ValidateCount(1,64)][ValidatePattern('^[A-Za-z0-9_.-]{1,256}$')][string[]]$Scope,
        [ValidateRange(1,8760)][int]$MaxAgeHours=168,
        [string]$NativeExecutablePath
    )
    # Validate the complete public ledger, including history, before selecting any rows.
    $catalog=Get-TokenForgeApplicationMetadata -Path $Path -PublicOnly -NativeExecutablePath $NativeExecutablePath
    $rows=[Collections.Generic.List[object]]::new()
    $names=@{}
    foreach($app in $catalog.Applications.Values){
        foreach($record in $app.Records.Values){
            $attributes=$record.Attributes
            $nameValue=if($attributes.Contains('Name')){[string]$attributes.Name}else{''}
            $names[$app.AppId]=$nameValue
            $common=@{
                AppId=$app.AppId;Name=$nameValue;ObservedAt=$record.LastSeenAt
                PresentInLatestRun=$record.PresentInLatestRun;Sources=@($record.Sources)
                ContentSha256=$record.ContentSha256
                SourceClaims=if($attributes.Contains('SourceClaims')){@($attributes.SourceClaims)}else{@()}
                MetadataConflicts=if($attributes.Contains('MetadataConflicts')){@($attributes.MetadataConflicts)}else{@()}
            }
            $row=$common.Clone();$row.ResourceId=$null;$row.Scopes=@();$row.EvidenceType='PublishedApplicationMetadata'
            $rows.Add([pscustomobject]$row)
            if($attributes.Contains('Grants')){foreach($grant in $attributes.Grants){
                $row=$common.Clone();$row.ResourceId=$grant.ResourceId;$row.Scopes=@($grant.Scopes);$row.EvidenceType='PublishedScopeHint'
                $rows.Add([pscustomobject]$row)
            }}
        }
    }
    foreach($filePath in $ObservationPath){
        try{
            $file=Get-Item -LiteralPath $filePath -ErrorAction Stop
            if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 67108864){throw 'Invalid public export file.'}
            for($part=$file.Directory;$null -ne $part;$part=$part.Parent){
                if($part.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked public export directory.'}
            }
            $stream=[IO.FileStream]::new($file.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
            try{
                if($stream.Length -gt 67108864){throw 'Invalid public export size.'}
                $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes,0,$bytes.Length)
                if($stream.ReadByte() -ne -1){throw 'Public export changed during reading.'}
                $offset=if($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191){3}else{0}
                $json=[Text.UTF8Encoding]::new($false,$true).GetString($bytes,$offset,$bytes.Length-$offset)
            }finally{$stream.Dispose()}
            $document=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($json)
            if(@($document.Keys|Where-Object {$_ -cnotin @('SchemaVersion','Observations','Disclaimer')}).Count -or ($document.SchemaVersion -isnot [int] -and $document.SchemaVersion -isnot [long]) -or $document.SchemaVersion -ne 1 -or $document.Observations -isnot [array]){throw 'Invalid public export.'}
            if($document.Contains('Disclaimer') -and $document.Disclaimer -isnot [string]){throw 'Invalid public disclaimer.'}
            $hash=Get-TokenForgeFingerprint -Value $json
            foreach($observation in $document.Observations){
                if($observation -isnot [Collections.IDictionary] -or @($observation.Keys|Where-Object {$_ -cnotin @('ClientId','ResourceId','ObservedAt','Scopes','Evidence','SignatureValidated')}).Count){throw 'Unexpected public observation fields.'}
                foreach($field in @('ClientId','ResourceId')){
                    $id=[guid]::Empty
                    if(-not [guid]::TryParse([string]$observation[$field],[ref]$id) -or $id -eq [guid]::Empty -or $observation[$field] -cne $id.ToString()){throw 'Invalid public identifier.'}
                }
                $date=[DateTimeOffset]::MinValue
                if(-not [TokenForge.Core.V0240.TimestampPolicy]::TryParse($observation.ObservedAt,[ref]$date) -or $observation.Evidence -cne 'AnonymousTenantTokenObservation' -or $observation.SignatureValidated -isnot [bool] -or $observation.SignatureValidated -or $observation.Scopes -isnot [array] -or @($observation.Scopes|Where-Object {$_ -isnot [string] -or $_ -cnotmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count){throw 'Invalid public observation evidence.'}
                $rows.Add([pscustomobject]@{
                    AppId=$observation.ClientId;Name=$names[$observation.ClientId];ResourceId=$observation.ResourceId
                    Scopes=@($observation.Scopes);EvidenceType='AnonymousTenantTokenObservation'
                    ObservedAt=$date.ToUniversalTime().ToString('o');PresentInLatestRun=$null
                    Sources=@([pscustomobject]@{Name='PublicScopeExport';Location=$file.FullName;Evidence=$observation.Evidence})
                    ContentSha256=$hash;SourceClaims=@();MetadataConflicts=@()
                })
            }
        }catch{throw 'Public scope export cannot be read; check format, size, and file access. Details suppressed.'}
    }
    $now=[DateTimeOffset]::UtcNow
    foreach($row in $rows|Sort-Object AppId,EvidenceType,ResourceId,ObservedAt){
        if($AppId -ne [guid]::Empty -and $row.AppId -ne $AppId.ToString()){continue}
        if($Name -and ([string]$row.Name).IndexOf($Name,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
        if($ResourceId -ne [guid]::Empty -and $row.ResourceId -ne $ResourceId.ToString()){continue}
        if($Scope -and @($Scope|Where-Object {$row.Scopes -cnotcontains $_}).Count){continue}
        $date=[TokenForge.Core.V0240.TimestampPolicy]::Parse($row.ObservedAt)
        $freshness=if($date -gt $now.AddMinutes(5)){'FutureDated'}elseif($date -lt $now.AddHours(-$MaxAgeHours)){'Stale'}else{'Fresh'}
        $row|Add-Member -NotePropertyName Freshness -NotePropertyValue $freshness
        $row|Add-Member -NotePropertyName Disclaimer -NotePropertyValue 'Metadata and anonymous observations do not guarantee consent, token acquisition, or API access for your account.'
        $row
    }
}
