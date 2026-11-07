#Requires -Version 7.6
# Offline SHA-1 Git object and canonical PACK v2 support for local proposals.
function ConvertTo-TfLocalGitHex([byte[]]$Bytes) { [Convert]::ToHexString($Bytes).ToLowerInvariant() }
function ConvertFrom-TfLocalGitHex([string]$Hex) {
 if($Hex -cnotmatch '\A[a-f0-9]{40}\z'){throw 'Invalid Git SHA-1.'}
 return ,([Convert]::FromHexString($Hex))
}
function Get-TfLocalGitObject([ValidateSet('blob','tree','commit')][string]$Type,[byte[]]$Bytes) {
 if($null -eq $Bytes -or $Bytes.Length -gt 8MB){throw 'Git object size bound.'}
 $header=[Text.Encoding]::ASCII.GetBytes("$Type $($Bytes.Length)`0")
 $sha=ConvertTo-TfLocalGitHex ([Security.Cryptography.SHA1]::HashData([byte[]]($header+$Bytes)))
 return [ordered]@{Type=$Type;Sha=$sha;Bytes=$Bytes}
}
function Write-TfLocalGitUInt32([IO.Stream]$Stream,[uint32]$Value) {
 $Stream.WriteByte([byte](($Value -shr 24) -band 255));$Stream.WriteByte([byte](($Value -shr 16) -band 255));$Stream.WriteByte([byte](($Value -shr 8) -band 255));$Stream.WriteByte([byte]($Value -band 255))
}
function Get-TfLocalGitTree([object[]]$Entries) {
 $ordered=[object[]]@($Entries)
 [Array]::Sort($ordered,[Comparison[object]]{
  param($left,$right)
  # Git compares UTF-8 name bytes, treating a tree name as if it ended in '/'.
  $ln=[string]$left.Name;if($left.Type -ceq 'tree'){$ln+='/'}
  $rn=[string]$right.Name;if($right.Type -ceq 'tree'){$rn+='/'}
  $lb=[Text.Encoding]::UTF8.GetBytes($ln);$rb=[Text.Encoding]::UTF8.GetBytes($rn)
  for($i=0;$i -lt [Math]::Min($lb.Length,$rb.Length);$i++){if($lb[$i] -ne $rb[$i]){return [int]$lb[$i]-[int]$rb[$i]}}
  return $lb.Length-$rb.Length
 })
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 $ms=[IO.MemoryStream]::new()
 foreach($e in $ordered){
  if(-not $seen.Add([string]$e.Name)){throw 'Duplicate tree name.'}
  $mode=[string]$e.Mode;$name=[string]$e.Name;$sha=[string]$e.Sha
  if($mode -cnotin @('040000','100644','100755','120000','160000') -or ($e.Type -ceq 'tree') -ne ($mode -ceq '040000') -or ($mode -ceq '160000' -and $e.Type -cne 'commit') -or ($mode -cnotin @('040000','160000') -and $e.Type -cne 'blob')){throw 'Invalid tree mode or type.'}
  if($name -ceq '' -or $name -cin @('.','..') -or $name.Contains('/') -or $name.Contains([char]0) -or $name.Contains([char]10) -or $name.Contains([char]13)){throw 'Invalid tree name.'}
  $nb=[Text.UTF8Encoding]::new($false,$true).GetBytes($name)
  if($nb.Length -gt 255){throw 'Tree name bound.'}
  $wireMode=if($mode -ceq '040000'){'40000'}else{$mode}
  $prefix=[Text.Encoding]::ASCII.GetBytes("$wireMode ");$ms.Write($prefix);$ms.Write($nb);$ms.WriteByte(0);$ms.Write((ConvertFrom-TfLocalGitHex $sha))
 }
 return Get-TfLocalGitObject tree $ms.ToArray()
}
function New-TfLocalGitStoredZlib([byte[]]$Bytes) {
 $ms=[IO.MemoryStream]::new();$ms.WriteByte(0x78);$ms.WriteByte(0x01)
 $a=[uint32]1;$b=[uint32]0
 foreach($v in $Bytes){$a=($a+[uint32]$v)%65521;$b=($b+$a)%65521}
 $position=0
 do {
  $length=[Math]::Min(65535,$Bytes.Length-$position);$final=($position+$length -eq $Bytes.Length)
  $ms.WriteByte([byte]$(if($final){1}else{0}))
  $ms.WriteByte([byte]($length -band 255));$ms.WriteByte([byte]($length -shr 8))
  $inverse=65535-$length;$ms.WriteByte([byte]($inverse -band 255));$ms.WriteByte([byte]($inverse -shr 8))
  $ms.Write($Bytes,$position,$length);$position+=$length
 }while(-not $final)
 Write-TfLocalGitUInt32 $ms ([uint32](([long]$b -shl 16) -bor [long]$a))
 return ,$ms.ToArray()
}
function New-TfLocalGitPack([object[]]$Objects) {
 if($Objects.Count -gt 10000){throw 'Git object count bound.'}
 $ms=[IO.MemoryStream]::new();$ms.Write([Text.Encoding]::ASCII.GetBytes('PACK'));Write-TfLocalGitUInt32 $ms 2;Write-TfLocalGitUInt32 $ms ([uint32]$Objects.Count)
 $types=@{commit=1;tree=2;blob=3}
 foreach($obj in $Objects){
  if($obj.Type -cnotin @('commit','tree','blob') -or $obj.Bytes.Length -gt 8MB){throw 'Git pack object.'}
  $size=[int]$obj.Bytes.Length;$first=(($types[$obj.Type] -shl 4) -bor ($size -band 15));$size=$size -shr 4
  if($size){$first=$first -bor 0x80};$ms.WriteByte([byte]$first)
  while($size){$next=$size -band 127;$size=$size -shr 7;if($size){$next=$next -bor 0x80};$ms.WriteByte([byte]$next)}
  $ms.Write((New-TfLocalGitStoredZlib $obj.Bytes))
  if($ms.Length -gt 8MB-20){throw 'Git pack size bound.'}
 }
 $body=$ms.ToArray();$ms.Write([Security.Cryptography.SHA1]::HashData($body))
 if($ms.Length -gt 8MB){throw 'Git pack size bound.'}
 return ,$ms.ToArray()
}
function New-TfLocalGitProposal {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$Parent,[Parameter(Mandatory)][string]$BaseTreeSha,[Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BaseEntries,[Parameter(Mandatory)][Collections.IDictionary]$Files,[Parameter(Mandatory)][string]$CandidateHash,[Parameter(Mandatory)][long]$UnixSeconds,[Parameter(Mandatory)][string]$AuthorName,[Parameter(Mandatory)][string]$AuthorEmail)
 $null=ConvertFrom-TfLocalGitHex $Parent;$null=ConvertFrom-TfLocalGitHex $BaseTreeSha
 if($Parent -ceq ('0'*40) -or $CandidateHash -cnotmatch '\A[a-f0-9]{64}\z' -or $UnixSeconds -lt 0 -or $UnixSeconds -gt 253402300799){throw 'Proposal identity bound.'}
 if($AuthorName -cnotmatch '\A[^<>\x00-\x1f\x7f]{1,128}\z' -or $AuthorEmail -cnotmatch '\A[^<>\s\x00-\x1f\x7f]{1,128}@[^<>\s\x00-\x1f\x7f]{1,128}\z'){throw 'Invalid commit author.'}
 $names=@('coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json')
 if($Files.Count -ne 7 -or @($Files.Keys|Where-Object {$_ -cnotin $names}).Count){throw 'Candidate file membership.'}
 $base=@{};$known=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$null=$known.Add($Parent);$null=$known.Add($BaseTreeSha)
 if($BaseEntries.Count -gt 10000){throw 'Base tree entry bound.'}
 foreach($item in $BaseEntries){
  $path=[string]$item.path;$segments=$path.Split('/')
  if($path -ceq '' -or $segments.Count -gt 64 -or $segments|Where-Object {$_ -ceq '' -or $_ -cin @('.','..')}){throw 'Invalid base tree path.'}
  if($base.ContainsKey($path)){throw 'Duplicate base tree path.'}
  $entry=[ordered]@{path=$path;mode=[string]$item.mode;type=[string]$item.type;sha=[string]$item.sha}
  $null=ConvertFrom-TfLocalGitHex $entry.sha
  $base[$path]=$entry;$null=$known.Add($entry.sha)
 }
 if($base.ContainsKey("candidates/$CandidateHash") -or @($base.Keys|Where-Object {$_ -clike "candidates/$CandidateHash/*"}).Count){throw 'Candidate path already exists.'}
 # Verify the caller supplied the complete recursive inventory, including every tree ID.
 $treePaths=@($base.Keys|Where-Object {$base[$_].type -ceq 'tree'}|Sort-Object @{Expression={$_.Split('/').Count};Descending=$true})
 foreach($path in $treePaths){
  $children=@($base.Keys|Where-Object {($_ -clike "$path/*") -and $_.Substring($path.Length+1).IndexOf('/') -lt 0}|ForEach-Object {$base[$_]})
  $tree=Get-TfLocalGitTree @($children|ForEach-Object {[ordered]@{Name=$_.path.Substring($path.Length+1);Mode=$_.mode;Type=$_.type;Sha=$_.sha}})
  if($tree.Sha -cne $base[$path].sha){throw 'Base subtree SHA mismatch.'}
 }
 foreach($path in $base.Keys){
  $segments=$path.Split('/');for($i=1;$i -lt $segments.Count;$i++){$ancestor=($segments[0..($i-1)] -join '/');if(-not $base.ContainsKey($ancestor) -or $base[$ancestor].type -cne 'tree'){throw 'Incomplete base tree inventory.'}}
 }
 $root=@($base.Keys|Where-Object {$_.IndexOf('/') -lt 0}|ForEach-Object {$base[$_]})
 $rootTree=Get-TfLocalGitTree @($root|ForEach-Object {[ordered]@{Name=$_.path;Mode=$_.mode;Type=$_.type;Sha=$_.sha}})
 if($rootTree.Sha -cne $BaseTreeSha){throw 'Base root SHA mismatch.'}
 if($base.ContainsKey('candidates') -and ($base['candidates'].type -cne 'tree' -or $base['candidates'].mode -cne '040000')){throw 'Invalid candidates tree.'}
 $objects=[Collections.Generic.List[object]]::new();$entries=[Collections.Generic.List[object]]::new();foreach($path in $base.Keys){$entries.Add($base[$path])}
 $candidateChildren=[Collections.Generic.List[object]]::new()
 foreach($name in $names){
  if(-not $Files.Contains($name) -or $Files[$name] -isnot [byte[]]){throw 'Candidate file bytes.'}
  $data=[byte[]]$Files[$name];if($data.Length -gt 8MB){throw 'Candidate file size.'}
  $blob=Get-TfLocalGitObject blob $data
  $path="candidates/$CandidateHash/$name";$entries.Add([ordered]@{path=$path;mode='100644';type='blob';sha=$blob.Sha})
  $candidateChildren.Add([ordered]@{Name=$name;Mode='100644';Type='blob';Sha=$blob.Sha})
  if($known.Add($blob.Sha)){$objects.Add($blob)}
 }
 $candidateTree=Get-TfLocalGitTree $candidateChildren.ToArray();$entries.Add([ordered]@{path="candidates/$CandidateHash";mode='040000';type='tree';sha=$candidateTree.Sha})
 if($known.Add($candidateTree.Sha)){$objects.Add($candidateTree)}
 $candidateRoot=@($base.Keys|Where-Object {$_.StartsWith('candidates/') -and $_.Substring(11).IndexOf('/') -lt 0}|ForEach-Object {$base[$_]})
 $candidateRoot+= [ordered]@{path="candidates/$CandidateHash";mode='040000';type='tree';sha=$candidateTree.Sha}
 $candidatesTree=Get-TfLocalGitTree @($candidateRoot|ForEach-Object {[ordered]@{Name=$_.path.Substring(11);Mode=$_.mode;Type=$_.type;Sha=$_.sha}})
 if($base.ContainsKey('candidates')){for($i=0;$i -lt $entries.Count;$i++){if($entries[$i].path -ceq 'candidates'){$entries[$i]=[ordered]@{path='candidates';mode='040000';type='tree';sha=$candidatesTree.Sha};break}}}
 else{$entries.Add([ordered]@{path='candidates';mode='040000';type='tree';sha=$candidatesTree.Sha})}
 if($known.Add($candidatesTree.Sha)){$objects.Add($candidatesTree)}
 $newRoot=@($root|Where-Object {$_.path -cne 'candidates'})+[ordered]@{path='candidates';mode='040000';type='tree';sha=$candidatesTree.Sha}
 $proposedTree=Get-TfLocalGitTree @($newRoot|ForEach-Object {[ordered]@{Name=$_.path;Mode=$_.mode;Type=$_.type;Sha=$_.sha}})
 if($known.Add($proposedTree.Sha)){$objects.Add($proposedTree)}
 if($entries.Count -gt 10000){throw 'Proposed tree entry bound.'}
 $person="$AuthorName <$AuthorEmail> $UnixSeconds +0000"
 $commitBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes("tree $($proposedTree.Sha)`nparent $Parent`nauthor $person`ncommitter $person`n`nTokenForge candidate $CandidateHash`n")
 $commit=Get-TfLocalGitObject commit $commitBytes
 if(-not $known.Add($commit.Sha)){throw 'Proposed commit already exists.'};$objects.Add($commit)
 $sorted=@($objects.ToArray()|Sort-Object Sha -CaseSensitive)
 $pack=New-TfLocalGitPack $sorted
 $inventory=[Text.Encoding]::ASCII.GetBytes(((@($sorted|ForEach-Object {"$($_.Type) $($_.Sha) $($_.Bytes.Length)"}) -join "`n")+"`n"))
 $result=[ordered]@{Parent=$Parent;BaseTree=$BaseTreeSha;ProposedCommit=$commit.Sha;ProposedTree=$proposedTree.Sha;Entries=@($entries.ToArray()|Sort-Object path -CaseSensitive);Objects=$sorted;Pack=$pack;PackSha256=(ConvertTo-TfLocalGitHex ([Security.Cryptography.SHA256]::HashData($pack)));InventorySha256=(ConvertTo-TfLocalGitHex ([Security.Cryptography.SHA256]::HashData($inventory)))}
 $null=Assert-TfLocalGitPack -Bytes $pack -Objects $sorted
 return $result
}
function Read-TfLocalGitTreeLinks([byte[]]$Bytes) {
 $items=[Collections.Generic.List[object]]::new();$offset=0
 while($offset -lt $Bytes.Length){
  $start=$offset
  while($offset -lt $Bytes.Length -and $Bytes[$offset] -ne 32){$offset++}
  if($offset -eq $Bytes.Length){throw 'Truncated tree mode.'}
  $mode=[Text.Encoding]::ASCII.GetString($Bytes,$start,$offset-$start);$offset++;$start=$offset
  while($offset -lt $Bytes.Length -and $Bytes[$offset] -ne 0){$offset++}
  if($offset -eq $Bytes.Length -or $offset+21 -gt $Bytes.Length){throw 'Truncated tree entry.'}
  $name=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes,$start,$offset-$start);$offset++
  $sha=ConvertTo-TfLocalGitHex ([byte[]]$Bytes[$offset..($offset+19)]);$offset+=20
  $type=if($mode -ceq '40000'){'tree'}elseif($mode -ceq '160000'){'commit'}else{'blob'}
  $publicMode=if($mode -ceq '40000'){'040000'}else{$mode}
  $items.Add([ordered]@{Name=$name;Mode=$publicMode;Type=$type;Sha=$sha})
 }
 $canonical=Get-TfLocalGitTree $items.ToArray()
 if($canonical.Bytes.Length -ne $Bytes.Length){throw 'Noncanonical tree length.'}
 for($i=0;$i -lt $Bytes.Length;$i++){if($canonical.Bytes[$i] -ne $Bytes[$i]){throw 'Noncanonical tree bytes.'}}
 return ,$items.ToArray()
}
function Assert-TfLocalGitPack {
 [CmdletBinding()]param([Parameter(Mandatory)][byte[]]$Bytes,[Parameter(Mandatory)][object[]]$Objects)
 if($Bytes.Length -lt 32 -or $Bytes.Length -gt 8MB -or $Objects.Count -gt 10000){throw 'Git pack bound.'}
 $n=$Bytes.Length;$offset=0
 function ReadByte {if($script:tfOffset -ge $script:tfN){throw 'Truncated pack.'};$v=$script:tfBytes[$script:tfOffset];$script:tfOffset++;return [int]$v}
 # Keep parser state scoped to this call, including all nested reads.
 $script:tfBytes=$Bytes;$script:tfN=$n;$script:tfOffset=0
 try {
  foreach($c in @(80,65,67,75,0,0,0,2)){if((ReadByte) -ne $c){throw 'Git pack header.'}}
  $count=0;for($i=0;$i -lt 4;$i++){$count=($count -shl 8) -bor (ReadByte)}
  if($count -ne $Objects.Count -or $count -gt 10000){throw 'Git pack object count.'}
  $actual=[Collections.Generic.List[object]]::new();$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  for($objectIndex=0;$objectIndex -lt $count;$objectIndex++){
   $v=ReadByte;$kind=($v -shr 4) -band 7;$size=[long]($v -band 15);$shift=4;$continuation=($v -band 128) -ne 0
   while($continuation){if($shift -gt 32){throw 'Git size encoding.'};$v=ReadByte;$size=$size -bor ([long]($v -band 127) -shl $shift);$shift+=7;$continuation=($v -band 128) -ne 0}
   if($size -gt 8MB -or $kind -notin @(1,2,3)){throw 'Git object type or size.'}
   if((ReadByte) -ne 0x78 -or (ReadByte) -ne 0x01){throw 'Noncanonical zlib header.'}
   $payload=[IO.MemoryStream]::new();$a=[uint32]1;$b=[uint32]0
   do {
    $flag=ReadByte;if($flag -notin @(0,1)){throw 'Noncanonical stored block.'}
    $len=(ReadByte) -bor ((ReadByte) -shl 8);$inv=(ReadByte) -bor ((ReadByte) -shl 8)
    if(($len -bxor $inv) -ne 65535 -or $len -ne [Math]::Min(65535,$size-$payload.Length) -or $script:tfOffset+$len -gt $n-20){throw 'Stored block framing.'}
    $payload.Write($Bytes,$script:tfOffset,$len)
    for($j=$script:tfOffset;$j -lt $script:tfOffset+$len;$j++){$a=($a+[uint32]$Bytes[$j])%65521;$b=($b+$a)%65521}
    $script:tfOffset+=$len
   }while($flag -eq 0)
   $adler=0;for($i=0;$i -lt 4;$i++){$adler=([long]$adler -shl 8) -bor (ReadByte)}
   if($adler -ne (([long]$b -shl 16) -bor [long]$a) -or $payload.Length -ne $size){throw 'Git Adler or length.'}
   $type=@{1='commit';2='tree';3='blob'}[$kind];$obj=Get-TfLocalGitObject $type $payload.ToArray()
   if(-not $seen.Add($obj.Sha)){throw 'Duplicate Git object.'};$actual.Add($obj)
  }
  if($script:tfOffset -ne $n-20){throw 'Trailing Git pack data.'}
  $digest=[Security.Cryptography.SHA1]::HashData([byte[]]$Bytes[0..($n-21)])
  for($i=0;$i -lt 20;$i++){if($Bytes[$n-20+$i] -ne $digest[$i]){throw 'Git pack trailer.'}}
  $expected=@($Objects|Sort-Object Sha -CaseSensitive)
  for($i=0;$i -lt $count;$i++){
   if($actual[$i].Sha -cne $expected[$i].Sha -or $actual[$i].Type -cne $expected[$i].Type -or $actual[$i].Bytes.Length -ne $expected[$i].Bytes.Length){throw 'Git object inventory mismatch.'}
   for($j=0;$j -lt $actual[$i].Bytes.Length;$j++){if($actual[$i].Bytes[$j] -ne $expected[$i].Bytes[$j]){throw 'Git object bytes mismatch.'}}
  }
  $commits=@($actual|Where-Object {$_.Type -ceq 'commit'})
  if($commits.Count -ne 1){throw 'Git pack must contain one proposed commit.'}
  $commitText=[Text.UTF8Encoding]::new($false,$true).GetString($commits[0].Bytes)
  if($commitText -cnotmatch '\Atree ([a-f0-9]{40})\nparent [a-f0-9]{40}\nauthor ([^<>\x00-\x1f\x7f]+ <[^<>\s\x00-\x1f\x7f]+> [0-9]+ \+0000)\ncommitter \2\n\nTokenForge candidate [a-f0-9]{64}\n\z'){throw 'Proposed commit metadata.'}
  $rootSha=$Matches[1]
  $bySha=@{};foreach($item in $actual){$bySha[$item.Sha]=$item}
  $reachable=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$null=$reachable.Add($commits[0].Sha)
  $pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($rootSha)
  while($pending.Count){
   $sha=$pending.Dequeue();if(-not $bySha.ContainsKey($sha) -or -not $reachable.Add($sha)){continue}
   $item=$bySha[$sha];if($item.Type -cne 'tree'){throw 'Git tree reference type.'}
   foreach($link in (Read-TfLocalGitTreeLinks $item.Bytes)){
    if($bySha.ContainsKey($link.Sha)){
     if($bySha[$link.Sha].Type -cne $link.Type){throw 'Git object reference type.'}
     if($link.Type -ceq 'tree'){$pending.Enqueue($link.Sha)}else{$null=$reachable.Add($link.Sha)}
    }
   }
  }
  if($reachable.Count -ne $count){throw 'Surplus or unreferenced Git object.'}
  $canonical=New-TfLocalGitPack $expected
  if($canonical.Length -ne $n){throw 'Noncanonical Git pack length.'}
  for($i=0;$i -lt $n;$i++){if($canonical[$i] -ne $Bytes[$i]){throw 'Noncanonical Git pack bytes.'}}
  return $true
 }finally{Remove-Variable tfBytes,tfN,tfOffset -Scope Script -ErrorAction SilentlyContinue}
}
