. "$PSScriptRoot/AdapterFixture.ps1"

function New-PublicationWriterFixture([string]$Parent) {
 $f=New-PublicationAdapterFixture $Parent
 $options=$f.Options.Clone()
 $transaction=(Invoke-TokenForgePublicationVerification @options).Transaction
 $f.Packet=(Get-Command ConvertTo-TfGitPacket).ScriptBlock
 $f.ExpectedBody=New-TfGitUpdate $f.Old $f.New 'refs/heads/discovery-data'
 $f.Mode='Success';$f.Posts=0;$f.GitReads=0
 $f.WriteFixture={param($method,$body)
  if($method -ceq 'GET'){
   $f.GitReads++
   $sha=$f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha
   $bytes=[byte[]]((& $f.Packet "# service=git-receive-pack`n")+[Text.Encoding]::ASCII.GetBytes('0000')+(& $f.Packet ($sha+" refs/heads/discovery-data`0report-status object-format=sha1`n"))+[Text.Encoding]::ASCII.GetBytes('0000'))
   return @{Status=200;ContentType='application/x-git-receive-pack-advertisement';Bytes=$bytes}
  }
  $f.Posts++
  if([Convert]::ToHexString($body) -cne [Convert]::ToHexString($f.ExpectedBody)){throw 'Unexpected command bytes.'}
  if($f.Mode -ceq 'PreSendLoss'){throw 'Synthetic transport loss before application.'}
  if($f.Mode -ceq 'Reject'){$status="ng refs/heads/discovery-data synthetic rejection`n"}
  else{
   $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.New
   $status="ok refs/heads/discovery-data`n"
  }
  if($f.Mode -ceq 'Rewind'){$f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.Old}
  if($f.Mode -ceq 'LostAck'){throw 'Synthetic acknowledgement loss.'}
  $bytes=[byte[]]((& $f.Packet "unpack ok`n")+(& $f.Packet $status)+[Text.Encoding]::ASCII.GetBytes('0000'))
  if($f.Mode -ceq 'Malformed'){$bytes=[Text.Encoding]::ASCII.GetBytes('0008bad!')}
  @{Status=200;ContentType='application/x-git-receive-pack-result';Bytes=$bytes}
 }.GetNewClosure()
 $f.WriterOptions=$options.Clone();$f.WriterOptions.ApprovedTransaction=$transaction;$f.WriterOptions.ExecutePublication=$true;$f.WriterOptions.WriteFixture=$f.WriteFixture
 $f.RecoveryOptions=@{PolicyPath=$f.PolicyPath;PolicySha256=$f.PolicyHash;Transaction=$transaction;Synthetic=$true;ReadFixture=$options.ReadFixture}
 $f.Journal=Join-Path $f.Policy.JournalRoot '100-discovery-data/writer.json'
 return $f
}
