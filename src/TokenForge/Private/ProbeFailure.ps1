function Get-TokenForgeProbeFailure {
    param([Management.Automation.ErrorRecord]$ErrorRecord)
    # Only numeric diagnostics from the existing sanitized transport are retained.
    # A decline is evidence for this request, never for an application globally.
    $known=@('50058','50076','50079','500133','50173','700082','700084','70043','70000','65001','65004','50105','53000','53001','53003','50011','700016','7000218','7000215')
    $codes=@([regex]::Matches($ErrorRecord.Exception.Message,'\bAADSTS([0-9]{4,9})\b')|ForEach-Object {$_.Groups[1].Value}|Where-Object {$_ -cin $known}|Sort-Object -Unique)
    $status=if($ErrorRecord.FullyQualifiedErrorId -match '^TokenForge\.(Budget|Cancelled|Deadline)'){'BudgetReached'}
        elseif($ErrorRecord.Exception.Message -match 'Identity transport failed or timed out'){'InFlightUnknown'}
        elseif($ErrorRecord.Exception.Message -match '\bHTTP (429|5[0-9]{2})\b'){'TransientFailure'}
        elseif(@($codes|Where-Object {$_ -in @('50058','50076','50079','500133','50173','700082','700084','70043','70000')}).Count){'SessionPaused'}
        elseif(@($codes|Where-Object {$_ -in @('65001','65004','50105','53000','53001','53003')}).Count){'RequestBlocked'}
        elseif(@($codes|Where-Object {$_ -in @('50011','700016','7000218','7000215')}).Count){'Failed'}
        else{'SessionPaused'}
    [pscustomobject]@{Status=$status;ErrorCodes=$codes}
}
