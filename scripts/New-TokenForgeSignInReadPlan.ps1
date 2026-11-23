#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)]$Context,
    [Parameter(Mandatory)]$Environment,
    [Parameter(Mandatory)][DateTimeOffset]$Since,
    [Parameter(Mandatory)][DateTimeOffset]$Until
)

$PSDefaultParameterValues = @{ Disabled = $true }
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$actualTenant = [guid]::Empty
if ($TenantId -eq [guid]::Empty -or
    ($Context.TenantId -isnot [string] -and $Context.TenantId -isnot [guid]) -or
    -not [guid]::TryParseExact([string]$Context.TenantId, 'D', [ref]$actualTenant) -or
    $actualTenant -ne $TenantId) {
    throw 'The existing SDK context must match the explicitly selected tenant.'
}
if ([string]$Context.AuthType -cne 'Delegated' -or [string]$Context.ContextScope -cne 'Process' -or
    'AuditLog.Read.All' -cnotin $Context.Scopes) {
    throw 'A process-scoped delegated SDK connection with existing AuditLog.Read.All is required.'
}
if ([string]$Context.Environment -cne 'Global' -or [string]$Environment.Name -cne 'Global' -or
    [string]$Environment.Type -cne 'Built-in' -or
    [string]$Environment.GraphEndpoint -cnotin @('https://graph.microsoft.com','https://graph.microsoft.com/') -or
    [string]$Environment.AzureADEndpoint -cnotin @('https://login.microsoftonline.com','https://login.microsoftonline.com/')) {
    throw 'The SDK environment must match the built-in Microsoft Graph global endpoints.'
}
$since = $Since.ToUniversalTime()
$until = $Until.ToUniversalTime()
if ($since -ge $until -or ($until - $since).TotalDays -gt 1 -or $until -gt [DateTimeOffset]::UtcNow) {
    throw 'Use one ordered interval of at most 24 hours that ends in the past.'
}

# This only formats arguments. It never loads an SDK module or invokes a provider.
[pscustomobject]@{
    Properties = @('id','appId','resourceId','createdDateTime','isInteractive')
    Filter = 'createdDateTime ge {0} and createdDateTime le {1}' -f $since.UtcDateTime.ToString('o'),$until.UtcDateTime.ToString('o')
    MaxRows = 1000
    SourceWindowCoverage = 'Unknown'
}
