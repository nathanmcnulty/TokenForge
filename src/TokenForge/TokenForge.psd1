@{
    RootModule = 'TokenForge.psm1'
    ModuleVersion = '0.16.0'
    GUID = 'bd810ddc-54dd-47e9-b318-134ff4b64f04'
    Author = 'Nathan McNulty'
    Description = 'Discover first-party Entra scope metadata and request scoped tokens from an authorized session.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Import-TokenForgeFlowEvidence', 'Get-TokenForgeFlowEvidence', 'Export-TokenForgeFlowEvidence', 'New-TokenForgeResearchCohort', 'Get-TokenForgeResearchCohort', 'Invoke-TokenForgeResearchChunk', 'Get-TokenForgeResearchCoverage', 'Connect-TokenForgeGraph', 'Disconnect-TokenForgeGraph', 'Find-TokenForgeGraphPermission', 'Get-TokenForgeProfileToken', 'Remove-TokenForgeProfileKey', 'New-TokenForgeProfile', 'Get-TokenForgeProfile', 'Get-TokenForgeProfileStatus', 'Test-TokenForgeProfile', 'Connect-TokenForgeProfile', 'Disconnect-TokenForgeProfile', 'Get-TokenForgeApplicationMetadata', 'Update-TokenForgeApplicationMetadata','Import-TokenForgeApplicationMetadata', 'Update-TokenForgeCatalog', 'Get-TokenForgeCatalog', 'Find-TokenForgeApplication', 'New-TokenForgeRequest', 'Get-TokenForgeToken', 'Get-TokenForgeTokenClaims', 'Get-TokenForgeDiscovery', 'Update-TokenForgeDiscovery', 'Get-TokenForgeSignInApplications', 'Get-TokenForgeTenantInventory', 'Register-TokenForgeApplication', 'New-TokenForgeDiscoveryRequest', 'Merge-TokenForgeScopeDatabase', 'Import-TokenForgeScopeDatabase', 'New-TokenForgeScopeDatabase', 'Get-TokenForgeScopeDatabase', 'Add-TokenForgeScopeObservation', 'Compare-TokenForgeScopeDatabase', 'Export-TokenForgeScopeDatabase', 'Get-TokenForgeAssessmentCoverage', 'Invoke-TokenForgeScopeProbe', 'Sync-TokenForgeApplicationRegistration', 'Get-TokenForgeProbePlan', 'New-TokenForgeVault', 'Get-TokenForgeVault', 'Get-TokenForgeVaultToken', 'Remove-TokenForgeVaultEntry', 'Export-TokenForgeVaultView', 'Get-TokenForgeScopedToken', 'Get-TokenForgeScopeCandidates', 'Get-TokenForgeEstsCookie', 'Test-TokenForgeTokenAccess', 'New-TokenForgeTenantRequest', 'Get-TokenForgeAssessmentPlan', 'Get-TokenForgeMaintenanceReport')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ ProjectUri = 'https://github.com/nathanmcnulty/TokenForge'; Tags = @('Entra', 'OAuth', 'PKCE') } }
}
