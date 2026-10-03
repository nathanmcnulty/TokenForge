@{
    RootModule = 'TokenForge.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'bd810ddc-54dd-47e9-b318-134ff4b64f04'
    Author = 'Nathan McNulty'
    Description = 'Discover first-party Entra scope metadata and request scoped tokens from an authorized session.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Update-TokenForgeCatalog', 'Get-TokenForgeCatalog', 'Find-TokenForgeApplication', 'New-TokenForgeRequest', 'Get-TokenForgeToken')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ ProjectUri = 'https://github.com/nathanmcnulty/TokenForge'; Tags = @('Entra', 'OAuth', 'PKCE') } }
}
