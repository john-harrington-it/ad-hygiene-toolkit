@{
    RootModule           = 'AdHygieneToolkit.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = '6f0f3a52-1c7e-4f43-9d0b-8a3e2d6b7c11'
    Author               = 'John Harrington'
    Copyright            = '(c) John Harrington. MIT License.'
    Description          = 'Active Directory hygiene reporting and safe, opt-in remediation: stale users and computers, non-expiring passwords, empty groups, and privileged group membership.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Get-AdhStaleUser'
        'Get-AdhStaleComputer'
        'Get-AdhNonExpiringPasswordAccount'
        'Get-AdhEmptyGroup'
        'Get-AdhPrivilegedGroupMember'
        'Invoke-AdhStaleObjectRemediation'
        'Invoke-AdhAudit'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags                       = @('ActiveDirectory', 'Security', 'Audit', 'Hygiene', 'Reporting')
            LicenseUri                 = 'https://opensource.org/licenses/MIT'
            ExternalModuleDependencies = @('ActiveDirectory')
        }
    }
}
