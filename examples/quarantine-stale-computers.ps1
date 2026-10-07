<#
.SYNOPSIS
    Example: preview, then disable and quarantine stale computer accounts.

.DESCRIPTION
    Without -Apply the script only previews (-WhatIf). With -Apply it disables and moves the
    computers, prompting once per object unless -Confirm:$false is also passed.

.PARAMETER QuarantineOU
    Distinguished name of the OU that receives disabled computers.

.PARAMETER DaysInactive
    Inactivity threshold in days.

.PARAMETER Apply
    Make the changes instead of previewing them.

.EXAMPLE
    ./quarantine-stale-computers.ps1 -QuarantineOU 'OU=Disabled Computers,DC=contoso,DC=local'

.EXAMPLE
    ./quarantine-stale-computers.ps1 -QuarantineOU 'OU=Disabled Computers,DC=contoso,DC=local' -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^OU=.+,DC=.+')]
    [string]$QuarantineOU,

    [ValidateRange(30, 3650)]
    [int]$DaysInactive = 120,

    [switch]$Apply
)

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../src/AdHygieneToolkit/AdHygieneToolkit.psd1') -Force

$stale = @(Get-AdhStaleComputer -DaysInactive $DaysInactive -ExcludeName 'CLU-*')
Write-Information -MessageData ('{0} stale computer(s) found' -f $stale.Count) -InformationAction Continue

$stale | Invoke-AdhStaleObjectRemediation -Action DisableAndMove -TargetPath $QuarantineOU -MaxObjects 100 -WhatIf:(-not $Apply) |
    Format-Table -Property DistinguishedName, Status, Message -AutoSize
