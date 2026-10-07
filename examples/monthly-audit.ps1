<#
.SYNOPSIS
    Example: monthly AD hygiene audit, suitable for a scheduled task.

.DESCRIPTION
    Writes a dated report folder and keeps the last 12 months. Reporting only; it never changes
    Active Directory. Review the report, then remediate with Invoke-AdhStaleObjectRemediation.

.PARAMETER ReportRoot
    Folder that holds one sub-folder per run.

.EXAMPLE
    ./monthly-audit.ps1 -ReportRoot 'D:\Reports\AD-Hygiene'
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$ReportRoot = (Join-Path -Path (Get-Location).Path -ChildPath 'AD-Hygiene')
)

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '../src/AdHygieneToolkit/AdHygieneToolkit.psd1') -Force

$runFolder = Join-Path -Path $ReportRoot -ChildPath (Get-Date -Format 'yyyy-MM')
$summary = Invoke-AdhAudit -OutputPath $runFolder -DaysInactive 90 -ExcludeSamAccountName 'krbtgt', 'Guest', 'svc_*'
$summary | Format-List

# Keep 12 months of reports.
Get-ChildItem -Path $ReportRoot -Directory |
    Sort-Object -Property Name -Descending |
    Select-Object -Skip 12 |
    Remove-Item -Recurse -Force -WhatIf:$WhatIfPreference
