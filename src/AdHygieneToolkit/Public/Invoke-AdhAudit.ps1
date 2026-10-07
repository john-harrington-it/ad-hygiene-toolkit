function Invoke-AdhAudit {
    <#
    .SYNOPSIS
        Runs every hygiene check and writes an HTML dashboard plus one CSV per finding type.

    .DESCRIPTION
        Runs Get-AdhStaleUser, Get-AdhStaleComputer, Get-AdhNonExpiringPasswordAccount,
        Get-AdhEmptyGroup, and Get-AdhPrivilegedGroupMember, then writes:

          <OutputPath>\index.html              Dashboard with summary cards and detail tables
          <OutputPath>\stale-users.csv         One CSV per check
          <OutputPath>\stale-computers.csv
          <OutputPath>\non-expiring-passwords.csv
          <OutputPath>\empty-groups.csv
          <OutputPath>\privileged-members.csv
          <OutputPath>\audit.log

        Reporting only: this command never changes Active Directory. Feed the CSV or the objects
        from the individual Get-* commands into Invoke-AdhStaleObjectRemediation to act on findings.

    .PARAMETER OutputPath
        Folder for the report. Created if missing. Defaults to .\AdhReport-<timestamp>.

    .PARAMETER DaysInactive
        Inactivity threshold for users, computers, and privileged members. Default 90.

    .PARAMETER SearchBase
        Limit user, computer, group, and password scans to this OU.

    .PARAMETER PrivilegedGroup
        Override the list of privileged groups to audit.

    .PARAMETER ExcludeSamAccountName
        Wildcard patterns for user accounts to ignore in the stale user scan.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the queries.

    .EXAMPLE
        Invoke-AdhAudit -OutputPath C:\Reports\AD -DaysInactive 120

        Writes the dashboard to C:\Reports\AD\index.html.

    .OUTPUTS
        Adh.AuditSummary
    #>
    [CmdletBinding()]
    [OutputType('Adh.AuditSummary')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('AdhReport-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmm'))),

        [ValidateRange(30, 3650)]
        [int]$DaysInactive = 90,

        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [ValidateNotNullOrEmpty()]
        [string[]]$PrivilegedGroup,

        [string[]]$ExcludeSamAccountName = @('krbtgt', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'),

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $null = Test-AdhPrerequisite
    if (-not (Test-Path -Path $OutputPath)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force -WhatIf:$false -Confirm:$false
    }
    $script:AdhLogPath = Join-Path -Path $OutputPath -ChildPath 'audit.log'
    Write-AdhLog -Message ("Audit started. OutputPath='{0}'" -f $OutputPath)

    $common = @{ Server = $Server; Credential = $Credential }
    if (-not $Server) { $common.Remove('Server') }
    $scoped = $common.Clone()
    if ($SearchBase) { $scoped['SearchBase'] = $SearchBase }
    $privParams = $common.Clone()
    $privParams['DaysInactive'] = $DaysInactive
    if ($PrivilegedGroup) { $privParams['GroupName'] = $PrivilegedGroup }

    $sections = [ordered]@{
        'Stale users'              = @(Get-AdhStaleUser @scoped -DaysInactive $DaysInactive -ExcludeSamAccountName $ExcludeSamAccountName)
        'Stale computers'          = @(Get-AdhStaleComputer @scoped -DaysInactive $DaysInactive)
        'Non-expiring passwords'   = @(Get-AdhNonExpiringPasswordAccount @scoped)
        'Empty groups'             = @(Get-AdhEmptyGroup @scoped)
        'Privileged group members' = @(Get-AdhPrivilegedGroupMember @privParams)
    }
    $files = [ordered]@{
        'Stale users'              = 'stale-users.csv'
        'Stale computers'          = 'stale-computers.csv'
        'Non-expiring passwords'   = 'non-expiring-passwords.csv'
        'Empty groups'             = 'empty-groups.csv'
        'Privileged group members' = 'privileged-members.csv'
    }

    foreach ($key in $sections.Keys) {
        $csv = Join-Path -Path $OutputPath -ChildPath $files[$key]
        $rows = @($sections[$key])
        if ($rows.Count -gt 0) {
            $rows | Select-Object -Property * -ExcludeProperty PSTypeName |
                Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }
        else {
            Set-Content -Path $csv -Value '' -Encoding UTF8 -WhatIf:$false -Confirm:$false
        }
    }

    $paramSummary = [ordered]@{ DaysInactive = $DaysInactive; SearchBase = $(if ($SearchBase) { $SearchBase } else { '(domain)' }); Server = $(if ($Server) { $Server } else { '(default)' }) }
    $html = ConvertTo-AdhHtmlReport -Section $sections -Parameter $paramSummary
    $reportPath = Join-Path -Path $OutputPath -ChildPath 'index.html'
    Set-Content -Path $reportPath -Value $html -Encoding UTF8 -WhatIf:$false -Confirm:$false
    Write-AdhLog -Message ("Audit complete. Report: {0}" -f $reportPath)

    [pscustomobject]@{
        PSTypeName                 = 'Adh.AuditSummary'
        ReportPath                 = $reportPath
        OutputPath                 = $OutputPath
        StaleUsers                 = $sections['Stale users'].Count
        StaleComputers             = $sections['Stale computers'].Count
        NonExpiringPasswords       = $sections['Non-expiring passwords'].Count
        EmptyGroups                = $sections['Empty groups'].Count
        PrivilegedMembers          = $sections['Privileged group members'].Count
        PrivilegedMembersFlagged   = @($sections['Privileged group members'] | Where-Object { $_.Flags }).Count
    }
}
