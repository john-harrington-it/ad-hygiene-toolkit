function Get-AdhStaleComputer {
    <#
    .SYNOPSIS
        Finds enabled computer accounts that have not authenticated for a given number of days.

    .DESCRIPTION
        Queries Active Directory for enabled computer objects whose LastLogonDate is older than
        -DaysInactive (or that never authenticated and were created more than -DaysInactive days ago).
        PasswordLastSet is included as a second signal: domain members rotate their machine password
        every 30 days by default, so an old PasswordLastSet strongly suggests the device is gone.
        This function is read-only.

    .PARAMETER DaysInactive
        Days without authentication before a computer is considered stale. 30-3650, default 90.

    .PARAMETER SearchBase
        Distinguished name of the OU to search. Defaults to the whole domain.

    .PARAMETER ExcludeName
        Wildcard patterns for computer names to ignore (for example cluster name objects 'CLU-*').

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the query.

    .EXAMPLE
        Get-AdhStaleComputer -DaysInactive 90 | Sort-Object DaysSinceLogon -Descending | Format-Table Name, Detail, DaysSinceLogon

        Shows stale computers, oldest first, with their operating system.

    .OUTPUTS
        Adh.StaleObject
    #>
    [CmdletBinding()]
    [OutputType('Adh.StaleObject')]
    param(
        [ValidateRange(30, 3650)]
        [int]$DaysInactive = 90,

        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [string[]]$ExcludeName = @(),

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $null = Test-AdhPrerequisite
    $now = Get-Date
    $cutoff = $now.AddDays(-$DaysInactive)

    $query = Get-AdhConnectionParameter -Server $Server -Credential $Credential
    $query['Filter'] = 'Enabled -eq $true'
    $query['Properties'] = @('LastLogonDate', 'whenCreated', 'PasswordLastSet', 'Description', 'OperatingSystem')
    if ($SearchBase) { $query['SearchBase'] = $SearchBase }

    Write-AdhLog -Message ("Stale computer scan: DaysInactive={0} SearchBase='{1}'" -f $DaysInactive, $SearchBase)
    $found = 0
    foreach ($computer in @(Get-ADComputer @query)) {
        if (Test-AdhExcluded -Name $computer.Name -Pattern $ExcludeName) { continue }

        $reference = $computer.LastLogonDate
        if (-not $reference) { $reference = $computer.whenCreated }
        if ($reference -and ([datetime]$reference) -ge $cutoff) { continue }

        $found++
        ConvertTo-AdhStaleObject -ADObject $computer -ObjectClass 'computer' -Now $now
    }
    Write-AdhLog -Message ("Stale computer scan complete: {0} found" -f $found)
}
