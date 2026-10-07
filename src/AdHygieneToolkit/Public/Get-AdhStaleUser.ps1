function Get-AdhStaleUser {
    <#
    .SYNOPSIS
        Finds enabled user accounts that have not signed in for a given number of days.

    .DESCRIPTION
        Queries Active Directory for enabled user accounts whose LastLogonDate (derived from the
        replicated lastLogonTimestamp attribute) is older than -DaysInactive. Accounts that have
        never signed in are included only when they were created more than -DaysInactive days ago,
        so brand-new hires are not flagged.

        lastLogonTimestamp replicates with a 9-14 day lag by design, so thresholds below 30 days
        are rejected. This function is read-only.

    .PARAMETER DaysInactive
        Number of days without a sign-in before an account is considered stale. 30-3650, default 90.

    .PARAMETER SearchBase
        Distinguished name of the OU to search. Defaults to the whole domain.

    .PARAMETER ExcludeSamAccountName
        Wildcard patterns for accounts to ignore (for example 'svc_*'). Built-in accounts are
        excluded by default.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the query.

    .EXAMPLE
        Get-AdhStaleUser -DaysInactive 120 -SearchBase 'OU=Staff,DC=contoso,DC=local'

        Lists enabled users in the Staff OU with no sign-in for 120+ days.

    .EXAMPLE
        Get-AdhStaleUser -ExcludeSamAccountName 'svc_*','krbtgt' | Export-Csv stale-users.csv -NoTypeInformation

        Exports stale users to CSV, ignoring service accounts.

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

        [string[]]$ExcludeSamAccountName = @('krbtgt', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount'),

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
    $query['Properties'] = @('LastLogonDate', 'whenCreated', 'PasswordLastSet', 'Description', 'AdminCount', 'UserPrincipalName')
    if ($SearchBase) { $query['SearchBase'] = $SearchBase }

    Write-AdhLog -Message ("Stale user scan: DaysInactive={0} SearchBase='{1}'" -f $DaysInactive, $SearchBase)
    $found = 0
    foreach ($user in @(Get-ADUser @query)) {
        if (Test-AdhExcluded -Name $user.SamAccountName -Pattern $ExcludeSamAccountName) { continue }

        $reference = $user.LastLogonDate
        if (-not $reference) { $reference = $user.whenCreated }
        if ($reference -and ([datetime]$reference) -ge $cutoff) { continue }

        $found++
        ConvertTo-AdhStaleObject -ADObject $user -ObjectClass 'user' -Now $now
    }
    Write-AdhLog -Message ("Stale user scan complete: {0} found" -f $found)
}
