function Get-AdhNonExpiringPasswordAccount {
    <#
    .SYNOPSIS
        Lists enabled user accounts whose password is set to never expire.

    .DESCRIPTION
        Returns enabled users with PasswordNeverExpires set, along with password age and whether the
        account looks like a service account (it has a servicePrincipalName). Use the output to move
        service accounts to gMSAs or a documented rotation process, and to remove the flag from
        human accounts. This function is read-only.

    .PARAMETER SearchBase
        Distinguished name of the OU to search. Defaults to the whole domain.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the query.

    .EXAMPLE
        Get-AdhNonExpiringPasswordAccount | Where-Object { -not $_.LikelyServiceAccount }

        Human accounts with non-expiring passwords, usually the first ones to fix.

    .OUTPUTS
        Adh.NonExpiringPassword
    #>
    [CmdletBinding()]
    [OutputType('Adh.NonExpiringPassword')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $null = Test-AdhPrerequisite
    $now = Get-Date

    $query = Get-AdhConnectionParameter -Server $Server -Credential $Credential
    $query['Filter'] = 'Enabled -eq $true -and PasswordNeverExpires -eq $true'
    $query['Properties'] = @('PasswordLastSet', 'LastLogonDate', 'Description', 'AdminCount', 'ServicePrincipalName', 'PasswordNeverExpires')
    if ($SearchBase) { $query['SearchBase'] = $SearchBase }

    Write-AdhLog -Message 'Non-expiring password scan started'
    foreach ($user in @(Get-ADUser @query)) {
        $age = $null
        if ($user.PasswordLastSet) { $age = [int][math]::Floor(($now - [datetime]$user.PasswordLastSet).TotalDays) }
        $isPrivileged = $false
        if ($user.PSObject.Properties['AdminCount'] -and $user.AdminCount -eq 1) { $isPrivileged = $true }

        [pscustomobject]@{
            PSTypeName           = 'Adh.NonExpiringPassword'
            Name                 = $user.Name
            SamAccountName       = $user.SamAccountName
            PasswordLastSet      = $user.PasswordLastSet
            PasswordAgeDays      = $age
            LastLogonDate        = $user.LastLogonDate
            LikelyServiceAccount = (@($user.ServicePrincipalName).Where({ $_ }).Count -gt 0)
            Privileged           = $isPrivileged
            Description          = $user.Description
            DistinguishedName    = $user.DistinguishedName
        }
    }
}
