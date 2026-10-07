function Get-AdhPrivilegedGroupMember {
    <#
    .SYNOPSIS
        Audits effective (recursive) membership of privileged Active Directory groups.

    .DESCRIPTION
        Expands each privileged group recursively and returns one row per member, with flags that
        deserve review: disabled accounts still in the group, stale accounts, passwords that never
        expire, old passwords, and non-user members. Group names default to the well-known English
        names; pass -GroupName for localized or custom tiers. This function is read-only.

    .PARAMETER GroupName
        Groups to audit. Defaults to the built-in privileged groups.

    .PARAMETER DaysInactive
        Flag members with no sign-in for this many days. Default 90.

    .PARAMETER MaxPasswordAgeDays
        Flag members whose password is older than this. Default 365.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the query.

    .EXAMPLE
        Get-AdhPrivilegedGroupMember | Where-Object Flags | Format-Table Group, SamAccountName, Flags

        Shows only privileged members that need attention.

    .EXAMPLE
        Get-AdhPrivilegedGroupMember -GroupName 'Domain Admins','Tier0-Admins'

    .OUTPUTS
        Adh.PrivilegedMember
    #>
    [CmdletBinding()]
    [OutputType('Adh.PrivilegedMember')]
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$GroupName = @(
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
            'DnsAdmins', 'Group Policy Creator Owners'
        ),

        [ValidateRange(1, 3650)]
        [int]$DaysInactive = 90,

        [ValidateRange(1, 3650)]
        [int]$MaxPasswordAgeDays = 365,

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $null = Test-AdhPrerequisite
    $now = Get-Date
    $conn = Get-AdhConnectionParameter -Server $Server -Credential $Credential

    foreach ($group in $GroupName) {
        try {
            $members = @(Get-ADGroupMember -Identity $group -Recursive @conn -ErrorAction Stop)
        }
        catch {
            Write-AdhLog -Level 'WARN' -Message ("Could not expand group '{0}': {1}" -f $group, $_.Exception.Message)
            continue
        }
        Write-AdhLog -Message ("Group '{0}': {1} effective member(s)" -f $group, $members.Count)

        foreach ($member in $members) {
            $flags = New-Object -TypeName System.Collections.Generic.List[string]
            $enabled = $null; $lastLogon = $null; $pwdSet = $null; $neverExpires = $null

            if ($member.objectClass -eq 'user') {
                $user = Get-ADUser -Identity $member.distinguishedName -Properties 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires' @conn
                $enabled = [bool]$user.Enabled
                $lastLogon = $user.LastLogonDate
                $pwdSet = $user.PasswordLastSet
                $neverExpires = [bool]$user.PasswordNeverExpires

                if (-not $enabled) { $flags.Add('Disabled account in privileged group') }
                if (-not $lastLogon) { $flags.Add('Never signed in') }
                elseif (($now - [datetime]$lastLogon).TotalDays -gt $DaysInactive) { $flags.Add(('No sign-in for {0}+ days' -f $DaysInactive)) }
                if ($neverExpires) { $flags.Add('Password never expires') }
                if ($pwdSet -and ($now - [datetime]$pwdSet).TotalDays -gt $MaxPasswordAgeDays) { $flags.Add(('Password older than {0} days' -f $MaxPasswordAgeDays)) }
            }
            else {
                $flags.Add(('Non-user member ({0})' -f $member.objectClass))
            }

            [pscustomobject]@{
                PSTypeName           = 'Adh.PrivilegedMember'
                Group                = $group
                Name                 = $member.name
                SamAccountName       = $member.SamAccountName
                ObjectClass          = $member.objectClass
                Enabled              = $enabled
                LastLogonDate        = $lastLogon
                PasswordLastSet      = $pwdSet
                PasswordNeverExpires = $neverExpires
                Flags                = ($flags -join '; ')
                DistinguishedName    = $member.distinguishedName
            }
        }
    }
}
