function ConvertTo-AdhStaleObject {
    <#
    .SYNOPSIS
        Normalizes an AD user or computer into the toolkit's stale-object shape.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [psobject]$ADObject,

        [Parameter(Mandatory)]
        [ValidateSet('user', 'computer')]
        [string]$ObjectClass,

        [Parameter(Mandatory)]
        [datetime]$Now
    )

    $lastLogon = $ADObject.LastLogonDate
    $daysSince = $null
    if ($lastLogon) { $daysSince = [int][math]::Floor(($Now - [datetime]$lastLogon).TotalDays) }

    $adminCount = $null
    if ($ADObject.PSObject.Properties['AdminCount']) { $adminCount = $ADObject.AdminCount }

    $extra = $null
    if ($ObjectClass -eq 'computer' -and $ADObject.PSObject.Properties['OperatingSystem']) {
        $extra = $ADObject.OperatingSystem
    }
    elseif ($ADObject.PSObject.Properties['UserPrincipalName']) {
        $extra = $ADObject.UserPrincipalName
    }

    [pscustomobject]@{
        PSTypeName        = 'Adh.StaleObject'
        ObjectClass       = $ObjectClass
        Name              = $ADObject.Name
        SamAccountName    = $ADObject.SamAccountName
        Detail            = $extra
        LastLogonDate     = $lastLogon
        DaysSinceLogon    = $daysSince
        NeverLoggedOn     = (-not $lastLogon)
        WhenCreated       = $ADObject.whenCreated
        PasswordLastSet   = $ADObject.PasswordLastSet
        AdminCount        = $adminCount
        Description       = $ADObject.Description
        DistinguishedName = $ADObject.DistinguishedName
    }
}
