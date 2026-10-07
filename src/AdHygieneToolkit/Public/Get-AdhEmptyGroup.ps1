function Get-AdhEmptyGroup {
    <#
    .SYNOPSIS
        Lists groups that have no members.

    .DESCRIPTION
        Returns security and distribution groups whose member attribute is empty. Built-in critical
        system groups (isCriticalSystemObject) are skipped because groups such as Domain Users and
        Domain Computers rely on primaryGroupID membership, which never appears in the member
        attribute. Groups created within -MinimumAgeDays are skipped so newly staged groups are not
        flagged. This function is read-only.

    .PARAMETER MinimumAgeDays
        Ignore groups created within this many days. Default 30.

    .PARAMETER SearchBase
        Distinguished name of the OU to search. Defaults to the whole domain.

    .PARAMETER Server
        Domain controller or domain to query.

    .PARAMETER Credential
        Alternate credentials for the query.

    .EXAMPLE
        Get-AdhEmptyGroup -SearchBase 'OU=Groups,DC=contoso,DC=local' | Format-Table Name, GroupCategory, WhenChanged

    .OUTPUTS
        Adh.EmptyGroup
    #>
    [CmdletBinding()]
    [OutputType('Adh.EmptyGroup')]
    param(
        [ValidateRange(0, 3650)]
        [int]$MinimumAgeDays = 30,

        [ValidateNotNullOrEmpty()]
        [string]$SearchBase,

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $null = Test-AdhPrerequisite
    $cutoff = (Get-Date).AddDays(-$MinimumAgeDays)

    $query = Get-AdhConnectionParameter -Server $Server -Credential $Credential
    $query['Filter'] = '*'
    $query['Properties'] = @('Members', 'whenCreated', 'whenChanged', 'Description', 'isCriticalSystemObject', 'ManagedBy')
    if ($SearchBase) { $query['SearchBase'] = $SearchBase }

    Write-AdhLog -Message 'Empty group scan started'
    foreach ($group in @(Get-ADGroup @query)) {
        if ($group.isCriticalSystemObject) { continue }
        if (@($group.Members).Where({ $_ }).Count -gt 0) { continue }
        if ($group.whenCreated -and ([datetime]$group.whenCreated) -gt $cutoff) { continue }

        [pscustomobject]@{
            PSTypeName        = 'Adh.EmptyGroup'
            Name              = $group.Name
            GroupCategory     = [string]$group.GroupCategory
            GroupScope        = [string]$group.GroupScope
            WhenCreated       = $group.whenCreated
            WhenChanged       = $group.whenChanged
            ManagedBy         = $group.ManagedBy
            Description       = $group.Description
            DistinguishedName = $group.DistinguishedName
        }
    }
}
