function Test-AdhPrerequisite {
    <#
    .SYNOPSIS
        Throws a helpful error when the ActiveDirectory cmdlets are not available.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Get-Command -Name 'Get-ADUser' -ErrorAction SilentlyContinue)) {
        throw 'The ActiveDirectory module (RSAT) is required. Install RSAT: Active Directory DS and LDS Tools, or run on a domain controller / management server.'
    }
    return $true
}
