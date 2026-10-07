function Test-AdhExcluded {
    <#
    .SYNOPSIS
        Returns $true when a name matches any of the supplied wildcard patterns.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [string]$Name,

        [string[]]$Pattern
    )

    foreach ($p in @($Pattern)) {
        if ($p -and $Name -like $p) { return $true }
    }
    return $false
}
