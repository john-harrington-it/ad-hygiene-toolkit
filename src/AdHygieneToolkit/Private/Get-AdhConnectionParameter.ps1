function Get-AdhConnectionParameter {
    <#
    .SYNOPSIS
        Builds the optional -Server / -Credential splat shared by all AD calls.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $splat = @{}
    if ($Server) { $splat['Server'] = $Server }
    if ($Credential -and $Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $splat['Credential'] = $Credential
    }
    return $splat
}
