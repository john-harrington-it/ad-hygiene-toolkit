function Write-AdhLog {
    <#
    .SYNOPSIS
        Writes a timestamped line to the verbose stream and, when configured, to the module log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'ACTION')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose -Message $line
    if ($Level -eq 'WARN') { Write-Warning -Message $Message }

    if ($script:AdhLogPath) {
        try {
            # -WhatIf:$false so the audit trail is still written during -WhatIf runs.
            Add-Content -Path $script:AdhLogPath -Value $line -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Verbose -Message ("Could not write to log file '{0}': {1}" -f $script:AdhLogPath, $_.Exception.Message)
        }
    }
}
