function Invoke-AdhStaleObjectRemediation {
    <#
    .SYNOPSIS
        Disables and/or moves stale user or computer accounts, with -WhatIf/-Confirm and an audit log.

    .DESCRIPTION
        Accepts objects from Get-AdhStaleUser or Get-AdhStaleComputer (anything with a
        DistinguishedName) and performs the requested action:

          Disable         Disable the account and stamp the description with the date (the previous
                          description is preserved after the stamp).
          Move            Move the object to -TargetPath (for example a "Disabled Objects" OU).
          DisableAndMove  Both of the above.

        Safety controls:
          * ConfirmImpact is High, so PowerShell prompts for every object unless -Confirm:$false.
          * -WhatIf shows exactly what would change and changes nothing.
          * -MaxObjects (default 25) refuses oversized batches, protecting against a bad filter.
          * Objects with adminCount=1 (current or former privileged accounts) are skipped unless
            -IncludeProtected is specified.
          * Every action and skip is written to a log file.

        Nothing is ever deleted.

    .PARAMETER InputObject
        Objects to remediate. Must expose a DistinguishedName property.

    .PARAMETER Action
        Disable, Move, or DisableAndMove.

    .PARAMETER TargetPath
        Distinguished name of the destination OU. Required for Move and DisableAndMove.

    .PARAMETER MaxObjects
        Maximum number of objects accepted in one run. Default 25.

    .PARAMETER IncludeProtected
        Also process objects with adminCount=1.

    .PARAMETER LogPath
        Log file path. Defaults to adh-remediation-<timestamp>.log in the current directory.

    .PARAMETER Server
        Domain controller or domain to target.

    .PARAMETER Credential
        Alternate credentials.

    .EXAMPLE
        Get-AdhStaleUser -DaysInactive 180 | Invoke-AdhStaleObjectRemediation -Action Disable -WhatIf

        Preview: lists every account that would be disabled. Nothing changes.

    .EXAMPLE
        Get-AdhStaleComputer -DaysInactive 120 |
            Invoke-AdhStaleObjectRemediation -Action DisableAndMove -TargetPath 'OU=Disabled Computers,DC=contoso,DC=local' -Confirm:$false

        Disables and quarantines stale computers without per-object prompts (after a -WhatIf review).

    .OUTPUTS
        Adh.RemediationResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('Adh.RemediationResult')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [psobject[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidateSet('Disable', 'Move', 'DisableAndMove')]
        [string]$Action,

        [ValidatePattern('^(OU|CN)=.+,DC=.+')]
        [string]$TargetPath,

        [ValidateRange(1, 10000)]
        [int]$MaxObjects = 25,

        [switch]$IncludeProtected,

        [ValidateNotNullOrEmpty()]
        [string]$LogPath = (Join-Path -Path (Get-Location).Path -ChildPath ('adh-remediation-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    begin {
        if ($Action -ne 'Disable' -and -not $TargetPath) {
            throw ("-TargetPath is required when -Action is '{0}'." -f $Action)
        }
        $null = Test-AdhPrerequisite
        $script:AdhLogPath = $LogPath
        $queue = New-Object -TypeName System.Collections.Generic.List[object]
    }

    process {
        foreach ($item in $InputObject) { $queue.Add($item) }
    }

    end {
        if ($queue.Count -gt $MaxObjects) {
            $msg = 'Refusing to process {0} objects because -MaxObjects is {1}. Review the input, then raise -MaxObjects deliberately.' -f $queue.Count, $MaxObjects
            Write-AdhLog -Level 'ERROR' -Message $msg
            throw $msg
        }

        $conn = Get-AdhConnectionParameter -Server $Server -Credential $Credential
        $stamp = 'Disabled by AD Hygiene Toolkit {0}' -f (Get-Date -Format 'yyyy-MM-dd')
        Write-AdhLog -Message ("Remediation run: Action={0} Objects={1} TargetPath='{2}' WhatIf={3}" -f $Action, $queue.Count, $TargetPath, [bool]$WhatIfPreference)

        foreach ($obj in $queue) {
            $dn = $null
            if ($obj.PSObject.Properties['DistinguishedName']) { $dn = [string]$obj.DistinguishedName }

            $result = [pscustomobject]@{
                PSTypeName        = 'Adh.RemediationResult'
                DistinguishedName = $dn
                Action            = $Action
                Status            = 'NotPerformed'
                Message           = ''
            }

            if (-not $dn) {
                $result.Status = 'Failed'
                $result.Message = 'Input object has no DistinguishedName.'
                Write-AdhLog -Level 'ERROR' -Message $result.Message
                $result
                continue
            }

            if (-not $IncludeProtected -and $obj.PSObject.Properties['AdminCount'] -and $obj.AdminCount -eq 1) {
                $result.Status = 'Skipped'
                $result.Message = 'Protected object (adminCount=1). Use -IncludeProtected to process.'
                Write-AdhLog -Level 'WARN' -Message ("Skipped protected object {0}" -f $dn)
                $result
                continue
            }

            $done = New-Object -TypeName System.Collections.Generic.List[string]
            try {
                if ($Action -in @('Disable', 'DisableAndMove')) {
                    if ($PSCmdlet.ShouldProcess($dn, 'Disable account and stamp description')) {
                        Disable-ADAccount -Identity $dn @conn -ErrorAction Stop
                        $newDescription = $stamp
                        if ($obj.PSObject.Properties['Description'] -and $obj.Description) {
                            $newDescription = '{0}; previous: {1}' -f $stamp, $obj.Description
                        }
                        if ($newDescription.Length -gt 1024) { $newDescription = $newDescription.Substring(0, 1024) }
                        Set-ADObject -Identity $dn -Description $newDescription @conn -ErrorAction Stop
                        $done.Add('Disabled')
                        Write-AdhLog -Level 'ACTION' -Message ("Disabled {0}" -f $dn)
                    }
                }
                if ($Action -in @('Move', 'DisableAndMove')) {
                    if ($PSCmdlet.ShouldProcess($dn, ("Move to '{0}'" -f $TargetPath))) {
                        Move-ADObject -Identity $dn -TargetPath $TargetPath @conn -ErrorAction Stop
                        $done.Add('Moved')
                        Write-AdhLog -Level 'ACTION' -Message ("Moved {0} to {1}" -f $dn, $TargetPath)
                    }
                }

                if ($done.Count -gt 0) {
                    $result.Status = 'Success'
                    $result.Message = $done -join ', '
                }
                elseif ($WhatIfPreference) {
                    $result.Status = 'WhatIf'
                    $result.Message = 'Preview only; no change made.'
                }
                else {
                    $result.Message = 'Declined at confirmation prompt.'
                }
            }
            catch {
                $result.Status = 'Failed'
                $result.Message = $_.Exception.Message
                if ($done.Count -gt 0) { $result.Message = ('{0} (completed before failure: {1})' -f $result.Message, ($done -join ', ')) }
                Write-AdhLog -Level 'ERROR' -Message ("{0}: {1}" -f $dn, $result.Message)
            }
            $result
        }
    }
}
