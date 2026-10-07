# Unit tests for AdHygieneToolkit. No domain is required: the ActiveDirectory cmdlets are
# replaced with stubs and Pester mocks, so the suite runs on any OS with PowerShell 7 or 5.1.

BeforeAll {
    $adStubs = @('Get-ADUser', 'Get-ADComputer', 'Get-ADGroup', 'Get-ADGroupMember', 'Disable-ADAccount', 'Set-ADObject', 'Move-ADObject')
    foreach ($name in $adStubs) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $null = New-Item -Path "function:global:$name" -Force -Value {
                [CmdletBinding()]
                param($Filter, $LDAPFilter, $Properties, $SearchBase, $Server, $Credential, $Identity, [switch]$Recursive, $Description, $TargetPath)
            }
        }
    }

    $manifest = [System.IO.Path]::Combine($PSScriptRoot, '..', 'src', 'AdHygieneToolkit', 'AdHygieneToolkit.psd1')
    Import-Module -Name $manifest -Force

    $script:Now = Get-Date
    function New-FakeUser {
        param($Sam, $LastLogonDaysAgo, $CreatedDaysAgo = 1000, $AdminCount = $null, $Description = $null)
        $lastLogon = $null
        if ($null -ne $LastLogonDaysAgo) { $lastLogon = $script:Now.AddDays(-$LastLogonDaysAgo) }
        [pscustomobject]@{
            Name              = $Sam
            SamAccountName    = $Sam
            UserPrincipalName = "$Sam@contoso.local"
            Enabled           = $true
            LastLogonDate     = $lastLogon
            whenCreated       = $script:Now.AddDays(-$CreatedDaysAgo)
            PasswordLastSet   = $script:Now.AddDays(-400)
            Description       = $Description
            AdminCount        = $AdminCount
            DistinguishedName = "CN=$Sam,OU=Staff,DC=contoso,DC=local"
        }
    }
}

AfterAll {
    Remove-Module -Name AdHygieneToolkit -Force -ErrorAction SilentlyContinue
}

Describe 'Get-AdhStaleUser' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADUser {
            New-FakeUser -Sam 'active.user' -LastLogonDaysAgo 5
            New-FakeUser -Sam 'stale.user' -LastLogonDaysAgo 200
            New-FakeUser -Sam 'never.old' -LastLogonDaysAgo $null -CreatedDaysAgo 400
            New-FakeUser -Sam 'never.newhire' -LastLogonDaysAgo $null -CreatedDaysAgo 3
            New-FakeUser -Sam 'svc_backup' -LastLogonDaysAgo 500
            New-FakeUser -Sam 'krbtgt' -LastLogonDaysAgo $null -CreatedDaysAgo 4000
        }
    }

    It 'returns only accounts past the threshold' {
        $result = Get-AdhStaleUser -DaysInactive 90 -ExcludeSamAccountName 'krbtgt', 'svc_*'
        $result.SamAccountName | Sort-Object | Should -Be @('never.old', 'stale.user')
    }

    It 'does not flag recently created accounts that never signed in' {
        (Get-AdhStaleUser).SamAccountName | Should -Not -Contain 'never.newhire'
    }

    It 'marks never-signed-in accounts and computes days since logon' {
        $result = Get-AdhStaleUser -ExcludeSamAccountName 'krbtgt'
        ($result | Where-Object SamAccountName -EQ 'never.old').NeverLoggedOn | Should -BeTrue
        ($result | Where-Object SamAccountName -EQ 'stale.user').DaysSinceLogon | Should -Be 200
    }

    It 'excludes built-in accounts by default' {
        (Get-AdhStaleUser).SamAccountName | Should -Not -Contain 'krbtgt'
    }

    It 'queries enabled users only and passes SearchBase and Server through' {
        $null = Get-AdhStaleUser -SearchBase 'OU=Staff,DC=contoso,DC=local' -Server 'dc01'
        Should -Invoke -ModuleName AdHygieneToolkit Get-ADUser -Times 1 -Exactly -ParameterFilter {
            $Filter -eq 'Enabled -eq $true' -and $SearchBase -eq 'OU=Staff,DC=contoso,DC=local' -and $Server -eq 'dc01'
        }
    }

    It 'rejects thresholds shorter than the lastLogonTimestamp replication window' {
        { Get-AdhStaleUser -DaysInactive 7 } | Should -Throw
    }
}

Describe 'Get-AdhStaleComputer' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADComputer {
            [pscustomobject]@{ Name = 'PC-OLD'; SamAccountName = 'PC-OLD$'; LastLogonDate = $script:Now.AddDays(-150); whenCreated = $script:Now.AddDays(-900); PasswordLastSet = $script:Now.AddDays(-150); OperatingSystem = 'Windows 10 Enterprise'; Description = $null; DistinguishedName = 'CN=PC-OLD,OU=Workstations,DC=contoso,DC=local' }
            [pscustomobject]@{ Name = 'PC-NEW'; SamAccountName = 'PC-NEW$'; LastLogonDate = $script:Now.AddDays(-2); whenCreated = $script:Now.AddDays(-30); PasswordLastSet = $script:Now.AddDays(-2); OperatingSystem = 'Windows 11 Enterprise'; Description = $null; DistinguishedName = 'CN=PC-NEW,OU=Workstations,DC=contoso,DC=local' }
            [pscustomobject]@{ Name = 'CLU-SQL'; SamAccountName = 'CLU-SQL$'; LastLogonDate = $script:Now.AddDays(-300); whenCreated = $script:Now.AddDays(-900); PasswordLastSet = $script:Now.AddDays(-300); OperatingSystem = $null; Description = 'Cluster name object'; DistinguishedName = 'CN=CLU-SQL,OU=Servers,DC=contoso,DC=local' }
        }
    }

    It 'returns stale computers with operating system detail' {
        $result = @(Get-AdhStaleComputer -ExcludeName 'CLU-*')
        $result.Count | Should -Be 1
        $result[0].Name | Should -Be 'PC-OLD'
        $result[0].Detail | Should -Be 'Windows 10 Enterprise'
        $result[0].ObjectClass | Should -Be 'computer'
    }
}

Describe 'Get-AdhNonExpiringPasswordAccount' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADUser {
            [pscustomobject]@{ Name = 'SQL Service'; SamAccountName = 'svc_sql'; PasswordLastSet = $script:Now.AddDays(-1200); LastLogonDate = $script:Now; ServicePrincipalName = @('MSSQLSvc/sql01.contoso.local:1433'); AdminCount = $null; Description = 'SQL'; DistinguishedName = 'CN=svc_sql,OU=Service,DC=contoso,DC=local'; PasswordNeverExpires = $true }
            [pscustomobject]@{ Name = 'Jane Admin'; SamAccountName = 'jadmin'; PasswordLastSet = $script:Now.AddDays(-30); LastLogonDate = $script:Now; ServicePrincipalName = @(); AdminCount = 1; Description = $null; DistinguishedName = 'CN=jadmin,OU=Admins,DC=contoso,DC=local'; PasswordNeverExpires = $true }
        }
    }

    It 'flags service accounts and privileged accounts separately' {
        $result = Get-AdhNonExpiringPasswordAccount
        ($result | Where-Object SamAccountName -EQ 'svc_sql').LikelyServiceAccount | Should -BeTrue
        ($result | Where-Object SamAccountName -EQ 'svc_sql').PasswordAgeDays | Should -Be 1200
        ($result | Where-Object SamAccountName -EQ 'jadmin').Privileged | Should -BeTrue
        ($result | Where-Object SamAccountName -EQ 'jadmin').LikelyServiceAccount | Should -BeFalse
    }

    It 'filters on enabled accounts with PasswordNeverExpires' {
        $null = Get-AdhNonExpiringPasswordAccount
        Should -Invoke -ModuleName AdHygieneToolkit Get-ADUser -ParameterFilter { $Filter -match 'PasswordNeverExpires -eq \$true' }
    }
}

Describe 'Get-AdhEmptyGroup' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADGroup {
            [pscustomobject]@{ Name = 'Old Project'; Members = @(); whenCreated = $script:Now.AddDays(-700); whenChanged = $script:Now.AddDays(-400); isCriticalSystemObject = $false; GroupCategory = 'Security'; GroupScope = 'Global'; ManagedBy = $null; Description = $null; DistinguishedName = 'CN=Old Project,OU=Groups,DC=contoso,DC=local' }
            [pscustomobject]@{ Name = 'Domain Users'; Members = @(); whenCreated = $script:Now.AddDays(-4000); whenChanged = $script:Now; isCriticalSystemObject = $true; GroupCategory = 'Security'; GroupScope = 'Global'; ManagedBy = $null; Description = $null; DistinguishedName = 'CN=Domain Users,CN=Users,DC=contoso,DC=local' }
            [pscustomobject]@{ Name = 'Accounting'; Members = @('CN=a,DC=contoso,DC=local'); whenCreated = $script:Now.AddDays(-700); whenChanged = $script:Now; isCriticalSystemObject = $false; GroupCategory = 'Security'; GroupScope = 'Global'; ManagedBy = $null; Description = $null; DistinguishedName = 'CN=Accounting,OU=Groups,DC=contoso,DC=local' }
            [pscustomobject]@{ Name = 'Brand New'; Members = @(); whenCreated = $script:Now.AddDays(-2); whenChanged = $script:Now; isCriticalSystemObject = $false; GroupCategory = 'Distribution'; GroupScope = 'Universal'; ManagedBy = $null; Description = $null; DistinguishedName = 'CN=Brand New,OU=Groups,DC=contoso,DC=local' }
        }
    }

    It 'returns empty, non-system groups older than the minimum age' {
        (Get-AdhEmptyGroup).Name | Should -Be 'Old Project'
    }

    It 'includes new groups when MinimumAgeDays is 0' {
        (Get-AdhEmptyGroup -MinimumAgeDays 0).Name | Sort-Object | Should -Be @('Brand New', 'Old Project')
    }
}

Describe 'Get-AdhPrivilegedGroupMember' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADGroupMember -ParameterFilter { $Identity -eq 'Domain Admins' } {
            [pscustomobject]@{ name = 'Good Admin'; SamAccountName = 'gadmin'; objectClass = 'user'; distinguishedName = 'CN=gadmin,DC=contoso,DC=local' }
            [pscustomobject]@{ name = 'Old Admin'; SamAccountName = 'oadmin'; objectClass = 'user'; distinguishedName = 'CN=oadmin,DC=contoso,DC=local' }
            [pscustomobject]@{ name = 'SRV01'; SamAccountName = 'SRV01$'; objectClass = 'computer'; distinguishedName = 'CN=SRV01,DC=contoso,DC=local' }
        }
        Mock -ModuleName AdHygieneToolkit Get-ADGroupMember -ParameterFilter { $Identity -eq 'Missing Group' } { throw 'Cannot find an object with identity' }
        Mock -ModuleName AdHygieneToolkit Get-ADUser -ParameterFilter { $Identity -eq 'CN=gadmin,DC=contoso,DC=local' } {
            [pscustomobject]@{ Enabled = $true; LastLogonDate = $script:Now.AddDays(-1); PasswordLastSet = $script:Now.AddDays(-20); PasswordNeverExpires = $false }
        }
        Mock -ModuleName AdHygieneToolkit Get-ADUser -ParameterFilter { $Identity -eq 'CN=oadmin,DC=contoso,DC=local' } {
            [pscustomobject]@{ Enabled = $false; LastLogonDate = $script:Now.AddDays(-400); PasswordLastSet = $script:Now.AddDays(-800); PasswordNeverExpires = $true }
        }
    }

    It 'returns one row per effective member' {
        @(Get-AdhPrivilegedGroupMember -GroupName 'Domain Admins').Count | Should -Be 3
    }

    It 'has no flags for a healthy admin' {
        (Get-AdhPrivilegedGroupMember -GroupName 'Domain Admins' | Where-Object SamAccountName -EQ 'gadmin').Flags | Should -BeNullOrEmpty
    }

    It 'flags disabled, stale, non-expiring and old-password members' {
        $flags = (Get-AdhPrivilegedGroupMember -GroupName 'Domain Admins' | Where-Object SamAccountName -EQ 'oadmin').Flags
        $flags | Should -Match 'Disabled account'
        $flags | Should -Match 'No sign-in for 90\+ days'
        $flags | Should -Match 'Password never expires'
        $flags | Should -Match 'Password older than 365 days'
    }

    It 'flags non-user members' {
        (Get-AdhPrivilegedGroupMember -GroupName 'Domain Admins' | Where-Object SamAccountName -EQ 'SRV01$').Flags | Should -Match 'Non-user member \(computer\)'
    }

    It 'warns and continues when a group cannot be read' {
        $result = @(Get-AdhPrivilegedGroupMember -GroupName 'Missing Group', 'Domain Admins' -WarningAction SilentlyContinue)
        $result.Count | Should -Be 3
    }
}

Describe 'Invoke-AdhStaleObjectRemediation' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Disable-ADAccount { }
        Mock -ModuleName AdHygieneToolkit Set-ADObject { }
        Mock -ModuleName AdHygieneToolkit Move-ADObject { }
        $script:Targets = @(
            New-FakeUser -Sam 'stale.one' -LastLogonDaysAgo 200 -Description 'Paralegal'
            New-FakeUser -Sam 'stale.two' -LastLogonDaysAgo 300
        )
        $script:Log = Join-Path -Path $TestDrive -ChildPath 'remediation.log'
    }

    It 'makes no changes with -WhatIf' {
        $result = $script:Targets | Invoke-AdhStaleObjectRemediation -Action DisableAndMove -TargetPath 'OU=Disabled,DC=contoso,DC=local' -LogPath $script:Log -WhatIf
        Should -Invoke -ModuleName AdHygieneToolkit Disable-ADAccount -Times 0 -Exactly
        Should -Invoke -ModuleName AdHygieneToolkit Move-ADObject -Times 0 -Exactly
        $result.Status | Should -Be @('WhatIf', 'WhatIf')
    }

    It 'still writes the audit log during -WhatIf' {
        $null = $script:Targets | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -WhatIf
        Test-Path -Path $script:Log | Should -BeTrue
    }

    It 'disables and stamps the description while preserving the old one' {
        $result = $script:Targets[0] | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -Confirm:$false
        $result.Status | Should -Be 'Success'
        Should -Invoke -ModuleName AdHygieneToolkit Disable-ADAccount -Times 1 -Exactly -ParameterFilter { $Identity -eq 'CN=stale.one,OU=Staff,DC=contoso,DC=local' }
        Should -Invoke -ModuleName AdHygieneToolkit Set-ADObject -Times 1 -Exactly -ParameterFilter { $Description -match '^Disabled by AD Hygiene Toolkit \d{4}-\d{2}-\d{2}; previous: Paralegal$' }
        Get-Content -Path $script:Log -Raw | Should -Match '\[ACTION\] Disabled CN=stale.one'
    }

    It 'moves objects to the target OU' {
        $null = $script:Targets | Invoke-AdhStaleObjectRemediation -Action Move -TargetPath 'OU=Disabled,DC=contoso,DC=local' -LogPath $script:Log -Confirm:$false
        Should -Invoke -ModuleName AdHygieneToolkit Move-ADObject -Times 2 -Exactly -ParameterFilter { $TargetPath -eq 'OU=Disabled,DC=contoso,DC=local' }
        Should -Invoke -ModuleName AdHygieneToolkit Disable-ADAccount -Times 0 -Exactly
    }

    It 'requires -TargetPath for Move' {
        { $script:Targets | Invoke-AdhStaleObjectRemediation -Action Move -LogPath $script:Log -Confirm:$false } | Should -Throw '*TargetPath is required*'
    }

    It 'skips protected (adminCount=1) objects unless -IncludeProtected' {
        $admin = New-FakeUser -Sam 'old.admin' -LastLogonDaysAgo 400 -AdminCount 1
        ($admin | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -Confirm:$false -WarningAction SilentlyContinue).Status | Should -Be 'Skipped'
        Should -Invoke -ModuleName AdHygieneToolkit Disable-ADAccount -Times 0 -Exactly
        ($admin | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -Confirm:$false -IncludeProtected).Status | Should -Be 'Success'
    }

    It 'refuses batches larger than -MaxObjects' {
        $many = 1..30 | ForEach-Object { New-FakeUser -Sam "u$_" -LastLogonDaysAgo 300 }
        { $many | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -Confirm:$false } | Should -Throw '*Refusing to process 30 objects*'
        Should -Invoke -ModuleName AdHygieneToolkit Disable-ADAccount -Times 0 -Exactly
    }

    It 'reports failures without stopping the batch' {
        Mock -ModuleName AdHygieneToolkit Disable-ADAccount -ParameterFilter { $Identity -like 'CN=stale.one*' } { throw 'Access is denied' }
        $result = $script:Targets | Invoke-AdhStaleObjectRemediation -Action Disable -LogPath $script:Log -Confirm:$false
        ($result | Where-Object DistinguishedName -Like 'CN=stale.one*').Status | Should -Be 'Failed'
        ($result | Where-Object DistinguishedName -Like 'CN=stale.two*').Status | Should -Be 'Success'
    }
}

Describe 'Invoke-AdhAudit' {
    BeforeAll {
        Mock -ModuleName AdHygieneToolkit Get-ADUser { New-FakeUser -Sam 'stale.user' -LastLogonDaysAgo 200 }
        Mock -ModuleName AdHygieneToolkit Get-ADComputer { }
        Mock -ModuleName AdHygieneToolkit Get-ADGroup { }
        Mock -ModuleName AdHygieneToolkit Get-ADGroupMember { }
        $script:Out = Join-Path -Path $TestDrive -ChildPath 'report'
        $script:Summary = Invoke-AdhAudit -OutputPath $script:Out
    }

    It 'writes the HTML dashboard' {
        Test-Path -Path (Join-Path -Path $script:Out -ChildPath 'index.html') | Should -BeTrue
        Get-Content -Path $script:Summary.ReportPath -Raw | Should -Match 'Active Directory Hygiene Report'
    }

    It 'writes one CSV per check' {
        foreach ($f in 'stale-users.csv', 'stale-computers.csv', 'non-expiring-passwords.csv', 'empty-groups.csv', 'privileged-members.csv') {
            Test-Path -Path (Join-Path -Path $script:Out -ChildPath $f) | Should -BeTrue
        }
        (Import-Csv -Path (Join-Path -Path $script:Out -ChildPath 'stale-users.csv')).SamAccountName | Should -Be 'stale.user'
    }

    It 'returns summary counts' {
        $script:Summary.StaleUsers | Should -Be 1
        $script:Summary.StaleComputers | Should -Be 0
    }

    It 'HTML-encodes directory data' {
        Mock -ModuleName AdHygieneToolkit Get-ADUser { New-FakeUser -Sam '<script>x</script>' -LastLogonDaysAgo 200 }
        $s = Invoke-AdhAudit -OutputPath (Join-Path -Path $TestDrive -ChildPath 'enc')
        $html = Get-Content -Path $s.ReportPath -Raw
        $html | Should -Not -Match '<script>x</script>'
        $html | Should -Match '&lt;script&gt;'
    }
}
