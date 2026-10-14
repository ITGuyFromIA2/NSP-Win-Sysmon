<#
    Pester 5. Sysmon is never installed, changed, or removed: Get-Service, the registry reader
    (Get-NSPSysmonRegistry), and the Sysmon runner (Invoke-NSPSysmonExe) are mocked. With
    NSP_SYSMON_EXE pointing at a real Sysmon binary, the generated configuration is also checked
    against that binary's own schema ("sysmon -s", which needs no elevation).
#>

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.Win.Sysmon.psd1') -Force -ErrorAction Stop
    $script:capture = @{}
    function Get-TestHash([string]$Text) {
        InModuleScope NSP.Win.Sysmon -Parameters @{ T = $Text } { param($T) Get-NSPSysmonHash -Bytes (ConvertTo-NSPSysmonConfigBytes -Configuration $T) }
    }
    function Use-TestSysmon {
        param([string]$ConfigFile, [string]$ConfigHash, [string]$State = 'Running', [string]$ImagePath = 'C:\Windows\Sysmon64.exe')
        $script:capture.Reg = [pscustomobject]@{ ImagePath = $ImagePath; DriverName = 'SysmonDrv'; ConfigFile = $ConfigFile; ConfigHash = $ConfigHash }
        $script:capture.State = $State
        Mock -ModuleName NSP.Win.Sysmon Get-Service { [pscustomobject]@{ Name = 'Sysmon64'; Status = $script:capture.State } }
        Mock -ModuleName NSP.Win.Sysmon Get-NSPSysmonRegistry { $script:capture.Reg }
    }
    function Use-TestNoSysmon { Mock -ModuleName NSP.Win.Sysmon Get-Service { } }
}

Describe 'New-NSPSysmonFileWatchConfig' {
    It 'includes file creates under each folder (with a trailing backslash) and excludes the extensions' {
        $xml = [xml](New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out', 'D:\Drop\' -ExcludeExtension 'pgp', '.tmp')
        $xml.Sysmon.schemaversion | Should -Be '4.50'
        $groups = @($xml.Sysmon.EventFiltering.RuleGroup)
        $include = @($groups | Where-Object { $_.FileCreate.onmatch -eq 'include' }).FileCreate.TargetFilename
        @($include | ForEach-Object { "$($_.condition)|$($_.'#text')" }) | Should -Be @('begin with|D:\Jobs\Out\', 'begin with|D:\Drop\')
        $exclude = @($groups | Where-Object { $_.FileCreate.onmatch -eq 'exclude' }).FileCreate.TargetFilename
        @($exclude | ForEach-Object { "$($_.condition)|$($_.'#text')" }) | Should -Be @('end with|.pgp', 'end with|.tmp')
    }
    It 'with -IncludeExtension matches each folder AND one of the extensions' {
        $xml = [xml](New-NSPSysmonFileWatchConfig -Path 'D:\Drop', 'E:\In' -IncludeExtension 'txt', '*.csv')
        $rules = @(@($xml.Sysmon.EventFiltering.RuleGroup | Where-Object { $_.FileCreate.onmatch -eq 'include' }).FileCreate.Rule)
        $rules | ForEach-Object groupRelation | Select-Object -Unique | Should -Be 'and'
        @($rules | ForEach-Object { ($_.TargetFilename | ForEach-Object { "$($_.condition)|$($_.'#text')" }) -join ' & ' }) | Should -Be @(
            'begin with|D:\Drop\ & end with|.txt', 'begin with|D:\Drop\ & end with|.csv',
            'begin with|E:\In\ & end with|.txt', 'begin with|E:\In\ & end with|.csv')
        @($xml.Sysmon.EventFiltering.RuleGroup | Where-Object { $_.FileCreate.onmatch -eq 'include' }).FileCreate.TargetFilename | Should -BeNullOrEmpty -Because 'no bare folder rule would match every file'
    }
    It 'turns every other event type off by default, and leaves them alone with -KeepDefaultEvents' {
        $xml = [xml](New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out')
        $off = @($xml.Sysmon.EventFiltering.RuleGroup | ForEach-Object { $_.ChildNodes } | Where-Object { $_.Name -ne 'FileCreate' -and $_.onmatch -eq 'include' -and -not $_.HasChildNodes } | ForEach-Object Name)
        $off | Should -Contain 'ProcessCreate'
        $off | Should -Contain 'ProcessTampering'
        $off | Should -Not -Contain 'FileExecutableDetected' -Because 'schema 4.50 has no such event'
        $kept = [xml](New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out' -KeepDefaultEvents)
        @($kept.Sysmon.EventFiltering.RuleGroup).Count | Should -Be 1
    }
    It 'adds the newer event types for schema 4.90' {
        (New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out' -SchemaVersion '4.90') | Should -BeLike '*<FileExecutableDetected onmatch="include" />*'
    }
    It 'escapes XML in folder names' {
        ([xml](New-NSPSysmonFileWatchConfig -Path "D:\R&D's in")).Sysmon.EventFiltering.RuleGroup[0].FileCreate.TargetFilename.'#text' | Should -Be "D:\R&D's in\"
    }
    It 'matches the schema of a real Sysmon binary' -Skip:(-not ($env:NSP_SYSMON_EXE -and (Test-Path -LiteralPath "$env:NSP_SYSMON_EXE"))) {
        $text = (& $env:NSP_SYSMON_EXE -s 2>&1 | Out-String)
        $manifest = [xml]$text.Substring($text.IndexOf('<manifest'))
        $known = @($manifest.manifest.events.event | ForEach-Object rulename | Where-Object { $_ })
        $schema = $manifest.manifest.schemaversion
        $xml = [xml](New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out' -ExcludeExtension 'pgp' -SchemaVersion $schema)
        $used = @($xml.Sysmon.EventFiltering.RuleGroup | ForEach-Object { $_.ChildNodes } | ForEach-Object Name | Select-Object -Unique)
        $used | Where-Object { $known -notcontains $_ } | Should -BeNullOrEmpty
        $fields = @(($manifest.manifest.events.event | Where-Object rulename -eq 'FileCreate').data | ForEach-Object name)
        $fields | Should -Contain 'TargetFilename'
        $conditions = @($manifest.manifest.configuration.filters.InnerText -split ',')
        $conditions | Should -Contain 'begin with'
        $conditions | Should -Contain 'end with'
    }
}

Describe 'Get-NSPSysmonStatus' {
    It 'reports not installed' {
        Use-TestNoSysmon
        $s = Get-NSPSysmonStatus
        $s.Installed | Should -BeFalse
        $s.ConfigFile | Should -BeNullOrEmpty
    }
    It 'reads the service and the configuration it loaded' {
        Use-TestSysmon -ConfigFile 'D:\Jobs\Sysmon.xml' -ConfigHash 'SHA256=AB'
        $s = Get-NSPSysmonStatus
        $s.Installed | Should -BeTrue
        $s.Running | Should -BeTrue
        $s.ServiceName | Should -Be 'Sysmon64'
        $s.ConfigFile | Should -Be 'D:\Jobs\Sysmon.xml'
        $s.ConfigHash | Should -Be 'SHA256=AB'
    }
    It 'parses the loaded rules with -IncludeRules' {
        Use-TestSysmon -ConfigFile 'D:\Jobs\Sysmon.xml' -ConfigHash 'SHA256=AB' -ImagePath $PSCommandPath
        Mock -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe { [pscustomobject]@{ ExitCode = 0; Output = @(
                    'Current configuration:', ' - Service name:                  Sysmon64',
                    'Rule configuration (version 4.50):',
                    ' - FileCreate                         onmatch: include   combine rules using ''Or''',
                    "        TargetFilename                 filter: begin with   value: 'D:\Jobs\Out\'",
                    ' - FileCreate                         onmatch: exclude   combine rules using ''Or''',
                    "        TargetFilename                 filter: end with     value: '.pgp'") } }
        $rules = (Get-NSPSysmonStatus -IncludeRules).Rules
        @($rules | ForEach-Object { "$($_.Event)|$($_.OnMatch)|$($_.Field)|$($_.Condition)|$($_.Value)" }) |
            Should -Be @('FileCreate|include|TargetFilename|begin with|D:\Jobs\Out\', 'FileCreate|exclude|TargetFilename|end with|.pgp')
    }
}

Describe 'Test-NSPSysmonConfig' {
    BeforeAll {
        $script:cfg = New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out' -ExcludeExtension 'pgp'
        $script:path = Join-Path $TestDrive 'Sysmon.xml'
    }
    BeforeEach {
        [IO.File]::WriteAllBytes($script:path, (InModuleScope NSP.Win.Sysmon -Parameters @{ C = $script:cfg } { param($C) ConvertTo-NSPSysmonConfigBytes -Configuration $C }))
    }
    It 'is in sync when Sysmon loaded this file with this content' {
        Use-TestSysmon -ConfigFile $script:path -ConfigHash (Get-TestHash $script:cfg)
        $t = Test-NSPSysmonConfig -ConfigPath $script:path -Configuration $script:cfg
        $t.Problems | Should -BeNullOrEmpty
        $t.InSync | Should -BeTrue
    }
    It 'notices a different configuration loaded, a stopped service, and another file' {
        Use-TestSysmon -ConfigFile 'C:\Other\Sysmon.xml' -ConfigHash 'SHA256=00' -State 'Stopped'
        $t = Test-NSPSysmonConfig -ConfigPath $script:path -Configuration $script:cfg
        $t.InSync | Should -BeFalse
        ($t.Problems -join "`n") | Should -BeLike '*not running*'
        ($t.Problems -join "`n") | Should -BeLike '*using C:\Other\Sysmon.xml*'
        ($t.Problems -join "`n") | Should -BeLike '*differs from the expected one*'
    }
    It 'notices the file on disk was changed but not applied' {
        Use-TestSysmon -ConfigFile $script:path -ConfigHash (Get-TestHash $script:cfg)
        Add-Content -LiteralPath $script:path -Value '<!-- edited -->'
        $t = Test-NSPSysmonConfig -ConfigPath $script:path -Configuration $script:cfg
        $t.Problems | Should -Be @("$script:path differs from the expected configuration.")
        (Test-NSPSysmonConfig -ConfigPath $script:path).Problems | Should -BeLike '*re-apply*' -Because 'without -Configuration the file itself is the expectation'
    }
    It 'reports Sysmon not installed' {
        Use-TestNoSysmon
        (Test-NSPSysmonConfig -ConfigPath $script:path -Configuration $script:cfg).Problems | Should -Be @('Sysmon is not installed.')
    }
}

Describe 'Install-NSPSysmon' {
    BeforeAll {
        $script:cfg = New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Out'
        $script:path = Join-Path $TestDrive 'cfg\Sysmon.xml'
        $script:exe = Join-Path $TestDrive 'Sysmon64.exe'
        Set-Content -LiteralPath $script:exe -Value 'x'
    }
    BeforeEach {
        Remove-Item -LiteralPath $script:path -ErrorAction SilentlyContinue
        Mock -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe { $script:capture.Run = [pscustomobject]@{ FilePath = $FilePath; Arguments = @($ArgumentList) }; [pscustomobject]@{ ExitCode = 0; Output = @('Configuration updated.') } }
    }
    It 'installs with -i when Sysmon is absent, writing the configuration first' {
        Use-TestNoSysmon
        $null = Install-NSPSysmon -SysmonPath $script:exe -ConfigPath $script:path -Configuration $script:cfg -Confirm:$false
        $script:capture.Run.FilePath | Should -Be $script:exe
        $script:capture.Run.Arguments | Should -Be @('-accepteula', '-i', $script:path)
        [IO.File]::ReadAllText($script:path) | Should -BeExactly ($script:cfg -replace "`r?`n", "`r`n")
    }
    It 'applies with -c using the installed copy when Sysmon already uses this file' {
        Use-TestSysmon -ConfigFile $script:path -ConfigHash 'SHA256=00'
        $null = Install-NSPSysmon -ConfigPath $script:path -Configuration $script:cfg -Confirm:$false
        $script:capture.Run.FilePath | Should -Be 'C:\Windows\Sysmon64.exe'
        $script:capture.Run.Arguments | Should -Be @('-accepteula', '-c', $script:path)
    }
    It 'refuses to replace another configuration without -Force' {
        Use-TestSysmon -ConfigFile 'C:\Security\sysmonconfig.xml' -ConfigHash 'SHA256=00'
        { Install-NSPSysmon -ConfigPath $script:path -Configuration $script:cfg -Confirm:$false } | Should -Throw '*already uses C:\Security\sysmonconfig.xml*-Force*'
        Should -Invoke -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe -Times 0
        Test-Path -LiteralPath $script:path | Should -BeFalse -Because 'nothing is written when it stops'
        $null = Install-NSPSysmon -ConfigPath $script:path -Configuration $script:cfg -Force -Confirm:$false
        $script:capture.Run.Arguments | Should -Be @('-accepteula', '-c', $script:path)
    }
    It 'throws with Sysmon''s message when it fails' {
        Use-TestNoSysmon
        Mock -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe { [pscustomobject]@{ ExitCode = 1; Output = @('Error: Incorrect or unsupported schema version: 9.99') } }
        { Install-NSPSysmon -SysmonPath $script:exe -ConfigPath $script:path -Configuration $script:cfg -Confirm:$false } | Should -Throw '*unsupported schema version*'
    }
    It 'changes nothing with -WhatIf' {
        Use-TestNoSysmon
        Install-NSPSysmon -SysmonPath $script:exe -ConfigPath $script:path -Configuration $script:cfg -WhatIf
        Should -Invoke -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe -Times 0
        Test-Path -LiteralPath $script:path | Should -BeFalse
    }
}

Describe 'Uninstall-NSPSysmon' {
    It 'runs -u force with the installed copy' {
        Use-TestSysmon -ConfigFile 'D:\Jobs\Sysmon.xml' -ConfigHash 'SHA256=00' -ImagePath $PSCommandPath
        Mock -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe { $script:capture.Run = @($ArgumentList); [pscustomobject]@{ ExitCode = 0; Output = @('Sysmon64 removed.') } }
        Uninstall-NSPSysmon -Force -Confirm:$false
        $script:capture.Run | Should -Be @('-u', 'force')
    }
    It 'does nothing when Sysmon is absent' {
        Use-TestNoSysmon
        Mock -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe { }
        Uninstall-NSPSysmon -Confirm:$false
        Should -Invoke -ModuleName NSP.Win.Sysmon Invoke-NSPSysmonExe -Times 0
    }
}

Describe 'Find-NSPSysmon' {
    It 'finds Sysmon64 in a folder, and the installed copy when no path is given' {
        $dir = Join-Path $TestDrive 'bin'; $null = New-Item -ItemType Directory -Path $dir
        Set-Content -LiteralPath (Join-Path $dir 'Sysmon64.exe') -Value 'x'; Set-Content -LiteralPath (Join-Path $dir 'Sysmon.exe') -Value 'x'
        $expected = if ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }
        Split-Path -Leaf (Find-NSPSysmon -Path $dir) | Should -Be $expected
        Use-TestSysmon -ConfigFile 'x' -ConfigHash 'x' -ImagePath (Join-Path $dir 'Sysmon.exe')
        Find-NSPSysmon | Should -Be (Join-Path $dir 'Sysmon.exe')
    }
}

Describe 'Hashing (real)' {
    It 'matches Get-FileHash over the bytes written, in the driver''s notation' {
        $file = Join-Path $TestDrive 'h.xml'
        $bytes = InModuleScope NSP.Win.Sysmon { ConvertTo-NSPSysmonConfigBytes -Configuration "<Sysmon>`n</Sysmon>" }
        [IO.File]::WriteAllBytes($file, $bytes)
        InModuleScope NSP.Win.Sysmon -Parameters @{ B = $bytes } { param($B) Get-NSPSysmonHash -Bytes $B } | Should -Be "SHA256=$((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash)"
    }
}
