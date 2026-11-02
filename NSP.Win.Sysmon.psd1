@{
    RootModule = 'NSP.Win.Sysmon.psm1'
    ModuleVersion = '0.1.1'
    GUID = '9139e989-f0b7-4e0f-b15d-adc65a505bac'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) 2026 Network Systems Plus. All rights reserved.'
    Description = 'Sysmon as a file watch: build a config that logs a file-create event for chosen folders (and nothing else), install or apply it without clobbering someone else''s, and check it is in force without elevation.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Find-NSPSysmon'
        'Get-NSPSysmonStatus'
        'Install-NSPSysmon'
        'New-NSPSysmonFileWatchConfig'
        'Save-NSPSysmon'
        'Test-NSPSysmonConfig'
        'Uninstall-NSPSysmon'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Sysmon', 'Sysinternals', 'FileWatch', 'EventLog', 'Automation', 'Windows', 'NSP')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-Win-Sysmon'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-Win-Sysmon/blob/main/LICENSE'
            ReleaseNotes = '0.1.1: RuleGroupOnly include-only fragment; RuleName for trigger filtering; Save-NSPSysmon downloads Sysmon and keeps it only when Microsoft-signed.'
        }
    }
}
