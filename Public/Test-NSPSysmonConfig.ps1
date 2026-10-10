function Test-NSPSysmonConfig {
    <#
    .SYNOPSIS
        Checks Sysmon is installed, running, and has loaded exactly this configuration: InSync plus one line per problem. Read-only, no elevation needed.
    .DESCRIPTION
        Compares the driver's recorded config file and hash with -ConfigPath. With -Configuration
        (e.g. from New-NSPSysmonFileWatchConfig), the hash is checked against that text - written
        the way Install-NSPSysmon writes it - and the file on disk is checked too; without it,
        against the file at -ConfigPath as it is now.
    .EXAMPLE
        Test-NSPSysmonConfig -ConfigPath 'D:\Jobs\Sysmon.xml' -Configuration (New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Outbound')
    .EXAMPLE
        (Test-NSPSysmonConfig -ConfigPath 'D:\Jobs\Sysmon.xml').Problems
    #>
    [CmdletBinding()]
    [OutputType('NSP.Win.Sysmon.ConfigTest')]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$Configuration
    )

    $full = [IO.Path]::GetFullPath($ConfigPath)
    $status = Get-NSPSysmonStatus
    $problems = [Collections.Generic.List[string]]::new()
    $onDisk = if (Test-Path -LiteralPath $full -PathType Leaf) { [IO.File]::ReadAllBytes($full) }

    if (-not $status.Installed) {
        $problems.Add('Sysmon is not installed.')
    } else {
        if (-not $status.Running) { $problems.Add("The $($status.ServiceName) service is not running.") }
        if (-not $status.ConfigFile -or [IO.Path]::GetFullPath($status.ConfigFile) -ne $full) {
            $problems.Add("Sysmon is using $(if ($status.ConfigFile) { $status.ConfigFile } else { 'no configuration file' }), not $full.")
        }
        $expected = if ($Configuration) { ConvertTo-NSPSysmonConfigBytes -Configuration $Configuration } else { $onDisk }
        if ($null -eq $expected) {
            $problems.Add("$full does not exist.")
        } elseif ($status.ConfigHash) {
            $algorithm = ($status.ConfigHash -split '=', 2)[0]
            if ((Get-NSPSysmonHash -Bytes $expected -Algorithm $algorithm) -ne $status.ConfigHash) {
                $problems.Add("The configuration Sysmon loaded differs from $(if ($Configuration) { 'the expected one' } else { $full }) - re-apply it (Install-NSPSysmon).")
            }
        }
    }
    if ($Configuration) {
        $want = ConvertTo-NSPSysmonConfigBytes -Configuration $Configuration
        if ($null -eq $onDisk) { if ($problems -notcontains "$full does not exist.") { $problems.Add("$full does not exist.") } }
        elseif ([Convert]::ToBase64String($onDisk) -ne [Convert]::ToBase64String($want)) { $problems.Add("$full differs from the expected configuration.") }
    }

    [pscustomobject]@{
        PSTypeName = 'NSP.Win.Sysmon.ConfigTest'
        ConfigPath = $full
        Installed = $status.Installed
        InSync = ($problems.Count -eq 0)
        Problems = @($problems)
        Status = $status
    }
}
