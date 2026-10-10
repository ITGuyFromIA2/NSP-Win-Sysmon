function Install-NSPSysmon {
    <#
    .SYNOPSIS
        Installs Sysmon with a configuration, or applies the configuration to the Sysmon already installed. Elevated.
    .DESCRIPTION
        With -Configuration the text is first written to -ConfigPath (UTF-8, CRLF - the bytes
        Test-NSPSysmonConfig expects). Not installed: "<SysmonPath> -accepteula -i <ConfigPath>".
        Installed: "<installed Sysmon> -c <ConfigPath>", using the installed copy so the binary
        and driver versions match.

        Sysmon has one configuration per computer. When the installed Sysmon is using a different
        configuration file - someone else's monitoring, perhaps - this stops unless -Force, since
        applying ours replaces theirs. Returns the status afterwards (Get-NSPSysmonStatus).
    .EXAMPLE
        $xml = New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Outbound' -ExcludeExtension '.pgp'
        Install-NSPSysmon -SysmonPath 'C:\Jobs\SetupFiles' -ConfigPath 'D:\Jobs\Sysmon.xml' -Configuration $xml
    .EXAMPLE
        Install-NSPSysmon -ConfigPath 'D:\Jobs\Sysmon.xml' -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType('NSP.Win.Sysmon.Status')]
    param(
        [string]$SysmonPath,
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$Configuration,
        [switch]$Force
    )

    $full = [IO.Path]::GetFullPath($ConfigPath)
    $status = Get-NSPSysmonStatus
    if ($status.Installed -and $status.ConfigFile -and [IO.Path]::GetFullPath($status.ConfigFile) -ne $full -and -not $Force) {
        throw "Sysmon here already uses $($status.ConfigFile). Sysmon has one configuration per computer, so applying $full replaces it. Merge the rules into one file, or pass -Force to replace it."
    }
    if (-not $Configuration -and -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$full does not exist; pass -Configuration to write it." }

    if ($status.Installed) {
        $exe = $status.ImagePath
        $argList = @('-accepteula', '-c', $full)
        $what = "Apply Sysmon configuration $full"
    } else {
        $exe = Find-NSPSysmon -Path $SysmonPath
        if (-not $exe) { throw 'Sysmon not found. Pass -SysmonPath, set NSP_SYSMON, or put Sysmon64.exe on PATH (https://learn.microsoft.com/sysinternals/downloads/sysmon).' }
        $argList = @('-accepteula', '-i', $full)
        $what = "Install Sysmon ($exe) with configuration $full"
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $what)) { return }

    if ($Configuration) {
        $folder = Split-Path -Parent $full
        if (-not (Test-Path -LiteralPath $folder)) { $null = New-Item -ItemType Directory -Path $folder -Force }
        [IO.File]::WriteAllBytes($full, (ConvertTo-NSPSysmonConfigBytes -Configuration $Configuration))
    }
    $run = Invoke-NSPSysmonExe -FilePath $exe -ArgumentList $argList
    if ($run.ExitCode -ne 0 -or @($run.Output) -match 'launch Sysmon as an Administrator|^Error|failed') {
        throw "Sysmon failed (exit code $($run.ExitCode)): $(@($run.Output) -join ' | ')"
    }
    @($run.Output) | ForEach-Object { Write-Verbose $_ }
    Get-NSPSysmonStatus
}
