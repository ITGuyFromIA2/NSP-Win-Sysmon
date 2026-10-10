function Uninstall-NSPSysmon {
    <#
    .SYNOPSIS
        Removes Sysmon from this computer (service and driver), using the installed copy. Elevated.
    .DESCRIPTION
        Sysmon is computer-wide: removing it stops every rule, not just a file watch. -Force passes
        "-u force", for a service that won't stop cleanly.
    .EXAMPLE
        Uninstall-NSPSysmon -Confirm:$false
    .EXAMPLE
        Uninstall-NSPSysmon -Force
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([switch]$Force)

    $status = Get-NSPSysmonStatus
    if (-not $status.Installed) { Write-Verbose 'Sysmon is not installed.'; return }
    if (-not $status.ImagePath -or -not (Test-Path -LiteralPath $status.ImagePath -PathType Leaf)) { throw "The installed Sysmon binary ($($status.ImagePath)) is missing; remove the $($status.ServiceName) service by hand." }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Uninstall Sysmon ($($status.ServiceName), configuration $($status.ConfigFile))")) { return }
    $argList = @('-u')
    if ($Force) { $argList += 'force' }
    $run = Invoke-NSPSysmonExe -FilePath $status.ImagePath -ArgumentList $argList
    if ($run.ExitCode -ne 0 -or @($run.Output) -match 'launch Sysmon as an Administrator') {
        throw "Sysmon uninstall failed (exit code $($run.ExitCode)): $(@($run.Output) -join ' | ')"
    }
    @($run.Output) | ForEach-Object { Write-Verbose $_ }
}
