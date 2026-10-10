function Find-NSPSysmon {
    <#
    .SYNOPSIS
        Finds the Sysmon executable: the given file or folder, then NSP_SYSMON, then the installed service's copy, then PATH. Returns its full path, or nothing.
    .DESCRIPTION
        A folder is searched for Sysmon64.exe (on 64-bit Windows) then Sysmon.exe. NSP.Win.Sysmon
        never downloads Sysmon; get it from https://learn.microsoft.com/sysinternals/downloads/sysmon.
    .EXAMPLE
        Find-NSPSysmon -Path 'C:\Jobs\SetupFiles'
    .EXAMPLE
        if (-not (Find-NSPSysmon)) { 'Sysmon missing' }
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Path)

    $names = if ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe', 'Sysmon.exe' } else { , 'Sysmon.exe' }
    foreach ($candidate in @($Path, $env:NSP_SYSMON)) {
        if (-not $candidate) { continue }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).ProviderPath }
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            foreach ($name in $names) {
                $file = Join-Path $candidate $name
                if (Test-Path -LiteralPath $file -PathType Leaf) { return (Resolve-Path -LiteralPath $file).ProviderPath }
            }
        }
        Write-Verbose "No Sysmon at '$candidate'"
    }
    $status = Get-NSPSysmonStatus
    if ($status.ImagePath -and (Test-Path -LiteralPath $status.ImagePath -PathType Leaf)) { return $status.ImagePath }
    foreach ($name in $names) {
        $command = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) { return $command.Source }
    }
}
