function Get-NSPSysmonRegistry {
    # What the installed service and driver record, readable without elevation. ConfigHash is
    # "<ALGORITHM>=<hex>" of the config file's bytes as Sysmon loaded them.
    param([Parameter(Mandatory)][string]$ServiceName)
    $services = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $service = Get-ItemProperty -LiteralPath (Join-Path $services $ServiceName) -ErrorAction SilentlyContinue
    $driver = (Get-ItemProperty -LiteralPath (Join-Path $services "$ServiceName\Parameters") -ErrorAction SilentlyContinue).DriverName
    if (-not $driver) { $driver = 'SysmonDrv' }
    $parameters = Get-ItemProperty -LiteralPath (Join-Path $services "$driver\Parameters") -ErrorAction SilentlyContinue
    $image = $null
    if ($service.ImagePath) { $image = [Environment]::ExpandEnvironmentVariables(($service.ImagePath -replace '^"([^"]+)".*$', '$1')) }
    [pscustomobject]@{
        ImagePath = $image
        DriverName = $driver
        ConfigFile = $parameters.ConfigFile
        ConfigHash = $parameters.ConfigHash
    }
}

function ConvertTo-NSPSysmonConfigBytes {
    # The bytes Install writes and Test hashes: UTF-8 without BOM, CRLF.
    param([Parameter(Mandatory)][string]$Configuration)
    $text = ($Configuration -replace "`r?`n", "`r`n")
    [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Get-NSPSysmonHash {
    # Same notation as the driver's ConfigHash value, in the algorithm it names (SHA256 by default).
    param([Parameter(Mandatory)][byte[]]$Bytes, [string]$Algorithm = 'SHA256')
    $hasher = [Security.Cryptography.HashAlgorithm]::Create($Algorithm.ToUpperInvariant())
    if (-not $hasher) { throw "Unknown hash algorithm '$Algorithm'." }
    try { "$($Algorithm.ToUpperInvariant())=$(-join ($hasher.ComputeHash($Bytes) | ForEach-Object { $_.ToString('X2') }))" } finally { $hasher.Dispose() }
}

function Invoke-NSPSysmonExe {
    # Runs Sysmon and returns its exit code and combined output. Sysmon needs elevation for
    # everything except -s and -?.
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList)
    $quoted = foreach ($arg in $ArgumentList) { if ($arg -match '[\s"]') { '"' + ($arg -replace '"', '\"') + '"' } else { $arg } }
    $psi = [Diagnostics.ProcessStartInfo]::new($FilePath, (@($quoted) -join ' '))
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    Write-Verbose "$FilePath $($psi.Arguments)"
    $process = [Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $lines = @(($stdout.Result + "`n" + $stderr.Result) -split "`r?`n" | Where-Object { $_.Trim() } |
                Where-Object { $_ -notmatch '^(System Monitor v|By Mark Russinovich|Copyright \(C\)|Using libxml2|Sysinternals - )' })
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $lines }
    } finally {
        $process.Dispose()
    }
}

function ConvertFrom-NSPSysmonRuleText {
    # Rules from "sysmon -c" output: an "- <Event>  onmatch: include|exclude" header, then
    # "<Field>  filter: <condition>  value: '<value>'" lines under it.
    param([string[]]$Line)
    $eventName = $null; $onMatch = $null
    foreach ($l in $Line) {
        if ($l -match "^\s*-\s*(?<event>\w+)\s+onmatch:\s*(?<match>include|exclude)") {
            $eventName = $Matches.event; $onMatch = $Matches.match
        } elseif ($eventName -and $l -match "^\s*(?<field>\w+)\s+filter:\s*(?<cond>.+?)\s+value:\s*'(?<value>.*)'\s*$") {
            [pscustomobject]@{ Event = $eventName; OnMatch = $onMatch; Field = $Matches.field; Condition = $Matches.cond; Value = $Matches.value }
        }
    }
}
