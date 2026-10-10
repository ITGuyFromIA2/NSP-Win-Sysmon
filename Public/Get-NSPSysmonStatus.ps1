function Get-NSPSysmonStatus {
    <#
    .SYNOPSIS
        Reports whether Sysmon is installed and running, its version, and which configuration file (and hash) it loaded. No elevation needed.
    .DESCRIPTION
        Reads the service and driver registry values (Sysmon64 or Sysmon service). -IncludeRules
        also lists the loaded rules from "sysmon -c", which needs an elevated session.
    .EXAMPLE
        Get-NSPSysmonStatus
    .EXAMPLE
        (Get-NSPSysmonStatus -IncludeRules).Rules | Where-Object Event -eq 'FileCreate'
    #>
    [CmdletBinding()]
    [OutputType('NSP.Win.Sysmon.Status')]
    param([switch]$IncludeRules)

    $status = [ordered]@{
        PSTypeName = 'NSP.Win.Sysmon.Status'
        Installed = $false; Running = $false; ServiceName = $null; DriverName = $null
        ImagePath = $null; Version = $null; ConfigFile = $null; ConfigHash = $null; Rules = $null
    }
    $service = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($service) {
        $reg = Get-NSPSysmonRegistry -ServiceName $service.Name
        $status.Installed = $true
        $status.Running = ("$($service.Status)" -eq 'Running')
        $status.ServiceName = $service.Name
        $status.DriverName = $reg.DriverName
        $status.ImagePath = $reg.ImagePath
        $status.ConfigFile = $reg.ConfigFile
        $status.ConfigHash = $reg.ConfigHash
        if ($reg.ImagePath -and (Test-Path -LiteralPath $reg.ImagePath -PathType Leaf)) {
            $status.Version = (Get-Item -LiteralPath $reg.ImagePath).VersionInfo.FileVersion
        }
        if ($IncludeRules -and $reg.ImagePath) {
            $run = Invoke-NSPSysmonExe -FilePath $reg.ImagePath -ArgumentList '-c'
            if (@($run.Output) -match 'launch Sysmon as an Administrator') { Write-Warning 'Listing the loaded rules needs an elevated session.' }
            else { $status.Rules = @(ConvertFrom-NSPSysmonRuleText -Line $run.Output) }
        }
    }
    [pscustomobject]$status
}
