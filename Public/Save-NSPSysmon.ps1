function Save-NSPSysmon {
    <#
    .SYNOPSIS
        Downloads Sysmon from Microsoft's Sysinternals site and keeps it only when it carries a valid Microsoft signature.
    .DESCRIPTION
        For a computer without Sysmon, when the operator chose to download it. Fetches the official
        Sysmon.zip, picks the binary for this processor (Sysmon64a.exe on ARM64, Sysmon64.exe on
        other 64-bit Windows, else Sysmon.exe) and checks its Authenticode signature: the status must
        be Valid and the signer's organization Microsoft Corporation. Only then are the binary and
        its EULA copied to -Destination. Nothing is installed; pass the returned Path to
        Install-NSPSysmon. A failed check throws and leaves -Destination unchanged.
    .EXAMPLE
        $sysmon = Save-NSPSysmon -Destination 'C:\ProgramData\NSP\Sysmon'
        Install-NSPSysmon -SysmonPath $sysmon.Path -ConfigPath 'C:\ProgramData\NSP\ScanBridge\Sysmon.xml' -Configuration $xml
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Destination,
        [ValidatePattern('^https://')][string]$Uri = 'https://download.sysinternals.com/files/Sysmon.zip'
    )

    if (-not $PSCmdlet.ShouldProcess($Destination, "Download Sysmon from $Uri")) { return }
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $binary = if ($architecture -eq 'ARM64') { 'Sysmon64a.exe' } elseif ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('nsp-sysmon-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $zip = Join-Path $work 'Sysmon.zip'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Uri -OutFile $zip -UseBasicParsing -ErrorAction Stop
        $expanded = Join-Path $work 'files'
        Expand-Archive -LiteralPath $zip -DestinationPath $expanded -ErrorAction Stop
        $exe = Join-Path $expanded $binary
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "The download does not contain $binary." }
        $signature = Get-AuthenticodeSignature -LiteralPath $exe
        $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
        if ([string]$signature.Status -ne 'Valid' -or $signer -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
            throw "Downloaded $binary is not validly signed by Microsoft (status $($signature.Status), signer '$signer'). Nothing was kept."
        }
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        $target = Join-Path $Destination $binary
        Copy-Item -LiteralPath $exe -Destination $target -Force
        $eula = Join-Path $expanded 'Eula.txt'
        if (Test-Path -LiteralPath $eula) { Copy-Item -LiteralPath $eula -Destination (Join-Path $Destination 'Eula.txt') -Force }
        [pscustomobject]@{
            Path = (Get-Item -LiteralPath $target).FullName
            Version = (Get-Item -LiteralPath $target).VersionInfo.FileVersion
            Signer = $signer
            Thumbprint = $signature.SignerCertificate.Thumbprint
        }
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
