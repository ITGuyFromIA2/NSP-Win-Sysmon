function New-NSPSysmonFileWatchConfig {
    <#
    .SYNOPSIS
        Builds a Sysmon configuration that logs a file-create event (ID 11) when a file lands in the given folders - and, by default, nothing else.
    .DESCRIPTION
        For triggering a job when a file arrives: a scheduled task on Sysmon event 11
        (New-NSPEventTaskTrigger in NSP.Win.ScheduledTask) picks the event up. Returns the XML as
        text; Install-NSPSysmon writes and applies it, Test-NSPSysmonConfig checks it is in force.

        Each folder matches files anywhere beneath it ("begin with" the folder plus a backslash, so
        C:\Drop doesn't also match C:\Dropbox). -IncludeExtension narrows that to files with
        those extensions (each folder AND one of the extensions). -ExcludeExtension skips files
        the job writes itself (e.g. its own .pgp output) so it doesn't trigger on them.

        Sysmon has one configuration per computer. Unless -KeepDefaultEvents, every other event
        type gets an empty include rule (log nothing), so the computer's Sysmon log holds only the
        file watch - not every process start, which Sysmon logs when no rule says otherwise.
    .EXAMPLE
        New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Outbound' -ExcludeExtension '.pgp'
    .EXAMPLE
        New-NSPSysmonFileWatchConfig -Path 'D:\Drop' -IncludeExtension '.txt'
    .EXAMPLE
        $xml = New-NSPSysmonFileWatchConfig -Path 'D:\Drop\A', 'D:\Drop\B'
        Install-NSPSysmon -SysmonPath 'C:\Tools\Sysmon64.exe' -ConfigPath 'D:\Jobs\Sysmon.xml' -Configuration $xml
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Returns text; changes nothing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [string[]]$IncludeExtension,
        [string[]]$ExcludeExtension,
        [ValidatePattern('^\d+\.\d+$')][string]$SchemaVersion = '4.50',
        [switch]$KeepDefaultEvents
    )

    $escape = { [Security.SecurityElement]::Escape([string]$args[0]) }
    $folders = foreach ($p in $Path) {
        $full = [IO.Path]::GetFullPath($p).TrimEnd('\')
        "$full\"
    }
    $toExtension = { foreach ($e in $args[0]) { if ($e) { '.' + $e.TrimStart('.', '*') } } }
    $includes = @(& $toExtension $IncludeExtension)
    $extensions = @(& $toExtension $ExcludeExtension)

    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("<Sysmon schemaversion=`"$SchemaVersion`">")
    $lines.Add('  <!-- File watch built by NSP.Win.Sysmon (New-NSPSysmonFileWatchConfig). Sysmon has one configuration per computer. -->')
    $lines.Add('  <EventFiltering>')
    $lines.Add('    <RuleGroup name="NSP file watch" groupRelation="or">')
    $lines.Add('      <FileCreate onmatch="include">')
    foreach ($f in $folders) {
        if (-not $includes.Count) { $lines.Add("        <TargetFilename condition=`"begin with`">$(& $escape $f)</TargetFilename>"); continue }
        foreach ($i in $includes) {
            $lines.Add('        <Rule groupRelation="and">')
            $lines.Add("          <TargetFilename condition=`"begin with`">$(& $escape $f)</TargetFilename>")
            $lines.Add("          <TargetFilename condition=`"end with`">$(& $escape $i)</TargetFilename>")
            $lines.Add('        </Rule>')
        }
    }
    $lines.Add('      </FileCreate>')
    $lines.Add('    </RuleGroup>')
    if ($extensions.Count) {
        $lines.Add('    <RuleGroup name="NSP file watch exclusions" groupRelation="or">')
        $lines.Add('      <FileCreate onmatch="exclude">')
        foreach ($x in $extensions) { $lines.Add("        <TargetFilename condition=`"end with`">$(& $escape $x)</TargetFilename>") }
        $lines.Add('      </FileCreate>')
        $lines.Add('    </RuleGroup>')
    }
    if (-not $KeepDefaultEvents) {
        # Event types (other than FileCreate) the schema knows; an empty include rule logs none of them
        $others = @('ProcessCreate', 'FileCreateTime', 'NetworkConnect', 'ProcessTerminate', 'DriverLoad', 'ImageLoad',
            'CreateRemoteThread', 'RawAccessRead', 'ProcessAccess', 'RegistryEvent', 'FileCreateStreamHash', 'PipeEvent',
            'WmiEvent', 'DnsQuery', 'FileDelete', 'ClipboardChange', 'ProcessTampering')
        if ([version]$SchemaVersion -ge [version]'4.90') { $others += @('FileDeleteDetected', 'FileBlockExecutable', 'FileBlockShredding', 'FileExecutableDetected') }
        foreach ($name in $others) {
            $lines.Add("    <RuleGroup name=`"NSP file watch: no $name`" groupRelation=`"or`">")
            $lines.Add("      <$name onmatch=`"include`" />")
            $lines.Add('    </RuleGroup>')
        }
    }
    $lines.Add('  </EventFiltering>')
    $lines.Add('</Sysmon>')
    ($lines -join "`r`n") + "`r`n"
}
