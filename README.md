# NSP.Win.Sysmon

Sysmon as a **file watch**: log an event when a file lands in a folder, so a scheduled task can
run a job on it (Sysmon event ID 11, picked up by `New-NSPEventTaskTrigger` in
NSP.Win.ScheduledTask). Windows PowerShell **5.1** compatible (and 7+); imports on a bare host.
Part of the `NSP.Win.*` family.

| Function | Purpose |
|---|---|
| `New-NSPSysmonFileWatchConfig` | The configuration as text: file creates under the given folders (optionally only some extensions, `-IncludeExtension`), minus extensions the job writes itself - and, unless `-KeepDefaultEvents`, nothing else (Sysmon otherwise logs every process start). |
| `Install-NSPSysmon` | Write the configuration and install Sysmon with it, or apply it to the installed Sysmon. Stops rather than replace a configuration it didn't write, unless `-Force`. |
| `Test-NSPSysmonConfig` | Installed, running, loaded **this** file with **this** content: `InSync` and one line per problem. No elevation needed. |
| `Get-NSPSysmonStatus` | Installed / running / version / which config file and hash it loaded (`-IncludeRules`, elevated, lists the loaded rules). |
| `Uninstall-NSPSysmon` | Remove Sysmon (computer-wide). |
| `Find-NSPSysmon` | Locate the Sysmon binary (a file or folder you give, `NSP_SYSMON`, the installed copy, PATH). |

```powershell
Import-Module NSP.Win.Sysmon
$xml = New-NSPSysmonFileWatchConfig -Path 'D:\Jobs\Outbound' -ExcludeExtension '.pgp'
$cfg = 'D:\Jobs\Sysmon.xml'

Test-NSPSysmonConfig -ConfigPath $cfg -Configuration $xml        # what's wrong, if anything
Install-NSPSysmon -SysmonPath 'D:\Jobs\SetupFiles' -ConfigPath $cfg -Configuration $xml   # elevated
```

## One configuration per computer

Sysmon loads a single configuration for the whole computer. If it's already installed with
someone else's configuration (security monitoring, say), applying a file watch replaces it, so
`Install-NSPSysmon` stops and says so; merge the file-watch rules into that configuration instead,
or pass `-Force`. Each folder matches "begin with" the folder **plus a backslash**, so `D:\Drop`
doesn't also match `D:\Dropbox`.

## Checking without elevation

`sysmon -c` needs an elevated session, but the driver records the configuration file it loaded and
its SHA256 in the registry (`...\Services\SysmonDrv\Parameters`, `ConfigFile` / `ConfigHash`),
which anyone can read. `Test-NSPSysmonConfig` compares those with the expected text, written the
way `Install-NSPSysmon` writes it (UTF-8, CRLF), so a check from a non-admin session is exact.

## Tests

```powershell
.\tools\Test-Repo.ps1
$env:NSP_SYSMON_EXE = 'C:\Tools\Sysmon64.exe'   # optional: check the config against that binary's schema
```

Pester 5+. Sysmon is never installed or changed: the service, registry reader, and Sysmon runner
are mocked.
