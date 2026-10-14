# Changelog

## 0.1.0 (unreleased)

- `New-NSPSysmonFileWatchConfig`: file-create rules for folders (trailing-backslash match),
  only some extensions (`-IncludeExtension`), excluded extensions, every other event type off unless `-KeepDefaultEvents`.
- `Install-NSPSysmon` / `Uninstall-NSPSysmon`: install or apply (installed binary for `-c`);
  refuses to replace another configuration without `-Force`.
- `Test-NSPSysmonConfig` / `Get-NSPSysmonStatus`: state and drift from the driver's registry
  values (config file + hash), no elevation needed.
- `Find-NSPSysmon`.
- Extracted from a client file-transfer job that encrypted each file Sysmon saw land in its
  source folder.
