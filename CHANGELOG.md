# Changelog

## 0.1.1 (2026-11-02)

- Add RuleGroupOnly to return an include-only file-watch fragment; existing full-config defaults remain unchanged.
- `New-NSPSysmonFileWatchConfig -RuleName`: names each include rule, so a task trigger can select
  only these events by the RuleName field. Rules stay unnamed when it is omitted.
- `Save-NSPSysmon`: downloads Sysmon.zip from Sysinternals on request and keeps the binary only
  when its Authenticode signature is valid and Microsoft Corporation's. It installs nothing.

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
