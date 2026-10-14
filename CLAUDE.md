# CLAUDE.md

## What this is

`NSP.Win.Sysmon`: Sysmon as a file watch (config builder, install/apply, drift check). Part of the
`NSP.Win.*` family; the event-11 task trigger lives in NSP.Win.ScheduledTask. First consumer: a
client file-transfer job that encrypts each file landing in its source folder.

## Hard rules

- Windows PowerShell 5.1 is the floor; imports on a bare host (no RequiredModules).
- Sysmon has one configuration per computer: never replace a configuration file other than the
  caller's without `-Force`.
- Install writes and Test hashes the same bytes (`ConvertTo-NSPSysmonConfigBytes`: UTF-8 no BOM,
  CRLF). Change one, change both.
- Status and Test need no elevation (registry only). Only Install, Uninstall, and
  `-IncludeRules` run Sysmon.
- Tests never touch the real Sysmon: mock `Get-Service`, `Get-NSPSysmonRegistry`,
  `Invoke-NSPSysmonExe`. `sysmon -s` (schema, no elevation) is fine behind `NSP_SYSMON_EXE`.
- One function per file in `Public\`. `FunctionsToExport` matches `Public\`. Exported functions
  need `.SYNOPSIS` and `.EXAMPLE`. CRLF, no BOM, ASCII only. Small (patch-level) version bumps.

## Testing

Pester 5+. Run `.\tools\Test-Repo.ps1`, and Pester under `powershell.exe` (5.1) too.

## Publishing (not adopted yet - do this on next use)

This repo isn't on the shared NSP release routine yet. Before its next release, adopt it the way
the published toolkit repos have (NSP-Console, NSP-Toolkit, NSP-ActiveDirectory, NSP-Bootstrap):

- Add `tools\Publish-ToGallery.ps1`: the same thin wrapper those repos carry, which imports
  NSP.RepoTools and runs `Publish-NSPModule` on this repo. Copy it as-is; all the logic stays in
  NSP.RepoTools.
- Dry run first: `.\tools\Publish-ToGallery.ps1 -WhatIf` runs every check (manifest, changelog,
  clean tree, Gallery version, client references across history, `tools\Test-Repo.ps1`, staged
  5.1 import) and publishes nothing.
- At release, change the CHANGELOG heading from `## <version> (unreleased)` to `## <version>`;
  the routine refuses an unreleased heading.
- Needs a GitHub remote first if the repo has none (the manifest's ProjectUri should point at it).