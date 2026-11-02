param([string]$SourceRoot)
$ErrorActionPreference='Stop'
if(-not $SourceRoot){$SourceRoot=Split-Path -Parent $PSScriptRoot}
$SourceRoot=(Resolve-Path -LiteralPath $SourceRoot).Path
. (Join-Path $SourceRoot 'Public/New-NSPSysmonFileWatchConfig.ps1')
$checks=0
function Check($condition,$message){if(-not $condition){throw $message};$script:checks++}
$default=[xml](New-NSPSysmonFileWatchConfig -Path 'C:\Synthetic\Input' -IncludeExtension '.pdf')
Check ($default.DocumentElement.Name -eq 'Sysmon') 'Existing full-config default changed.'
Check (@($default.Sysmon.EventFiltering.RuleGroup|Where-Object {$_.ProcessCreate}).Count -gt 0) 'Existing suppression default changed.'
$fragment=[xml](New-NSPSysmonFileWatchConfig -Path 'C:\Synthetic\Input','C:\Synthetic\Other' -IncludeExtension '.pdf' -RuleGroupOnly)
Check ($fragment.DocumentElement.LocalName -eq 'RuleGroup') 'Fragment includes a full Sysmon configuration.'
Check ($fragment.RuleGroup.FileCreate.onmatch -eq 'include') 'Fragment is not additive include rules.'
Check (@($fragment.RuleGroup.FileCreate.Rule).Count -eq 2) 'Folder/extension conjunctions changed.'
Check (@($fragment.RuleGroup.ChildNodes|Where-Object Name -ne 'FileCreate').Count -eq 0) 'Fragment changes unrelated events.'
Check ($fragment.OuterXml -notmatch 'onmatch="exclude"') 'Fragment globally excludes monitoring.'
$failed=$false
try {New-NSPSysmonFileWatchConfig -Path 'C:\Synthetic\Input' -ExcludeExtension '.tmp' -RuleGroupOnly|Out-Null}catch{$failed=$true}
Check $failed 'Global exclusions were allowed in a merge fragment.'
Write-Host ('Passed: {0} Sysmon fragment checks in {1}; text generation only, no Sysmon calls.' -f $checks,$PSVersionTable.PSVersion)
