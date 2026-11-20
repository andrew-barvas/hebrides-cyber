# Registers a daily Task Scheduler job that runs `hebrides-agent report` as
# SYSTEM. Run as Administrator after `hebrides-agent enrol`.
#
#   .\register-task.ps1 -AgentPath "C:\Program Files\HebridesCyber\hebrides-agent.exe"
param(
  [string]$AgentPath = "$env:ProgramFiles\HebridesCyber\hebrides-agent.exe"
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $AgentPath)) { throw "Agent not found at $AgentPath" }

$action = New-ScheduledTaskAction -Execute $AgentPath -Argument 'report'
# Daily, with a random delay so an office doesn't report all at once.
$trigger = New-ScheduledTaskTrigger -Daily -At 10am -RandomDelay (New-TimeSpan -Hours 4)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RunOnlyIfNetworkAvailable
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'HebridesCyber device report' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Write-Output 'Registered "HebridesCyber device report" (daily, as SYSTEM).'
