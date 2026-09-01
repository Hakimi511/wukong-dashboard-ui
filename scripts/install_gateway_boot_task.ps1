[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DashboardRoot,
  [string]$UiRoot,
  [Parameter(Mandatory=$true)][string]$SecretFile,
  [Parameter(Mandatory=$true)][string]$Origin,
  [string]$CloudflaredConfig = "$env:USERPROFILE\.cloudflared\config.yml"
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot
$runGateway = Join-Path $scriptRoot 'run_gateway.ps1'
if (-not $UiRoot) { $UiRoot = Join-Path $scriptRoot 'public' }
$cloudflared = Get-Command cloudflared -ErrorAction Stop

# This script is intentionally not run by the source build. It creates two
# stable boot tasks and does not touch the separate daily update task.
$gatewayAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runGateway`" -DashboardRoot `"$DashboardRoot`" -UiRoot `"$UiRoot`" -SecretFile `"$SecretFile`" -Origin `"$Origin`""
$gatewayTrigger = New-ScheduledTaskTrigger -AtStartup
$gatewayPrincipal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType InteractiveToken -RunLevel Limited
Register-ScheduledTask -TaskName 'WukongPrivateDashboardGateway' -Action $gatewayAction -Trigger $gatewayTrigger -Principal $gatewayPrincipal -Force | Out-Null

$tunnelAction = New-ScheduledTaskAction -Execute $cloudflared.Source -Argument "tunnel --config `"$CloudflaredConfig`" run"
$tunnelTrigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'WukongPrivateDashboardTunnel' -Action $tunnelAction -Trigger $tunnelTrigger -Principal $gatewayPrincipal -Force | Out-Null
Write-Output 'Boot tasks registered: WukongPrivateDashboardGateway, WukongPrivateDashboardTunnel'
