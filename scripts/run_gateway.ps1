[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$DashboardRoot,
  [string]$UiRoot,
  [string]$SecretFile,
  [string]$Origin,
  [switch]$InsecureLocalhost,
  [int]$Port = 8766
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $PSScriptRoot
$gateway = Join-Path $scriptRoot 'gateway\server.py'
if (-not $UiRoot) { $UiRoot = Join-Path $scriptRoot 'public' }
$runtimeCandidates = @(
  'C:\Users\liyil\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',
  'C:\Users\liyil\anaconda3\python.exe'
)
$python = $runtimeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $python) {
  $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
  if (-not $pythonCommand) { throw 'Python runtime not found.' }
  $python = $pythonCommand.Source
}
if ($SecretFile) {
  if (-not (Test-Path -LiteralPath $SecretFile)) { throw 'Encrypted gateway Secret file was not found.' }
  $protectedPayload = (Get-Content -LiteralPath $SecretFile -Raw).Trim()
  $securePayload = ConvertTo-SecureString $protectedPayload
  $payloadPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePayload)
  try {
    $payloadJson = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($payloadPointer)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($payloadPointer)
  }
  $payload = $payloadJson | ConvertFrom-Json
  $env:WUKONG_DASHBOARD_USERS_JSON = [string]$payload.users_json
  $env:WUKONG_SESSION_SECRET = [string]$payload.session_secret
}
if (-not $env:WUKONG_DASHBOARD_USERS_JSON) {
  if (-not $env:WUKONG_DASHBOARD_USERNAME) { $env:WUKONG_DASHBOARD_USERNAME = 'liyilin' }
  if (-not $env:WUKONG_DASHBOARD_PASSWORD_HASH) { throw 'Set WUKONG_DASHBOARD_USERS_JSON, or set WUKONG_DASHBOARD_PASSWORD_HASH for the single-owner setup.' }
}
if (-not $env:WUKONG_SESSION_SECRET) { throw 'WUKONG_SESSION_SECRET is not set.' }

$arguments = @($gateway, '--ui-root', $UiRoot, '--dashboard-root', $DashboardRoot, '--port', $Port)
if ($Origin) { $arguments += @('--origin', $Origin) }
if ($InsecureLocalhost) { $arguments += '--insecure-localhost' }
& $python @arguments
exit $LASTEXITCODE
