param(
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$ApkPath,

  [string]$OutDir = ".\\apk-validator-output",
  [int]$ApktoolTimeoutSec = 900,
  [int]$MaxStringSamplesPerRule = 25,
  [int]$MaxScanFiles = 15000,
  [int]$ProgressEveryFiles = 500,
  [ValidateSet("balanced", "fast", "deep")]
  [string]$Profile = "fast",
  [int]$ApktoolRetryHeapMb = 1536,

  [switch]$EnableVirusTotal,
  [string]$VirusTotalApiKey = "",
  [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Add-PathEntryForSession {
  param([string]$Entry)
  if ([string]::IsNullOrWhiteSpace($Entry)) { return }
  if (-not (Test-Path -LiteralPath $Entry)) { return }
  $parts = @($env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if (-not ($parts -contains $Entry)) {
    $env:Path = $Entry + ';' + $env:Path
  }
}

function Normalize-ApkPath {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
  return $Value.Trim().Trim('"')
}

$ApkPath = Normalize-ApkPath -Value $ApkPath

if ([string]::IsNullOrWhiteSpace($ApkPath)) {
  $ApkPath = Read-Host "Pega o arrastra la ruta del APK"
  $ApkPath = Normalize-ApkPath -Value $ApkPath
}

if ([string]::IsNullOrWhiteSpace($ApkPath)) {
  throw "No se recibio ruta de APK."
}

if (-not (Test-Path -LiteralPath $ApkPath)) {
  throw "APK no encontrado: $ApkPath"
}

$scriptPath = Join-Path $PSScriptRoot "apk-definitive-validator.ps1"
if (-not (Test-Path -LiteralPath $scriptPath)) {
  throw "No se encontro script principal: $scriptPath"
}

if ([string]::IsNullOrWhiteSpace($env:ANDROID_SDK_ROOT) -and (Test-Path -LiteralPath "D:\Android")) {
  $env:ANDROID_SDK_ROOT = "D:\Android"
}
Add-PathEntryForSession -Entry "D:\Android\build-tools\36.0.0"
Add-PathEntryForSession -Entry "D:\Android\platform-tools"
Add-PathEntryForSession -Entry "D:\Tools\apktool"

$params = @{
  ApkPath = $ApkPath
  OutDir = $OutDir
  ApktoolTimeoutSec = $ApktoolTimeoutSec
  MaxStringSamplesPerRule = $MaxStringSamplesPerRule
  MaxScanFiles = $MaxScanFiles
  ProgressEveryFiles = $ProgressEveryFiles
  Profile = $Profile
  ApktoolRetryHeapMb = $ApktoolRetryHeapMb
}

if ($EnableVirusTotal) {
  $params.EnableVirusTotal = $true
  if (-not [string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
    $params.VirusTotalApiKey = $VirusTotalApiKey
  }
}
if ($KeepArtifacts) {
  $params.KeepArtifacts = $true
}

& $scriptPath @params
