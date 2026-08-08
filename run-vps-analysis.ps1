param(
  [Parameter(Mandatory = $false, Position = 0)]
  [string]$ApkPath,

  [string]$Host = "169.58.39.50",
  [string]$User = "root",
  [int]$Port = 22,

  [string]$RemoteBase = "/opt/apk-validator",
  [string]$RemoteInput = "/opt/apk-input",
  [string]$RemoteOutput = "/opt/apk-output",

  [ValidateSet("fast", "balanced", "deep")]
  [string]$Profile = "fast",

  [int]$ApktoolTimeoutSec = 300,
  [int]$MaxScanFiles = 3000,
  [int]$ProgressEveryFiles = 500,
  [int]$ApktoolRetryHeapMb = 1536,

  [string]$LocalOutputDir = ".\\vps-reports"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Normalize-InputPath {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
  return $Value.Trim().Trim('"')
}

function Invoke-Native {
  param(
    [string]$Exe,
    [string[]]$Args
  )
  & $Exe @Args
  if ($LASTEXITCODE -ne 0) {
    throw "Fallo ejecutando: $Exe $($Args -join ' ')"
  }
}

$ApkPath = Normalize-InputPath -Value $ApkPath
if ([string]::IsNullOrWhiteSpace($ApkPath)) {
  $ApkPath = Read-Host "Pega o arrastra la ruta del APK"
  $ApkPath = Normalize-InputPath -Value $ApkPath
}
if ([string]::IsNullOrWhiteSpace($ApkPath)) {
  throw "No se recibio ruta de APK."
}
if (-not (Test-Path -LiteralPath $ApkPath)) {
  throw "APK no encontrado: $ApkPath"
}

$apkFileName = [IO.Path]::GetFileName($ApkPath)
$analysisName = ([IO.Path]::GetFileNameWithoutExtension($apkFileName) + "-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$remoteApkPath = "$RemoteInput/$apkFileName"
$remoteOutDir = "$RemoteOutput/$analysisName"

$localOutRoot = Resolve-Path -LiteralPath "."
$localOutDir = Join-Path $localOutRoot $LocalOutputDir
if (-not (Test-Path -LiteralPath $localOutDir)) {
  New-Item -ItemType Directory -Path $localOutDir -Force | Out-Null
}
$localRunDir = Join-Path $localOutDir $analysisName
if (-not (Test-Path -LiteralPath $localRunDir)) {
  New-Item -ItemType Directory -Path $localRunDir -Force | Out-Null
}

$sshTarget = "$User@$Host"

"[1/5] Preparando VPS..."
$prepCmd = "mkdir -p $RemoteBase $RemoteInput $RemoteOutput"
Invoke-Native -Exe "ssh" -Args @("-p", "$Port", $sshTarget, $prepCmd)

"[2/5] Subiendo script y APK..."
Invoke-Native -Exe "scp" -Args @("-P", "$Port", (Join-Path $PSScriptRoot "apk-definitive-validator.ps1"), "$sshTarget`:$RemoteBase/")
Invoke-Native -Exe "scp" -Args @("-P", "$Port", $ApkPath, "$sshTarget`:$RemoteApkPath")

"[3/5] Ejecutando analisis remoto ($Profile)..."
$runCmd = @(
  "pwsh -NoLogo -NoProfile -File $RemoteBase/apk-definitive-validator.ps1",
  "-ApkPath $remoteApkPath",
  "-Profile $Profile",
  "-ApktoolTimeoutSec $ApktoolTimeoutSec",
  "-MaxScanFiles $MaxScanFiles",
  "-ProgressEveryFiles $ProgressEveryFiles",
  "-ApktoolRetryHeapMb $ApktoolRetryHeapMb",
  "-OutDir $remoteOutDir"
) -join " "
Invoke-Native -Exe "ssh" -Args @("-p", "$Port", $sshTarget, $runCmd)

"[4/5] Descargando reportes..."
Invoke-Native -Exe "scp" -Args @("-P", "$Port", "$sshTarget`:$remoteOutDir/report.txt", "$localRunDir/report.txt")
Invoke-Native -Exe "scp" -Args @("-P", "$Port", "$sshTarget`:$remoteOutDir/report.json", "$localRunDir/report.json")

"[5/5] Limpieza remota de temporales de ejecucion..."
$cleanupCmd = "rm -rf /tmp/apk_def_validator_*"
Invoke-Native -Exe "ssh" -Args @("-p", "$Port", $sshTarget, $cleanupCmd)

""
"Listo."
"Reporte local: $localRunDir/report.txt"
"JSON local:    $localRunDir/report.json"
