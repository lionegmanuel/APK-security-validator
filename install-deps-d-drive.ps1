param(
  [string]$AndroidRoot = "D:\Android",
  [string]$ToolsRoot = "D:\Tools",
  [string]$BuildToolsVersion = "36.0.0",
  [switch]$AutoAcceptLicenses
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-Directory {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Add-PathEntryForUser {
  param([string]$Entry)
  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  if ([string]::IsNullOrWhiteSpace($current)) {
    [Environment]::SetEnvironmentVariable("Path", $Entry, "User")
    return
  }
  $parts = @($current -split ";" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if (-not ($parts -contains $Entry)) {
    $parts += $Entry
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
  }
}

Write-Host "[1/7] Creando estructura base en D:"
Ensure-Directory -Path $AndroidRoot
Ensure-Directory -Path $ToolsRoot
$apktoolRoot = Join-Path $ToolsRoot "apktool"
Ensure-Directory -Path $apktoolRoot

$tempRoot = Join-Path $env:TEMP "apk-validator-setup"
Ensure-Directory -Path $tempRoot

Write-Host "[2/7] Descargando Android command-line tools"
$cmdlineZip = Join-Path $tempRoot "commandlinetools-win-latest.zip"
Invoke-WebRequest -Uri "https://dl.google.com/android/repository/commandlinetools-win-13114758_latest.zip" -OutFile $cmdlineZip

Write-Host "[3/7] Instalando Android command-line tools"
$extractDir = Join-Path $tempRoot "android-cmdline-tools"
if (Test-Path -LiteralPath $extractDir) {
  Remove-Item -LiteralPath $extractDir -Recurse -Force
}
Expand-Archive -LiteralPath $cmdlineZip -DestinationPath $extractDir -Force

$cmdlineLatest = Join-Path $AndroidRoot "cmdline-tools\latest"
if (Test-Path -LiteralPath $cmdlineLatest) {
  Remove-Item -LiteralPath $cmdlineLatest -Recurse -Force
}
Ensure-Directory -Path $cmdlineLatest
Copy-Item -Path (Join-Path $extractDir "cmdline-tools\*") -Destination $cmdlineLatest -Recurse -Force

$sdkManager = Join-Path $cmdlineLatest "bin\sdkmanager.bat"

if ($AutoAcceptLicenses) {
  Write-Host "[4/7] Aceptando licencias Android SDK automaticamente"
  @("y") * 250 | & $sdkManager --sdk_root=$AndroidRoot --licenses | Out-Null
}
else {
  Write-Host "[4/7] Licencias Android SDK (interactivo)"
  & $sdkManager --sdk_root=$AndroidRoot --licenses
}

Write-Host "[5/7] Instalando platform-tools y build-tools"
& $sdkManager --sdk_root=$AndroidRoot "platform-tools" "build-tools;$BuildToolsVersion"

Write-Host "[6/7] Instalando apktool"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat" -OutFile (Join-Path $apktoolRoot "apktool.bat")
Invoke-WebRequest -Uri "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.11.1.jar" -OutFile (Join-Path $apktoolRoot "apktool.jar")

# Evita pausa cuando se ejecuta desde wrappers /c.
$apktoolBat = Join-Path $apktoolRoot "apktool.bat"
$content = Get-Content -LiteralPath $apktoolBat
$filtered = @($content | Where-Object { $_ -notmatch "pause\s*&\s*exit\s*/b" })
Set-Content -LiteralPath $apktoolBat -Value $filtered -Encoding ASCII

Write-Host "[7/7] Persistiendo variables de entorno del usuario"
[Environment]::SetEnvironmentVariable("ANDROID_SDK_ROOT", $AndroidRoot, "User")
Add-PathEntryForUser -Entry (Join-Path $AndroidRoot "build-tools\$BuildToolsVersion")
Add-PathEntryForUser -Entry (Join-Path $AndroidRoot "platform-tools")
Add-PathEntryForUser -Entry $apktoolRoot

Write-Host ""
Write-Host "Instalacion completada. Cerra y reabrí la terminal para refrescar PATH."
Write-Host "Validacion sugerida:"
Write-Host "  apktool -version"
Write-Host "  aapt v"
Write-Host "  apksigner --version"
Write-Host "  java -version"
