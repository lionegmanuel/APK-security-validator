param(
  [Parameter(Mandatory = $true)]
  [string]$ApkPath,

  [string]$OutDir = ".\\apk-validator-output",
  [string]$VirusTotalApiKey = "",
  [switch]$EnableVirusTotal,
  [switch]$KeepArtifacts,
  [int]$MaxStringSamplesPerRule = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Collection {
  return New-Object System.Collections.Generic.List[object]
}

function Add-Finding {
  param(
    [string]$Type,
    [string]$Severity,
    [string]$Message,
    [double]$Weight,
    [object]$Evidence = $null
  )

  $script:Findings.Add([PSCustomObject]@{
      type = $Type
      severity = $Severity
      weight = $Weight
      message = $Message
      evidence = $Evidence
    }) | Out-Null

  $script:RiskScore += $Weight
}

function Get-ToolPath {
  param([string]$Name)
  $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $cmd) { return $null }
  return $cmd.Source
}

function Ensure-Directory {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Parse-AaptPermissions {
  param([string[]]$BadgingOutput)
  $items = New-Object System.Collections.Generic.HashSet[string]
  foreach ($line in $BadgingOutput) {
    if ($line -match "^uses-permission(?:-sdk-23)?:\s+name='([^']+)'") {
      [void]$items.Add($Matches[1])
    }
  }
  return @($items)
}

function Parse-AaptPackageInfo {
  param([string[]]$BadgingOutput)
  $package = ""
  $versionName = ""
  $versionCode = ""
  foreach ($line in $BadgingOutput) {
    if ($line -match "^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'") {
      $package = $Matches[1]
      $versionCode = $Matches[2]
      $versionName = $Matches[3]
      break
    }
  }
  return [PSCustomObject]@{ package = $package; versionCode = $versionCode; versionName = $versionName }
}

function Collect-Files {
  param([string]$Root, [string[]]$Extensions)
  $set = New-Object System.Collections.Generic.HashSet[string]
  foreach ($ext in $Extensions) {
    $files = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter ("*" + $ext) -ErrorAction SilentlyContinue
    foreach ($f in $files) { [void]$set.Add($f.FullName) }
  }
  return @($set)
}

function Select-RuleEvidence {
  param(
    [System.Collections.Generic.List[object]]$Matches,
    [int]$MaxItems
  )
  $result = New-Collection
  $count = 0
  foreach ($m in $Matches) {
    $result.Add([PSCustomObject]@{ file = $m.Path; line = $m.LineNumber; text = ($m.Line.Trim()) }) | Out-Null
    $count++
    if ($count -ge $MaxItems) { break }
  }
  return @($result)
}

function Get-RuleMatches {
  param(
    [string[]]$Paths,
    [string]$Pattern
  )

  if ($null -eq $Paths -or $Paths.Count -eq 0) { return @() }
  $hits = Select-String -Path $Paths -Pattern $Pattern -CaseSensitive:$false -ErrorAction SilentlyContinue
  if ($null -eq $hits) { return @() }
  return @($hits)
}

function Query-VirusTotalByHash {
  param([string]$Sha256, [string]$ApiKey)
  $headers = @{ "x-apikey" = $ApiKey }
  $url = "https://www.virustotal.com/api/v3/files/$Sha256"
  return Invoke-RestMethod -Method Get -Uri $url -Headers $headers -TimeoutSec 45
}

if (-not (Test-Path -LiteralPath $ApkPath)) {
  throw "APK no encontrado: $ApkPath"
}

$ApkPath = (Resolve-Path -LiteralPath $ApkPath).Path
$OutDir = (Resolve-Path -LiteralPath ".").Path + [IO.Path]::DirectorySeparatorChar + ($OutDir.TrimStart('.','\\','/'))
Ensure-Directory -Path $OutDir

$script:Findings = New-Collection
$script:RiskScore = 0.0
$analysisStarted = Get-Date

$tools = [PSCustomObject]@{
  apksigner = Get-ToolPath "apksigner"
  aapt = Get-ToolPath "aapt"
  apktool = Get-ToolPath "apktool"
}

if (-not $tools.apksigner) { Add-Finding -Type "tooling" -Severity "high" -Weight 35 -Message "Falta apksigner. Sin validacion criptografica completa." }
if (-not $tools.aapt) { Add-Finding -Type "tooling" -Severity "high" -Weight 35 -Message "Falta aapt. Sin analisis de permisos/package." }
if (-not $tools.apktool) { Add-Finding -Type "tooling" -Severity "high" -Weight 45 -Message "Falta apktool. Sin decompilacion para IOC." }

# 1) Hash
$hash = Get-FileHash -LiteralPath $ApkPath -Algorithm SHA256
$sha256 = $hash.Hash

# 2) Firma y certificados
$signatureSummary = [PSCustomObject]@{
  verifies = $false
  signerDn = ""
  certSha256 = @()
  raw = @()
}

if ($tools.apksigner) {
  $signOut = & $tools.apksigner verify --verbose --print-certs "$ApkPath" 2>&1
  $signatureSummary.raw = @($signOut)
  $signText = ($signOut | Out-String)

  if ($signText -match "Verified using") {
    $signatureSummary.verifies = $true
    Add-Finding -Type "signature" -Severity "low" -Weight 1 -Message "Firma valida con apksigner."
  } else {
    Add-Finding -Type "signature" -Severity "high" -Weight 55 -Message "Firma invalida o APK no verificable."
  }

  $dnLine = $signOut | Where-Object { $_ -match "Signer #1 certificate DN:" } | Select-Object -First 1
  if ($dnLine) { $signatureSummary.signerDn = (($dnLine -replace ".*DN:\s*", "").Trim()) }

  $digestLines = $signOut | Where-Object { $_ -match "Signer #\d+ certificate SHA-256 digest:" }
  $digests = New-Object System.Collections.Generic.List[string]
  foreach ($d in $digestLines) {
    $digests.Add((($d -replace ".*digest:\s*", "").Trim())) | Out-Null
  }
  $signatureSummary.certSha256 = @($digests)
}

# 3) Package + permisos + componentes exportados
$packageInfo = [PSCustomObject]@{ package = ""; versionCode = ""; versionName = "" }
$permissions = @()

if ($tools.aapt) {
  $badging = & $tools.aapt dump badging "$ApkPath" 2>&1
  $packageInfo = Parse-AaptPackageInfo -BadgingOutput $badging
  $permissions = Parse-AaptPermissions -BadgingOutput $badging

  $highRiskPerms = @(
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE"
  )

  $permHits = @($permissions | Where-Object { $highRiskPerms -contains $_ })
  if ($permHits.Count -ge 8) {
    Add-Finding -Type "permissions" -Severity "high" -Weight 35 -Message "Muchos permisos sensibles detectados." -Evidence $permHits
  } elseif ($permHits.Count -ge 4) {
    Add-Finding -Type "permissions" -Severity "medium" -Weight 20 -Message "Permisos sensibles moderados detectados." -Evidence $permHits
  } elseif ($permHits.Count -ge 1) {
    Add-Finding -Type "permissions" -Severity "low" -Weight 8 -Message "Permisos sensibles presentes." -Evidence $permHits
  }
}

# 4) Decompilacion + IOC rules
$tempRoot = Join-Path $env:TEMP ("apk_def_validator_" + [Guid]::NewGuid().ToString("N"))
Ensure-Directory -Path $tempRoot
$decodedPath = Join-Path $tempRoot "decoded"

$ruleHitSummary = @()
$suspiciousDomains = @()

try {
  if ($tools.apktool) {
    & $tools.apktool d -f "$ApkPath" -o "$decodedPath" | Out-Null

    $scanFiles = Collect-Files -Root $decodedPath -Extensions @(".smali", ".xml", ".json", ".txt", ".html", ".js", ".kt", ".java", ".properties")

    $rules = @(
      @{ id = "dynamic_loader"; regex = "DexClassLoader|PathClassLoader|InMemoryDexClassLoader"; severity = "high"; weight = 26; msg = "Carga dinamica de codigo detectada." },
      @{ id = "cmd_exec"; regex = "Runtime\.getRuntime\(\)\.exec|ProcessBuilder\("; severity = "high"; weight = 30; msg = "Ejecucion de comandos detectada." },
      @{ id = "root_evasion"; regex = "\/system\/bin\/su|magisk|frida|xposed|substrate"; severity = "medium"; weight = 16; msg = "Indicadores de anti-analisis/root hooking." },
      @{ id = "network_cleartext"; regex = "http:\/\/"; severity = "medium"; weight = 12; msg = "Endpoints en texto plano (HTTP) detectados." },
      @{ id = "exfil_channels"; regex = "api\.telegram\.org|discord(app)?\.com\/api\/webhooks|pastebin\.com|ngrok\.io|raw\.githubusercontent\.com|bit\.ly|tinyurl\.com"; severity = "high"; weight = 28; msg = "Canales de exfiltracion/C2 potenciales detectados." },
      @{ id = "crypto_weak"; regex = "AES\/ECB|DES\/ECB|MD5|SHA1"; severity = "medium"; weight = 10; msg = "Primitivas criptograficas debiles detectadas." },
      @{ id = "webview_jsbridge"; regex = "addJavascriptInterface|setJavaScriptEnabled\(true\)"; severity = "medium"; weight = 12; msg = "Superficie WebView riesgosa detectada." },
      @{ id = "install_dropper"; regex = "REQUEST_INSTALL_PACKAGES|PackageInstaller|ACTION_INSTALL_PACKAGE|FileProvider"; severity = "high"; weight = 24; msg = "Comportamiento tipo dropper/instalador detectado." }
    )

    foreach ($rule in $rules) {
      $matches = @(Get-RuleMatches -Paths $scanFiles -Pattern $rule.regex)
      if ($matches.Count -gt 0) {
        $effectiveWeight = [Math]::Min([double]$rule.weight + ([Math]::Log10($matches.Count + 1) * 4.0), [double]$rule.weight * 1.8)
        $evidence = Select-RuleEvidence -Matches $matches -MaxItems $MaxStringSamplesPerRule
        Add-Finding -Type "ioc:$($rule.id)" -Severity $rule.severity -Weight $effectiveWeight -Message $rule.msg -Evidence $evidence
        $ruleHitSummary += [PSCustomObject]@{ id = $rule.id; count = $matches.Count; weight = [Math]::Round($effectiveWeight, 2) }
      }
    }

    # Dominios embebidos
    $domainRegex = "\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|live|shop|click|info|biz|app|dev)\b"
    $domainMatches = New-Object System.Collections.Generic.HashSet[string]
    $domainHits = @(Get-RuleMatches -Paths $scanFiles -Pattern $domainRegex)
    foreach ($h in $domainHits) {
      foreach ($m in [regex]::Matches($h.Line, $domainRegex, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        [void]$domainMatches.Add($m.Value.ToLowerInvariant())
      }
    }
    $suspiciousTld = @($domainMatches | Where-Object { $_ -match "\.(ru|cn|top|xyz|click)$" })
    $suspiciousDomains = $suspiciousTld
    if ($suspiciousTld.Count -ge 3) {
      Add-Finding -Type "domain_intel" -Severity "high" -Weight 20 -Message "Multiples dominios con TLD de alto riesgo." -Evidence $suspiciousTld
    } elseif ($suspiciousTld.Count -ge 1) {
      Add-Finding -Type "domain_intel" -Severity "medium" -Weight 10 -Message "Se detectaron dominios con TLD de alto riesgo." -Evidence $suspiciousTld
    }

    # Ofuscacion heuristica
    $smaliFiles = Get-ChildItem -LiteralPath $decodedPath -Recurse -File -Filter "*.smali" -ErrorAction SilentlyContinue
    $shortClassNames = 0
    $classCount = 0
    foreach ($sf in $smaliFiles) {
      $classCount++
      if ($sf.BaseName -match "^[a-zA-Z]{1,2}$") { $shortClassNames++ }
    }
    if ($classCount -gt 0) {
      $obfRatio = [Math]::Round(($shortClassNames / [double]$classCount) * 100.0, 2)
      if ($obfRatio -ge 35) {
        Add-Finding -Type "obfuscation" -Severity "medium" -Weight 14 -Message "Ofuscacion alta por nombres de clase cortos ($obfRatio%)."
      } elseif ($obfRatio -ge 15) {
        Add-Finding -Type "obfuscation" -Severity "low" -Weight 6 -Message "Ofuscacion moderada ($obfRatio%)."
      }
    }
  }
}
finally {
  if ($KeepArtifacts) {
    $persistDecoded = Join-Path $OutDir "decoded"
    if (Test-Path -LiteralPath $persistDecoded) {
      Remove-Item -LiteralPath $persistDecoded -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $decodedPath) {
      Copy-Item -LiteralPath $decodedPath -Destination $persistDecoded -Recurse -Force
    }
  }

  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# 5) VirusTotal hash lookup (opcional)
$vtSummary = $null
if ($EnableVirusTotal) {
  if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) {
    Add-Finding -Type "virustotal" -Severity "medium" -Weight 8 -Message "EnableVirusTotal activo pero sin API key."
  }
  else {
    try {
      $vtResp = Query-VirusTotalByHash -Sha256 $sha256 -ApiKey $VirusTotalApiKey
      $stats = $vtResp.data.attributes.last_analysis_stats
      $mal = [int]$stats.malicious
      $sus = [int]$stats.suspicious
      $undet = [int]$stats.undetected

      if ($mal -ge 5 -or $sus -ge 5) {
        Add-Finding -Type "virustotal" -Severity "high" -Weight 55 -Message "VT reporta detecciones altas (malicious=$mal, suspicious=$sus)."
      }
      elseif ($mal -ge 1 -or $sus -ge 1) {
        Add-Finding -Type "virustotal" -Severity "medium" -Weight 26 -Message "VT reporta detecciones parciales (malicious=$mal, suspicious=$sus)."
      }
      else {
        Add-Finding -Type "virustotal" -Severity "low" -Weight 0.5 -Message "VT sin detecciones relevantes."
      }

      $vtSummary = [PSCustomObject]@{
        malicious = $mal
        suspicious = $sus
        harmless = [int]$stats.harmless
        undetected = $undet
        timeout = [int]$stats.timeout
      }
    }
    catch {
      Add-Finding -Type "virustotal" -Severity "medium" -Weight 10 -Message "Error consultando VT: $($_.Exception.Message)"
    }
  }
}

# 6) Score y conclusiones
$riskRounded = [Math]::Round($RiskScore, 2)
$verdict = "LOW_RISK"
$confidence = "MEDIUM"

if ($riskRounded -ge 130) {
  $verdict = "CRITICAL_RISK"
  $confidence = "HIGH"
}
elseif ($riskRounded -ge 85) {
  $verdict = "HIGH_RISK"
  $confidence = "HIGH"
}
elseif ($riskRounded -ge 45) {
  $verdict = "MEDIUM_RISK"
  $confidence = "MEDIUM"
}
else {
  $verdict = "LOW_RISK"
  $confidence = "LOW"
}

$topFindings = $Findings | Sort-Object -Property weight -Descending | Select-Object -First 8
$conclusions = New-Collection

if ($verdict -eq "CRITICAL_RISK" -or $verdict -eq "HIGH_RISK") {
  $conclusions.Add("No instalar en dispositivo con datos reales ni cuentas personales.") | Out-Null
  $conclusions.Add("Solo ejecutar en emulador aislado sin credenciales y con trafico monitorizado.") | Out-Null
}
if ($Findings.Where({ $_.type -eq "signature" -and $_.severity -eq "high" }).Count -gt 0) {
  $conclusions.Add("La integridad/firma es inconsistente: riesgo alto de tampering.") | Out-Null
}
if ($Findings.Where({ $_.type -like "ioc:*" -and $_.severity -eq "high" }).Count -gt 0) {
  $conclusions.Add("Hay indicadores tecnicos de comportamiento potencialmente malicioso.") | Out-Null
}
if ($conclusions.Count -eq 0) {
  $conclusions.Add("No se detectaron señales criticas en este analisis estatico, pero no garantiza ausencia total de malware.") | Out-Null
}

$report = [PSCustomObject]@{
  metadata = [PSCustomObject]@{
    analyzer = "apk-definitive-validator"
    version = "1.0.0"
    analyzedAt = (Get-Date).ToString("s")
    elapsedSeconds = [Math]::Round(((Get-Date) - $analysisStarted).TotalSeconds, 2)
  }
  input = [PSCustomObject]@{
    apkPath = $ApkPath
    sha256 = $sha256
    package = $packageInfo.package
    versionCode = $packageInfo.versionCode
    versionName = $packageInfo.versionName
  }
  tooling = $tools
  signature = $signatureSummary
  permissions = $permissions
  suspiciousDomains = $suspiciousDomains
  ruleHits = $ruleHitSummary
  virustotal = $vtSummary
  scoring = [PSCustomObject]@{
    riskScore = $riskRounded
    verdict = $verdict
    confidence = $confidence
  }
  findings = $Findings
  topFindings = $topFindings
  conclusions = @($conclusions)
}

$jsonPath = Join-Path $OutDir "report.json"
$txtPath = Join-Path $OutDir "report.txt"

$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$lines = New-Collection
$lines.Add("APK Definitive Validator Report") | Out-Null
$lines.Add("Generated: $((Get-Date).ToString('s'))") | Out-Null
$lines.Add("APK: $ApkPath") | Out-Null
$lines.Add("SHA256: $sha256") | Out-Null
$lines.Add("Package: $($packageInfo.package) v$($packageInfo.versionName) ($($packageInfo.versionCode))") | Out-Null
$lines.Add("Risk Score: $riskRounded") | Out-Null
$lines.Add("Verdict: $verdict") | Out-Null
$lines.Add("Confidence: $confidence") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("Top Findings:") | Out-Null
foreach ($f in $topFindings) {
  $lines.Add("- [$($f.severity)] ($([Math]::Round([double]$f.weight,2))) $($f.type): $($f.message)") | Out-Null
}
$lines.Add("") | Out-Null
$lines.Add("Conclusions:") | Out-Null
foreach ($c in $conclusions) {
  $lines.Add("- $c") | Out-Null
}

Set-Content -LiteralPath $txtPath -Value $lines -Encoding UTF8

"Done"
"Report JSON: $jsonPath"
"Report TXT:  $txtPath"
"Risk Score:  $riskRounded"
"Verdict:     $verdict"
