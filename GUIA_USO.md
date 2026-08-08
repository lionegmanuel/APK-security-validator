# APK Security Validator - Guia de uso

## 1) Que es

`apk-definitive-validator.ps1` analiza un APK con enfoque de riesgo y genera:

- `report.json` (detalle tecnico completo)
- `report.txt` (resumen legible)

No garantiza 0 malware, pero da una evaluacion tecnica robusta para decidir instalacion en entorno aislado.

## 2) Requisitos

Ya instalados en tu maquina:

- `apktool`
- `aapt`
- `apksigner`
- `java` (JRE/JDK 17)

Validar rapido:

```powershell
apktool -version
aapt v
apksigner --version
java -version
```

## 3) Ubicacion

- Script: `D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1`
- Carpeta de salida por defecto: `./apk-validator-output` (relativa al directorio desde donde ejecutes)

## 4) Uso basico

Desde PowerShell:

```powershell
& "D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1" -ApkPath "D:\ruta\app.apk"
```

Con carpeta de salida personalizada:

```powershell
& "D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1" -ApkPath "D:\ruta\app.apk" -OutDir "D:\ruta\salida"
```

## 5) VirusTotal (opcional)

El script consulta VT por hash (no sube archivo) solo si activas el flag.

Recomendado: usar variable de entorno para no exponer la clave en historial:

```powershell
$env:VT_API_KEY = "TU_API_KEY"
& "D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1" -ApkPath "D:\ruta\app.apk" -EnableVirusTotal -VirusTotalApiKey $env:VT_API_KEY
```

## 6) Parametros disponibles

- `-ApkPath` (obligatorio): ruta al APK.
- `-OutDir`: carpeta donde guardar reportes.
- `-EnableVirusTotal`: habilita consulta VT por hash.
- `-VirusTotalApiKey`: clave API de VT.
- `-KeepArtifacts`: guarda carpeta `decoded` para revision manual.
- `-MaxStringSamplesPerRule`: limite de evidencias por regla (default 25).

## 7) Interpretacion rapida de resultados

- `LOW_RISK`: sin senales criticas en estatico.
- `MEDIUM_RISK`: hay indicadores a revisar antes de instalar.
- `HIGH_RISK`: multiples indicadores serios.
- `CRITICAL_RISK`: no instalar en dispositivos reales.

Siempre revisa `topFindings` y `conclusions` en `report.json`.

## 8) Flujo recomendado para tesis

1. Analisis estatico con este script.
2. Si sale `MEDIUM/HIGH/CRITICAL`, ejecutar solo en emulador aislado.
3. Monitorear trafico saliente y comportamiento runtime.
4. Registrar evidencia y decision final en tu matriz de riesgo.

## 9) Sincronizacion segura entre PCs

- Podes subir el script y esta guia a Git sin problema.
- Evita subir APKs analizados y reportes sensibles si contienen IOCs o rutas privadas.
- No subas API keys; usa variables de entorno o archivo local ignorado por Git.

## 10) Ejecucion en VPS

Si queres ejecutar el analizador en servidor (para no consumir RAM/CPU de tu PC), revisa:

- `GUIA_VPS.md`

Incluye instalacion en Ubuntu, subida de APK, ejecucion remota y descarga de reportes.
