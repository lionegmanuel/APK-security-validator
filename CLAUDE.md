# CLAUDE.md — APK Security Validator

## 0) Reglas Core (eficiencia)

### 1. Contexto y lectura
- Antes de editar, ubicar archivos con `Glob`/`Grep` y leer solo lo necesario (`Read` con `offset/limit`).
- Si la ruta exacta es conocida, leer directo sin cadenas largas de búsqueda.
- No releer archivos ya inspeccionados salvo que hayan cambiado.
- Paralelizar tool calls independientes.

### 2. Edición de código
- Priorizar cambios mínimos y locales.
- Mantener estilo existente del repo (PowerShell claro, nombres explícitos, reportes trazables).
- Evitar dependencias nuevas sin justificación.

### 3. Comunicación
- Responder corto y accionable, sin relleno.
- No copiar bloques grandes de código en el chat si ya fueron escritos en archivos.

### 4. Validación
- Después de cambios en script, ejecutar al menos: carga de parámetros (`-?`) y un caso controlado (por ejemplo APK inexistente para validar manejo de errores).
- No declarar éxito sin evidencia de consola.

### 5. UPDATES.md
- Revisar `UPDATES.md` al iniciar una sesión nueva de este proyecto.
- Solo escribir/actualizar `UPDATES.md` cuando el usuario lo pida explícitamente.
- Retención por días: conservar solo las últimas 3 secciones de día.

---

## 1) Qué es este proyecto

`APK-Security-Validator` es un proyecto de análisis técnico de APKs orientado a investigación y evaluación de riesgo.

Objetivo principal:
- Auditar APKs con criterios reproducibles (firma, permisos, IOC estáticos, ofuscación, dominios, score de riesgo y conclusiones).

Resultado esperado:
- Reporte estructurado (`report.json`) y reporte ejecutivo (`report.txt`) para toma de decisión.

Limitación explícita:
- No existe garantía de malware cero; es un sistema de priorización de riesgo y evidencia técnica.

---

## 2) Stack y archivos clave

- Script principal: `apk-definitive-validator.ps1`
- Guía operativa: `GUIA_USO.md`
- Salidas: carpeta definida por `-OutDir` (por defecto `./apk-validator-output`)

Tecnología:
- PowerShell 5.1
- Herramientas Android CLI (`apksigner`, `aapt`, `apktool`)
- Java 17+
- Integración opcional con VirusTotal por hash

---

## 3) Entorno local instalado (preferencia disco D:)

- `apktool`: `D:\Tools\apktool\apktool.cmd`
- `jadx-gui`: `D:\Tools\jadx\jadx-gui.cmd`
- Android SDK root: `D:\Android`
- Build-tools (incluye `aapt`, `apksigner`): `D:\Android\build-tools\36.0.0`
- Platform-tools (`adb`): `D:\Android\platform-tools`

Variables/rutas relevantes:
- `ANDROID_SDK_ROOT = D:\Android`
- `PATH` de usuario incluye rutas de `D:\Android\...` y `D:\Tools\...`

---

## 4) Comandos de uso

Analisis basico:

```powershell
& "D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1" -ApkPath "D:\ruta\app.apk"
```

Analisis con VirusTotal por hash:

```powershell
$env:VT_API_KEY = "TU_API_KEY"
& "D:\Documents\MANUEL\VELINEX\APK-Security-Validator\apk-definitive-validator.ps1" -ApkPath "D:\ruta\app.apk" -EnableVirusTotal -VirusTotalApiKey $env:VT_API_KEY
```

Validaciones rápidas de entorno:

```powershell
apktool -version
aapt v
apksigner --version
java -version
```

---

## 5) Criterios operativos de seguridad

- Ejecutar APKs sospechosos solo en emulador/entorno aislado, nunca en teléfono principal.
- No usar cuentas reales ni credenciales personales durante pruebas dinámicas.
- Mantener las API keys fuera de commits y fuera de texto plano en archivos versionados.
- Evitar publicar reportes con datos sensibles (rutas privadas, IOCs internos, tokens).

---

## 6) Próximas mejoras sugeridas

- Modo batch para analizar múltiples APK en una corrida.
- Perfilado por tipo de app (editor de video, banca, juegos, etc.) con reglas diferenciadas.
- Módulo opcional de análisis dinámico (tráfico y comportamiento runtime) con pipeline automatizado.
