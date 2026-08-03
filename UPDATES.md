# UPDATES.md — APK Security Validator · Historial de sesiones

> Registrar solo cuando el usuario lo pida. Mantener solo las ultimas 3 secciones por dia. Dentro de cada dia puede haber multiples sesiones, separadas con `---`.

---

## 2026-08-02

### Sesion 1 — Base del proyecto, instalacion de tooling y estructura

- Se creo el script principal `apk-definitive-validator.ps1` con analisis estatico avanzado: hash SHA-256, validacion de firma/certificados, permisos sensibles, decompilacion (`apktool`), reglas IOC, heuristica de ofuscacion, inteligencia basica de dominios y scoring final con veredicto.
- Se agrego integracion opcional con VirusTotal por hash (`-EnableVirusTotal` + `-VirusTotalApiKey`), sin subida forzada de APK.
- Se implemento salida dual de reportes: `report.json` (detallado) y `report.txt` (ejecutivo).
- Se instalo tooling necesario priorizando `D:`:
  - `apktool` en `D:\Tools\apktool`
  - `jadx-gui` en `D:\Tools\jadx`
  - Android SDK cmdline tools + build-tools + platform-tools en `D:\Android`
  - Java 17 (OpenJDK)
- Se configuraron variables y PATH de usuario para resolver `apktool`, `aapt`, `apksigner`, `adb` y `jadx-gui` en nuevas terminales.
- Se reorganizo el proyecto a carpeta dedicada: `D:\Documents\MANUEL\VELINEX\APK-Security-Validator`.
- Se creo guia operativa `GUIA_USO.md` con uso exacto, parametros y buenas practicas de seguridad.

### Estado al cierre

- Proyecto operativo y listo para uso manual en una sola maquina o sincronizacion entre PCs.
- No hubo push ni publicacion automatica en GitHub.

### Pendientes sugeridos

- Agregar script launcher corto (`run-validator.ps1`) para ejecucion rapida.
- Implementar modo batch para multiples APKs.
- Diseñar modulo dinamico opcional (emulador + captura de trafico) para ampliar cobertura.
