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

---

## 2026-08-03

### Sesion 1 — Hardening, performance, estabilidad y despliegue VPS

- Se aplico hardening integral en `apk-definitive-validator.ps1` para evitar caidas por warnings/stderr, rutas inexistentes, nulos y tipados inconsistentes.
- Se agrego control de ejecucion de procesos con timeout para `apktool`/`java` y fallback de heap configurable para proteger recursos.
- Se introdujeron perfiles de ejecucion (`fast`, `balanced`, `deep`) con limites de seguridad/performance (`-ApktoolTimeoutSec`, `-MaxScanFiles`, `-ProgressEveryFiles`, `-ApktoolRetryHeapMb`).
- Se agregaron mensajes de progreso por fase y avance de IOC para evitar corridas "silenciosas" y facilitar monitoreo.
- Se optimizo el escaneo IOC para reducir I/O y recorridos redundantes.
- Se refino la regla `install_dropper` para reducir falsos positivos (se removio `FileProvider` del patron).
- Se creo launcher local robusto `run-validator.ps1` y wrapper `run-validator.bat` para ejecucion simple por ruta/arrastre.
- Se creo `.gitignore` robusto para evitar exponer secretos, artefactos, APKs y outputs sensibles.
- Se creo `install-deps-d-drive.ps1` para instalacion repetible de dependencias en PC local (disco D:).
- Se hizo despliegue funcional en VPS Ubuntu 24.04 con instalacion de `apktool`, `aapt`, `apksigner`, `java` y `pwsh`.
- Se creo flujo de 1 comando para VPS: `run-vps-analysis.ps1` + `run-vps-analysis.bat`.
- Se creo `GUIA_VPS.md` y se actualizo `GUIA_USO.md` para documentar uso en servidor.

### Resultado tecnico sobre APK CapCut (hash reproducible)

- APK: `capcut-APK-V15-5-0_happymod.ar.apk`
- SHA-256: `BBD5366DFB69F76558296C71966244A6F54E5099E1837586773F144D1C88A3CD`
- Resultado en VPS (perfil `fast`, limites seguros): `Risk Score 128.02`, `Verdict HIGH_RISK`.
- Hallazgos principales reportados: `dynamic_loader`, `domain_intel`, permisos sensibles moderados, `crypto_weak`, `webview_jsbridge`, `network_cleartext`, ofuscacion moderada.

### Estado al cierre

- Proyecto estable para ejecucion local y remota, con controles para evitar consumo excesivo de recursos en PC.
- Quedaron scripts listos para operacion diaria con minima friccion (arrastrar APK o ejecutar 1 comando).
