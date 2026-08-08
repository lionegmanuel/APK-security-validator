# APK Security Validator - Guia VPS (Ubuntu)

Esta guia deja el analizador ejecutando en un VPS Linux para no consumir recursos de tu PC.

## 1) Requisitos previos

- VPS Ubuntu 24.04 (o similar) con acceso SSH.
- Usuario con permisos `sudo` (ideal) o `root`.
- Docker no es obligatorio para esta version (se instala nativo).

## 2) Preparar carpetas en el VPS

```bash
sudo mkdir -p /opt/apk-validator /opt/apk-input /opt/apk-output
```

## 3) Instalar dependencias

```bash
sudo apt-get update -y
sudo apt-get install -y openjdk-17-jre-headless apktool aapt apksigner wget
```

Instalar PowerShell 7:

```bash
wget -q https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
sudo dpkg -i /tmp/packages-microsoft-prod.deb
sudo apt-get update -y
sudo apt-get install -y powershell
```

Validar:

```bash
pwsh -v
apktool --version
aapt v
apksigner --version
java -version
```

## 4) Subir scripts al VPS

Desde tu PC (PowerShell):

```powershell
scp .\apk-definitive-validator.ps1 root@TU_IP:/opt/apk-validator/
scp .\run-validator.ps1 root@TU_IP:/opt/apk-validator/
```

Si usas usuario distinto, reemplaza `root`.

## 5) Subir APK al VPS

```powershell
scp "D:\ruta\tu-app.apk" root@TU_IP:/opt/apk-input/
```

## 6) Ejecutar analisis remoto (modo seguro recomendado)

Conectate por SSH y ejecuta:

```bash
pwsh -NoLogo -NoProfile -File /opt/apk-validator/apk-definitive-validator.ps1 \
  -ApkPath /opt/apk-input/tu-app.apk \
  -Profile fast \
  -ApktoolTimeoutSec 300 \
  -MaxScanFiles 3000 \
  -ProgressEveryFiles 500 \
  -ApktoolRetryHeapMb 1536 \
  -OutDir /opt/apk-output/analisis-1
```

## 7) Ver resultados

En el VPS:

```bash
cat /opt/apk-output/analisis-1/report.txt
```

Bajar reportes a tu PC:

```powershell
scp root@TU_IP:/opt/apk-output/analisis-1/report.txt .
scp root@TU_IP:/opt/apk-output/analisis-1/report.json .
```

## 8) Perfiles recomendados

- `fast` (recomendado diario): menor consumo de RAM/CPU, mas rapido.
- `balanced`: mayor cobertura, consumo intermedio.
- `deep`: max cobertura, mas tiempo/recursos.

## 9) Comandos utiles de operacion

Ver procesos del analizador:

```bash
pgrep -af "pwsh.*apk-definitive-validator|apktool|java"
```

Detener corrida activa:

```bash
pkill -f "apk-definitive-validator.ps1"
pkill -f "apktool"
pkill -f "java.*apktool"
```

Limpiar temporales:

```bash
rm -rf /tmp/apk_def_validator_*
```

## 10) Seguridad operativa recomendada

- No usar `root` para trabajo diario; crear usuario tecnico con `sudo`.
- Rotar credenciales si se compartieron en texto plano.
- No subir API keys a Git; usar variables de entorno.
- Mantener `/opt/apk-input` para APKs y `/opt/apk-output` para reportes, con permisos controlados.

## 11) Ejecucion en 1 comando (recomendado)

Desde tu repo local (Windows PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File ".\run-vps-analysis.ps1" "D:\ruta\tu-app.apk"
```

Eso hace automaticamente:

1. Crea/valida carpetas en VPS.
2. Sube `apk-definitive-validator.ps1`.
3. Sube tu APK.
4. Ejecuta analisis remoto en perfil seguro (`fast`).
5. Descarga `report.txt` y `report.json` a `./vps-reports/<run-id>/`.

Tambien podes usar doble click + arrastrar APK sobre:

- `run-vps-analysis.bat`

Opciones utiles:

```powershell
.\run-vps-analysis.ps1 "D:\ruta\tu-app.apk" -Host "TU_IP" -User "root" -Port 22
.\run-vps-analysis.ps1 "D:\ruta\tu-app.apk" -Profile balanced -MaxScanFiles 8000
```

Nota: requiere que `ssh` y `scp` funcionen desde tu terminal local.
