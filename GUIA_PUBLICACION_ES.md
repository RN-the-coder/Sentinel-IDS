# Guía rápida: publicar Sentinel IDS desde Windows

Esta carpeta ya contiene los archivos preparados. **No incluye tus logs reales, tus datos de captura ni tu `venv`.**

## 1. Abrir el proyecto

Descomprime el ZIP, abre la carpeta `Sentinel-IDS-GitHub` en VS Code y verifica que estén `README.md`, `dashboard.py`, `sentinel_live.py` e `ids.py`.

El código original de `ids.py` que se adjunta corresponde al generado anteriormente en esta conversación. Si realizaste cambios locales posteriores, compáralos antes de reemplazarlo.

## 2. Probar la demo

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run dashboard.py
```

En el panel, selecciona **Demostración**. Esto no requiere captura ni permisos de administrador.

## 3. GitHub (crea un repositorio vacío)

En https://github.com/new, crea `Sentinel-IDS`. Selecciona Público solo cuando hayas revisado el contenido y NO marques la creación automática de README, licencia o .gitignore.

En VS Code, en la terminal de la carpeta principal:

```powershell
git init -b main
git add .
git status --short
```

ANTES de continuar, verifica que **no aparezcan** `venv`, `.env`, `ids_alerts.log`, `sentinel_status.json`, `.pcap`, capturas con IP reales ni CSVs privados.

```powershell
git commit -m "Initial release: Sentinel IDS dashboard"
git remote add origin https://github.com/TU_USUARIO/Sentinel-IDS.git
git push -u origin main
```

Reemplaza `TU_USUARIO` por tu usuario de GitHub o pega la URL exacta de tu repositorio; GitHub puede solicitar autenticación en el navegador. Si el directorio ya es un repositorio Git con un remoto `origin`, comprueba primero `git remote -v` antes de añadir otro.

## 4. Imágenes y privacidad

El README contiene capturas de la interfaz con IP protegidas. Para una presentación pública posterior, es preferible reemplazarlas por capturas nuevas en **Demostración**.

## 5. Créditos

El README atribuye el tutorial de freeCodeCamp. No añadí una licencia MIT porque parte del código proviene de un tutorial; revisa primero los derechos de redistribución si decides poner una licencia.
