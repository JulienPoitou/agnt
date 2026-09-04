@echo off
REM ============================================================================
REM Lance l'interface AGNT (API moteur seule) sur Windows, en local uniquement.
REM Double-cliquer ce fichier suffit :
REM   1. cree .venv si absent (Python du PATH)
REM   2. installe requirements-interface.txt si besoin
REM   3. demarre PHASE3\interface\api.py sur 127.0.0.1:8141
REM Override explicite reseau : lancer-web.bat --host 0.0.0.0 --port 8141
REM Ne touche pas : policy.py, sandbox bwrap, dashboard_api 8142.
REM ============================================================================
setlocal
cd /d "%~dp0"

set API_HOST=127.0.0.1
set API_PORT=8141

:parse_args
if "%~1"=="" goto run
if "%~1"=="--host" (
  set API_HOST=%~2
  shift
  shift
  goto parse_args
)
if "%~1"=="--port" (
  set API_PORT=%~2
  shift
  shift
  goto parse_args
)
REM Arguments inconnus transmis tels quels a api.py
set EXTRA_ARGS=%EXTRA_ARGS% %1
shift
goto parse_args

:run
if not exist ".venv\Scripts\python.exe" (
  echo ^>^> creation du venv Python (.venv)...
  python -m venv .venv
  if errorlevel 1 (
    echo ERREUR : python introuvable. Installe Python 3 puis relance.
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements-interface.txt
) else (
  ".venv\Scripts\python.exe" -c "import yaml" 2^>nul
  if errorlevel 1 (
    echo ^>^> dependances manquantes, installation...
    ".venv\Scripts\python.exe" -m pip install --quiet -r requirements-interface.txt
  )
)

echo ^>^> demarrage de l'API moteur sur %API_HOST%:%API_PORT% ...
echo     Console : http://%API_HOST%:%API_PORT%/  (Ctrl+C pour quitter)
".venv\Scripts\python.exe" PHASE3\interface\api.py --host %API_HOST% --port %API_PORT% %EXTRA_ARGS%
