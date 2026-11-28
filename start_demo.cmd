@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv-dashboard\Scripts\python.exe" (
  python -m venv .venv-dashboard
  if errorlevel 1 exit /b 1
)
echo Preparing the dashboard environment...
".venv-dashboard\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements-dashboard.txt
if errorlevel 1 exit /b 1
".venv-dashboard\Scripts\python.exe" -m treasury.lab %*
exit /b %errorlevel%
