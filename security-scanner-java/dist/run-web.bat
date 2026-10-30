@echo off
REM SecureForge - launch the web dashboard (Windows)
REM Usage: run-web.bat [port]

set PORT=%1
if "%PORT%"=="" set PORT=8765
set JAR_DIR=%~dp0
set JAR=%JAR_DIR%secureforge.jar

where java >nul 2>nul
if errorlevel 1 (
  echo Java is not installed. SecureForge needs Java 21 or later.
  echo Download: https://adoptium.net/
  exit /b 1
)

echo Starting SecureForge web UI on port %PORT% ...
echo Open http://localhost:%PORT% in your browser.
echo.
java -jar "%JAR%" --web --port %PORT%
