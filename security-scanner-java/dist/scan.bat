@echo off
REM SecureForge - run a one-off CLI scan (Windows)
REM Usage: scan.bat C:\path\to\project [output-dir]

set TARGET=%1
set OUTPUT=%2
if "%OUTPUT%"=="" set OUTPUT=.\reports
set JAR_DIR=%~dp0
set JAR=%JAR_DIR%secureforge.jar

if "%TARGET%"=="" (
  echo Usage: scan.bat C:\path\to\project [output-dir]
  exit /b 1
)

where java >nul 2>nul
if errorlevel 1 (
  echo Java is not installed. SecureForge needs Java 21 or later.
  echo Download: https://adoptium.net/
  exit /b 1
)

java -jar "%JAR%" --target "%TARGET%" --output "%OUTPUT%"
