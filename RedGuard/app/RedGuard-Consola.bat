@echo off
title RedGuard - Revisar mi red
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0RedGuard.ps1" %*
echo.
pause
