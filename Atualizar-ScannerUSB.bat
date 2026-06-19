@echo off
title Atualizar ScannerUSB
setlocal

REM ============================================================
REM  EDITA ESTA LINHA: poe o teu utilizador/repositorio do GitHub
set "REPO=Jaime3412/scanner-usb"
REM ============================================================

set "URL=https://github.com/%REPO%/releases/latest/download/ScannerUSB.exe"
set "OUT=%~dp0ScannerUSB.exe"

echo.
echo  A descarregar a versao mais recente do ScannerUSB...
echo  De:   %URL%
echo  Para: %OUT%
echo.

curl -L -f -o "%OUT%" "%URL%"

if %ERRORLEVEL%==0 (
    echo.
    echo  [OK] Concluido! Ja tens a versao mais recente.
) else (
    echo.
    echo  [ERRO] Nao foi possivel descarregar.
    echo.
    echo  Verifica que:
    echo    1^) Editaste a linha REPO neste ficheiro com o teu utilizador/repositorio.
    echo    2^) Existe um Release no GitHub com um ficheiro chamado ScannerUSB.exe.
    echo    3^) Tens ligacao a internet.
)

echo.
pause
