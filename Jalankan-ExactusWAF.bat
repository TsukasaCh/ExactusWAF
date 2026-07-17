@echo off
REM ====================================================================
REM  ExactusWAF - Klik dua kali file ini untuk MENJALANKAN WAF.
REM ====================================================================
title ExactusWAF
cd /d "%~dp0"

echo.
echo   Memulai ExactusWAF...
echo   (Untuk berhenti: tekan Ctrl+C atau tutup jendela ini)
echo.

REM Jika binary belum ada, coba buatkan otomatis (butuh Go terpasang).
if not exist "exactuswaf.exe" (
    echo   File exactuswaf.exe belum ada, mencoba membangun...
    where go >nul 2>nul
    if errorlevel 1 (
        echo.
        echo   [!] Go belum terpasang dan exactuswaf.exe tidak ditemukan.
        echo       Silakan unduh Go di https://go.dev/dl/ lalu jalankan Build-ExactusWAF.bat
        echo.
        pause
        exit /b 1
    )
    go build -o exactuswaf.exe .
    if errorlevel 1 (
        echo   [!] Gagal membangun. Cek pesan di atas.
        pause
        exit /b 1
    )
)

exactuswaf.exe -config config.yaml

echo.
echo   ExactusWAF berhenti.
pause
