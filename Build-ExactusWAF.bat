@echo off
REM ====================================================================
REM  Bangun ulang exactuswaf.exe dari kode sumber (butuh Go terpasang).
REM  Jalankan ini setelah Anda mengubah aturan atau kode.
REM ====================================================================
title Build ExactusWAF
cd /d "%~dp0"

where go >nul 2>nul
if errorlevel 1 (
    echo   [!] Go belum terpasang. Unduh di https://go.dev/dl/ lalu coba lagi.
    pause
    exit /b 1
)

echo   Membangun exactuswaf.exe ...
go mod tidy
go build -o exactuswaf.exe .
if errorlevel 1 (
    echo   [!] Build GAGAL. Cek pesan error di atas.
    pause
    exit /b 1
)
echo.
echo   [OK] Selesai. File exactuswaf.exe sudah dibuat.
echo        Sekarang klik dua kali "Jalankan-ExactusWAF.bat".
pause
