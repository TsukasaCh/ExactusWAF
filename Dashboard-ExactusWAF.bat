@echo off
REM ====================================================================
REM  Membuka Dashboard ExactusWAF sebagai jendela aplikasi (tanpa
REM  address bar), atau di browser biasa bila Edge/Chrome tak ditemukan.
REM  Pastikan ExactusWAF sudah berjalan lebih dulu.
REM ====================================================================
setlocal
set "URL=http://localhost:9090"

REM Bila ExactusWAF berjalan di Docker, dashboard dibuka lewat IP container
REM (port dashboard sengaja tidak dipublish agar tidak terbuka ke jaringan).
for /f "usebackq delims=" %%i in (`docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" exactuswaf 2^>nul`) do (
    if not "%%i"=="" set "URL=http://%%i:9090"
)

REM --- Coba Microsoft Edge (mode aplikasi) ---
set "EDGE=%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
if exist "%EDGE%" (
    start "" "%EDGE%" --app=%URL% --window-size=1200,850
    goto :eof
)
set "EDGE=%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
if exist "%EDGE%" (
    start "" "%EDGE%" --app=%URL% --window-size=1200,850
    goto :eof
)

REM --- Coba Google Chrome (mode aplikasi) ---
set "CHROME=%ProgramFiles%\Google\Chrome\Application\chrome.exe"
if exist "%CHROME%" (
    start "" "%CHROME%" --app=%URL% --window-size=1200,850
    goto :eof
)
set "CHROME=%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
if exist "%CHROME%" (
    start "" "%CHROME%" --app=%URL% --window-size=1200,850
    goto :eof
)

REM --- Cadangan: buka di browser default ---
start "" "%URL%"
