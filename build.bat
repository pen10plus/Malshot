@echo off
setlocal
cd /d "%~dp0"

where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go was not found on PATH.
    exit /b 1
)

if exist "C:\msys64\mingw64\bin\gcc.exe" (
    set "PATH=C:\msys64\mingw64\bin;C:\msys64\usr\bin;%PATH%"
    set "PKG_CONFIG_PATH=C:\msys64\mingw64\lib\pkgconfig"
    set "CGO_LDFLAGS=-LC:/msys64/mingw64/lib -lyara -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32"
) else if exist "C:\msys64\ucrt64\bin\gcc.exe" (
    set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
    set "PKG_CONFIG_PATH=C:\msys64\ucrt64\lib\pkgconfig"
    set "CGO_LDFLAGS=-LC:/msys64/ucrt64/lib -lyara -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32"
)

where gcc >nul 2>&1
if errorlevel 1 (
    echo [ERROR] gcc was not found on PATH. Install MinGW-w64 for CGO.
    exit /b 1
)

if "%CGO_ENABLED%"=="" set CGO_ENABLED=1
if not "%CGO_ENABLED%"=="1" (
    echo [ERROR] CGO_ENABLED must be 1 for the SQLite/YARA/ONNX build.
    exit /b 1
)

echo [INFO] Building MalShot with CGO_ENABLED=%CGO_ENABLED%...
go build -trimpath -tags deepinspection -ldflags="-s -w -H=windowsgui" -o malshot.exe .
if errorlevel 1 (
    echo [ERROR] Build failed. Verify libyara and ONNX Runtime development libraries are installed.
    exit /b 1
)

echo [OK] Created %CD%\malshot.exe
endlocal
