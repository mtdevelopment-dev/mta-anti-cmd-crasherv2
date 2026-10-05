@echo off
setlocal enabledelayedexpansion

echo =======================================================
echo   MTA Server Shield - Build Script (MSVC x64)
echo =======================================================

:: 1. Check if cl.exe is already in PATH and actually targeted for x64
set "IS_X64=0"
where cl >nul 2>&1
if not errorlevel 1 (
    cl 2>&1 | findstr /i "x64" >nul
    if not errorlevel 1 (
        set "IS_X64=1"
    )
)

if "%IS_X64%"=="1" goto compile

:: 2. Try locating Visual Studio via vswhere.exe
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
    if defined VS_PATH (
        if exist "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" (
            call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
            goto check_compiler
        )
        if exist "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" (
            call "!VS_PATH!\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
            goto check_compiler
        )
    )
)

:: 3. Fallback to standard known paths
if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)
if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    goto check_compiler
)

:check_compiler
where cl >nul 2>&1
if errorlevel 1 goto nocompiler

cl 2>&1 | findstr /i "x64" >nul
if errorlevel 1 (
    echo [WARNING] Active compiler is not x64. Attempting to switch...
    if exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
        call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
    )
)

:compile
if not exist bin mkdir bin
if not exist bin\x64 mkdir bin\x64

echo [*] Compiling mta_server_shield.dll (Release x64)...
cl /nologo /std:c++17 /O2 /EHsc /MT /LD src\mta_server_shield.cpp /Fe:bin\x64\mta_server_shield.dll /link /MACHINE:X64

if errorlevel 1 goto failed

:: Copy to bin/ as well for convenience
copy /y bin\x64\mta_server_shield.dll bin\mta_server_shield.dll >nul 2>&1

del *.obj *.exp *.lib 2>nul
del bin\x64\*.exp bin\x64\*.lib 2>nul
del bin\*.exp bin\*.lib 2>nul

echo =======================================================
echo   [SUCCESS] Built successfully:
echo   - bin\x64\mta_server_shield.dll (x64)
echo   - bin\mta_server_shield.dll (x64)
echo =======================================================
exit /b 0

:nocompiler
echo [ERROR] MSVC x64 Compiler (cl.exe) not found.
echo Please run this script from 'x64 Native Tools Command Prompt for VS'
echo or install C++ build tools in Visual Studio Installer.
exit /b 1

:failed
echo =======================================================
echo [ERROR] Build failed! Check the MSVC errors above.
echo =======================================================
exit /b 1
