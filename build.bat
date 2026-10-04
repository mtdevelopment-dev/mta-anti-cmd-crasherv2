@echo off

echo =======================================================
echo   MTA Server Shield - Build Script (MSVC x64)
echo =======================================================

where cl >nul 2>&1
if not errorlevel 1 goto compile

if exist "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

where cl >nul 2>&1
if errorlevel 1 goto nocompiler

:compile
if not exist bin mkdir bin
if not exist bin\x64 mkdir bin\x64

echo [*] Compiling mta_server_shield.dll (Release x64)...
cl /nologo /std:c++17 /O2 /EHsc /MT /LD src\mta_server_shield.cpp /Fe:bin\x64\mta_server_shield.dll /link /MACHINE:X64

if errorlevel 1 goto failed

del *.obj *.exp *.lib 2>nul
del bin\x64\*.exp bin\x64\*.lib 2>nul

echo =======================================================
echo   [SUCCESS] Built successfully:
echo   bin\x64\mta_server_shield.dll
echo =======================================================
exit /b 0

:nocompiler
echo [ERROR] MSVC x64 Compiler (cl.exe) not found.
echo Please run this script from 'x64 Native Tools Command Prompt for VS'.
exit /b 1

:failed
echo [ERROR] Build failed!
exit /b 1
