@echo off
color 0C

cls
echo.
echo  ========================================================
echo   Stopping All ZKDIP Services...
echo  ========================================================
echo.

taskkill /F /IM blind-token-service.exe /T 2>nul
if %errorlevel%==0 (echo  [OK] Blind Token Service stopped) else (echo  [--] Blind Token Service not running)

taskkill /F /IM enclave-sim.exe /T 2>nul
if %errorlevel%==0 (echo  [OK] Enclave Simulator stopped) else (echo  [--] Enclave Simulator not running)

taskkill /F /IM dip-service.exe /T 2>nul
if %errorlevel%==0 (echo  [OK] DIP Service stopped) else (echo  [--] DIP Service not running)

taskkill /F /IM vpn-server.exe /T 2>nul
if %errorlevel%==0 (echo  [OK] VPN Server stopped) else (echo  [--] VPN Server not running)

echo.
echo  ========================================================
echo   All services stopped
echo  ========================================================
echo.
pause
