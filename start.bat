@echo off
setlocal enabledelayedexpansion
color 0A

:banner
cls
echo.
echo  ========================================================
echo.
echo     ########  ##    ## ########  #### ########
echo        ##     ##   ##  ##     ##  ##  ##     ##
echo       ##      ##  ##   ##     ##  ##  ##     ##
echo      ##       #####    ##     ##  ##  ########
echo     ##        ##  ##   ##     ##  ##  ##
echo    ##         ##   ##  ##     ##  ##  ##
echo   ########    ##    ## ########  #### ##
echo.
echo  ========================================================
echo   Zero-Knowledge Dedicated IP VPN System
echo   Secure * Private * Decentralized
echo  ========================================================
echo.

:menu
echo  [1] Start All Services
echo  [2] Stop All Services
echo  [3] Check System Status
echo  [4] Run Full System Test
echo  [5] Start Individual Services
echo  [6] VPN Connection Test
echo  [7] View Logs
echo  [8] Clean Build
echo  [0] Exit
echo.
set /p choice="  Select option: "

if "%choice%"=="1" goto start_all
if "%choice%"=="2" goto stop_all
if "%choice%"=="3" goto status
if "%choice%"=="4" goto test_system
if "%choice%"=="5" goto individual
if "%choice%"=="6" goto vpn_test
if "%choice%"=="7" goto logs
if "%choice%"=="8" goto clean_build
if "%choice%"=="0" goto end
goto menu

:start_all
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Starting All Services...
echo  ════════════════════════════════════════════════════════
echo.

echo  [1/4] Starting Blind Token Service (Port 3001)...
start "ZKDIP - Blind Token Service" cmd /k "color 0B && title ZKDIP - Blind Token Service && cargo run -p blind-token-service"
timeout /t 3 /nobreak >nul

echo  [2/4] Starting Enclave Simulator (Port 3002)...
start "ZKDIP - Enclave Simulator" cmd /k "color 0C && title ZKDIP - Enclave Simulator && cargo run -p enclave-sim"
timeout /t 3 /nobreak >nul

echo  [3/4] Starting DIP Service (Port 3003)...
start "ZKDIP - DIP Service" cmd /k "color 0D && title ZKDIP - DIP Service && cargo run -p dip-service"
timeout /t 5 /nobreak >nul

echo  [4/4] Starting VPN Server (Port 51820)...
start "ZKDIP - VPN Server" cmd /k "color 0E && title ZKDIP - VPN Server && cargo run --bin vpn-server -- --ip 192.168.1.100 --jwt-secret dev_secret_key_change_in_production"
timeout /t 3 /nobreak >nul

echo.
echo  ✓ All services started successfully!
echo.
echo  Services running:
echo    • Blind Token Service : http://localhost:3001
echo    • Enclave Simulator   : http://localhost:3002
echo    • DIP Service         : http://localhost:3003
echo    • VPN Server          : udp://0.0.0.0:51820
echo.
pause
goto menu

:stop_all
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Stopping All Services...
echo  ════════════════════════════════════════════════════════
echo.

taskkill /F /IM blind-token-service.exe /T 2>nul
if %errorlevel%==0 (echo  ✓ Blind Token Service stopped) else (echo  ⚠ Blind Token Service not running)

taskkill /F /IM enclave-sim.exe /T 2>nul
if %errorlevel%==0 (echo  ✓ Enclave Simulator stopped) else (echo  ⚠ Enclave Simulator not running)

taskkill /F /IM dip-service.exe /T 2>nul
if %errorlevel%==0 (echo  ✓ DIP Service stopped) else (echo  ⚠ DIP Service not running)

taskkill /F /IM vpn-server.exe /T 2>nul
if %errorlevel%==0 (echo  ✓ VPN Server stopped) else (echo  ⚠ VPN Server not running)

echo.
echo  ✓ All services stopped
echo.
pause
goto menu

:status
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   System Status
echo  ════════════════════════════════════════════════════════
echo.

echo  Checking services...
echo.

netstat -an | findstr "3001" >nul
if %errorlevel%==0 (
    echo  ✓ Blind Token Service  [RUNNING]  Port 3001
) else (
    echo  ✗ Blind Token Service  [STOPPED]
)

netstat -an | findstr "3002" >nul
if %errorlevel%==0 (
    echo  ✓ Enclave Simulator    [RUNNING]  Port 3002
) else (
    echo  ✗ Enclave Simulator    [STOPPED]
)

netstat -an | findstr "3003" >nul
if %errorlevel%==0 (
    echo  ✓ DIP Service          [RUNNING]  Port 3003
) else (
    echo  ✗ DIP Service          [STOPPED]
)

netstat -an | findstr "51820" >nul
if %errorlevel%==0 (
    echo  ✓ VPN Server           [RUNNING]  Port 51820
) else (
    echo  ✗ VPN Server           [STOPPED]
)

echo.
echo  ════════════════════════════════════════════════════════
pause
goto menu

:test_system
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Running Full System Test
echo  ════════════════════════════════════════════════════════
echo.

echo  Checking if all services are running...
netstat -an | findstr "3001 3002 3003 51820" >nul
if %errorlevel% neq 0 (
    echo  ✗ Error: Not all services are running!
    echo    Please start all services first (Option 1)
    echo.
    pause
    goto menu
)

echo  ✓ All services detected
echo.
echo  Running client test flow...
echo.
cargo run -p zkdip-client -- test

echo.
echo  ════════════════════════════════════════════════════════
pause
goto menu

:vpn_test
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   VPN Connection Test
echo  ════════════════════════════════════════════════════════
echo.

netstat -an | findstr "51820" >nul
if %errorlevel% neq 0 (
    echo  ✗ Error: VPN Server is not running!
    echo    Please start VPN server first
    echo.
    pause
    goto menu
)

echo  ✓ VPN Server detected
echo.
echo  Running VPN connection test...
echo.
cargo run --bin test-client -- --server 127.0.0.1:51820 --ip 192.168.1.100 --jwt-secret dev_secret_key_change_in_production

echo.
echo  ════════════════════════════════════════════════════════
pause
goto menu

:individual
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Start Individual Service
echo  ════════════════════════════════════════════════════════
echo.
echo  [1] Blind Token Service (Port 3001)
echo  [2] Enclave Simulator (Port 3002)
echo  [3] DIP Service (Port 3003)
echo  [4] VPN Server (Port 51820)
echo  [0] Back to Main Menu
echo.
set /p svc="  Select service: "

if "%svc%"=="1" (
    start "ZKDIP - Blind Token Service" cmd /k "color 0B && title ZKDIP - Blind Token Service && cargo run -p blind-token-service"
    echo  ✓ Blind Token Service started
    timeout /t 2 /nobreak >nul
)
if "%svc%"=="2" (
    start "ZKDIP - Enclave Simulator" cmd /k "color 0C && title ZKDIP - Enclave Simulator && cargo run -p enclave-sim"
    echo  ✓ Enclave Simulator started
    timeout /t 2 /nobreak >nul
)
if "%svc%"=="3" (
    start "ZKDIP - DIP Service" cmd /k "color 0D && title ZKDIP - DIP Service && cargo run -p dip-service"
    echo  ✓ DIP Service started
    timeout /t 2 /nobreak >nul
)
if "%svc%"=="4" (
    start "ZKDIP - VPN Server" cmd /k "color 0E && title ZKDIP - VPN Server && cargo run --bin vpn-server -- --ip 192.168.1.100 --jwt-secret dev_secret_key_change_in_production"
    echo  ✓ VPN Server started
    timeout /t 2 /nobreak >nul
)
if "%svc%"=="0" goto menu
goto individual

:logs
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Service Logs
echo  ════════════════════════════════════════════════════════
echo.
echo  Logs are displayed in each service window.
echo  To enable debug logging, set: RUST_LOG=debug
echo.
echo  Service Windows:
echo    • ZKDIP - Blind Token Service
echo    • ZKDIP - Enclave Simulator
echo    • ZKDIP - DIP Service
echo    • ZKDIP - VPN Server
echo.
pause
goto menu

:clean_build
cls
call :banner
echo  ════════════════════════════════════════════════════════
echo   Clean Build
echo  ════════════════════════════════════════════════════════
echo.
echo  This will:
echo    1. Stop all running services
echo    2. Clean build artifacts
echo    3. Rebuild all crates
echo.
set /p confirm="  Continue? (y/n): "
if /i not "%confirm%"=="y" goto menu

echo.
echo  Stopping services...
call :stop_all_quiet

echo  Cleaning build artifacts...
cargo clean

echo  Building all crates...
cargo build --workspace --release

echo.
echo  ✓ Clean build completed
echo.
pause
goto menu

:stop_all_quiet
taskkill /F /IM blind-token-service.exe /T 2>nul
taskkill /F /IM enclave-sim.exe /T 2>nul
taskkill /F /IM dip-service.exe /T 2>nul
taskkill /F /IM vpn-server.exe /T 2>nul
exit /b

:end
cls
call :banner
echo  Shutting down...
call :stop_all_quiet
echo.
echo  ✓ ZKDIP System shutdown complete
echo.
timeout /t 2 /nobreak >nul
exit
