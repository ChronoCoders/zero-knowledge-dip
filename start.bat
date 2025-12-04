@echo off
color 0A

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
echo  Starting All Services...
echo  ========================================================
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
echo  ========================================================
echo   All Services Started Successfully!
echo  ========================================================
echo.
echo   - Blind Token Service : http://localhost:3001
echo   - Enclave Simulator   : http://localhost:3002
echo   - DIP Service         : http://localhost:3003
echo   - VPN Server          : udp://0.0.0.0:51820
echo.
echo  ========================================================
echo   Press any key to exit...
echo  ========================================================
pause >nul
