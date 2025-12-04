@echo off
color 0E

cls
echo.
echo  ========================================================
echo   ZKDIP System Test
echo  ========================================================
echo.

echo  Running full system test...
echo.
cargo run -p zkdip-client -- test

echo.
echo  ========================================================
echo   Running VPN connection test...
echo  ========================================================
echo.
cargo run --bin test-client -- --server 127.0.0.1:51820 --ip 192.168.1.100 --jwt-secret dev_secret_key_change_in_production

echo.
echo  ========================================================
echo   Tests complete
echo  ========================================================
pause
