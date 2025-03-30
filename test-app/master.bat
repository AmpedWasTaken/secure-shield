@echo off
echo Starting Security Test Suite...
echo =============================

REM Setup database
call setup_db.bat

REM Start application
start "Test App" cmd /c start.bat

REM Wait for application to start
echo Waiting for application to start...
timeout /t 5

REM Run tests
call run_tests.bat

echo All done!
pause 