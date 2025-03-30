@echo off
echo Starting Test Application...
echo ==========================

REM Check if node_modules exists
if not exist "node_modules" (
    echo Installing dependencies...
    npm install
)

REM Check if logs directory exists
if not exist "logs" (
    echo Creating logs directory...
    mkdir logs
)

REM Start the application
echo Starting server...
node app.js
pause 