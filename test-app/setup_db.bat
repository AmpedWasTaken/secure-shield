@echo off
echo Setting up MySQL Database...
echo ==========================

REM MySQL credentials from config.js
set MYSQL_USER=root
set MYSQL_PASS=your_password

REM Create database
echo Creating database...
mysql -u %MYSQL_USER% -p%MYSQL_PASS% -e "CREATE DATABASE IF NOT EXISTS security_test;"

REM Create tables
echo Creating tables...
mysql -u %MYSQL_USER% 