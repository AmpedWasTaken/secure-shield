@echo off
echo Running Security Tests...
echo ========================

echo 1. Testing User Registration
echo ---------------------------
curl -X POST http://localhost:3000/api/users/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser1\",\"password\":\"Password123!\",\"email\":\"test1@example.com\"}"
echo.

echo 2. Testing XSS Protection
echo ------------------------
curl -X POST http://localhost:3000/api/users/register ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"<script>alert(\\\"hacked\\\")</script>\",\"password\":\"Password123!\",\"email\":\"test2@example.com\"}"
echo.

echo 3. Testing SQL Injection Protection
echo ---------------------------------
curl -X POST http://localhost:3000/api/users/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"admin\\\" OR \\\"1\\\"=\\\"1\",\"password\":\"anything\"}"
echo.

echo 4. Testing Normal Login
echo ----------------------
curl -X POST http://localhost:3000/api/users/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":\"testuser1\",\"password\":\"Password123!\"}"
echo.

echo 5. Testing Post Creation
echo -----------------------
curl -X POST http://localhost:3000/api/posts ^
  -H "Content-Type: application/json" ^
  -d "{\"title\":\"Test Post\",\"content\":\"This is a legitimate post content.\"}"
echo.

echo 6. Testing Security Headers
echo -------------------------
curl -I http://localhost:3000/
echo.

echo 7. Testing Rate Limiting (10 quick requests)
echo ------------------------------------------
for /L %%i in (1,1,10) do (
    curl -s -o nul -w "%%{http_code}\n" http://localhost:3000/api/posts
)
echo.

echo 8. Testing Large Payload
echo ----------------------
setlocal EnableDelayedExpansion
set "payload="
for /L %%i in (1,1,1000) do set "payload=!payload!A"
curl -X POST http://localhost:3000/api/posts ^
  -H "Content-Type: application/json" ^
  -d "{\"title\":\"Large Post\",\"content\":\"!payload!\"}"
echo.

echo 9. Testing NoSQL Injection
echo ------------------------
curl -X POST http://localhost:3000/api/users/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}"
echo.

echo Tests completed!
pause 