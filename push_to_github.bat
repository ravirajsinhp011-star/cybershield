@echo off
echo ===================================================
echo   Pushing Clean CyberShield to GitHub Repository
echo ===================================================
git branch -M main
git push -u origin main --force
echo.
echo ===================================================
echo   Done! Check your Vercel deployment dashboard.
echo ===================================================
pause
