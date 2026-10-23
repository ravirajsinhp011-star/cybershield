@echo off
title AI CyberShield - One-Click Auto Deploy
color 0B
echo ========================================================
echo        AI CYBERSHIELD - ONE-CLICK AUTO DEPLOY
echo ========================================================
echo.
echo [*] Step 1: Staging changes...
git add .
echo [*] Step 2: Creating commit...
git commit -m "Auto update: %date% %time%"
echo [*] Step 3: Pushing to GitHub (Triggering Vercel Deployment)...
git push origin main
echo.
echo ========================================================
echo  [SUCCESS] Code pushed to GitHub!
echo  Vercel is now building your updated website.
echo.
echo  Live URL: https://cybershield-cyber-shield.vercel.app/
echo ========================================================
echo.
pause
