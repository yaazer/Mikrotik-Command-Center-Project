@echo off
rem Restart Mikrotik Command Center: stops the copy already running on the port, then starts a new one.
rem Pass the same options you normally use, e.g.  restart-mcc.cmd --demo
cd /d "%~dp0"
where python >nul 2>nul && (python mcc.py --replace %*) || (py -3 mcc.py --replace %*)
