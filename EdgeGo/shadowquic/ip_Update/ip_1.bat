@echo off
setlocal
chcp 936 >nul
cd /d "%~dp0"
Title ip1云端更新 shadowquic 最新配置
..\..\wget -t 2  --no-hsts --no-check-certificate https://www.gitlabip.xyz/Alvin9999/PAC/refs/heads/master/backup/img/1/2/ipp/shadowquic/1/client.yaml

if exist client.yaml goto startcopy

..\..\wget -t 2  --no-hsts --no-check-certificate https://gitlab.com/free9999/ipupdate/-/raw/master/backup/img/1/2/ipp/shadowquic/1/client.yaml

if exist client.yaml goto startcopy

echo ip更新失败，请试试ip_2更新
pause
exit
:startcopy

del "..\client.yaml_backup"
ren "..\client.yaml"  client.yaml_backup
copy /y "%~dp0client.yaml" ..\client.yaml
del "%~dp0client.yaml"
ECHO.&ECHO.已更新完成最新shadowquic配置,请按回车键或空格键启动程序！ &PAUSE >NUL 2>NUL
exit