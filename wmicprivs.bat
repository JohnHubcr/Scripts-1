@echo off
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> permissions.txt
for /f eol^=^"^ delims^=^" %a in (permissions.txt) do cmd.exe /c icacls "%a" >> srvperms.txt
del permissions.txt
