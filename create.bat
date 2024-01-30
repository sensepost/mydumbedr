sc create mydumbedr type=kernel binpath=Z:\windev\MyDumbEDR\x64\Debug\MyDumbEDRDriver.sys
sc start mydumbedr
start cmd.exe /c Z:\windev\MyDumbEDR\x64\Debug\MyDumbEDRStaticAnalyzer.exe 
start cmd.exe /c Z:\windev\MyDumbEDR\x64\Debug\MyDumbEDRRemoteInjector.exe 
start cmd.exe /K "cd Z:\windev\MyDumbEDR\x64\Debug"

echo EDR's running, press any key to stop it
pause

taskkill /F /IM MyDumbEDRStaticAnalyzer.exe 
taskkill /F /IM MyDumbEDRRemoteInjector.exe
sc stop mydumbedr
sc delete mydumbedr
