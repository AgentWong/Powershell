$TargetComputer = Read-Host "What computer name do you want to install the printer on?"
$PrintServer = Read-Host "What is the name of the print server?"
$Printer = Read-Host "What is the name of the printer?"

Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$TargetComputer /ga /n \\$PrintServer\$Printer"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net stop spooler"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net start spooler"
