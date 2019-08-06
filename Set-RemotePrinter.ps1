<#
.SYNOPSIS
This adds, removes, or views printers installed on remote computers (workstations only).

.DESCRIPTION
This uses the rundll32 printui.dll,PrintUIEntry command to install, remove, or view printers installed on remote workstations.
This should only be required if a print driver needs to be installed from a print server and isn't already on a computer.
Any printers installed using this tool will be available for all users on the computer.  If a printer needs to be removed,
it must be removed using this tool or the printer will reappear.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Set-RemotePrinter'
$form.Size = New-Object System.Drawing.Size(400,300)
$form.StartPosition = 'CenterScreen'

$TargetLabel = New-Object System.Windows.Forms.Label
$TargetLabel.Location = New-Object System.Drawing.Point(75,20)
$TargetLabel.Size = New-Object System.Drawing.Size(225,20)
$TargetLabel.Text = 'Target Computer:'
$form.Controls.Add($TargetLabel)

$TargetComputerBox = New-Object System.Windows.Forms.TextBox
$TargetComputerBox.Location = New-Object System.Drawing.Point(75,40)
$TargetComputerBox.Size = New-Object System.Drawing.Size(225,20)
$form.Controls.Add($TargetComputerBox)

$ServerLabel = New-Object System.Windows.Forms.Label
$ServerLabel.Location = New-Object System.Drawing.Point(75,70)
$ServerLabel.Size = New-Object System.Drawing.Size(225,20)
$ServerLabel.Text = 'Print Server:'
$form.Controls.Add($ServerLabel)

$PrintServerBox = New-Object System.Windows.Forms.TextBox
$PrintServerBox.Location = New-Object System.Drawing.Point(75,90)
$PrintServerBox.Size = New-Object System.Drawing.Size(225,20)
$form.Controls.Add($PrintServerBox)

$PrinterLabel = New-Object System.Windows.Forms.Label
$PrinterLabel.Location = New-Object System.Drawing.Point(75,120)
$PrinterLabel.Size = New-Object System.Drawing.Size(225,20)
$PrinterLabel.Text = 'Printer Name:'
$form.Controls.Add($PrinterLabel)

$PrinterBox = New-Object System.Windows.Forms.TextBox
$PrinterBox.Location = New-Object System.Drawing.Point(75,140)
$PrinterBox.Size = New-Object System.Drawing.Size(225,20)
$form.Controls.Add($PrinterBox)

$AddButton = New-Object System.Windows.Forms.Button
$AddButton.Location = New-Object System.Drawing.Point(75,180)
$AddButton.Size = New-Object System.Drawing.Size(75,23)
$AddButton.Text = 'Add'
$form.Controls.Add($AddButton)

$RemoveButton = New-Object System.Windows.Forms.Button
$RemoveButton.Location = New-Object System.Drawing.Point(150,180)
$RemoveButton.Size = New-Object System.Drawing.Size(75,23)
$RemoveButton.Text = 'Remove'
$form.Controls.Add($RemoveButton)

$ViewButton = New-Object System.Windows.Forms.Button
$ViewButton.Location = New-Object System.Drawing.Point(225,180)
$ViewButton.Size = New-Object System.Drawing.Size(75,23)
$ViewButton.Text = 'View'
$form.Controls.Add($ViewButton)

$form.Topmost = $true

$form.ShowDialog()

$AddButton.Add_Click({Add-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text})
$RemoveButton.Add_Click({Remove-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text})
$ViewButton.Add_Click({Get-RemotePrinter -ComputerName $TargetComputerBox.Text})
Function Add-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ComputerName,
        [Parameter(Mandatory=$True)]
        [string]$ServerName,
        [Parameter(Mandatory=$True)]
        [string]$PrinterName
    )
BEGIN {}

PROCESS{
Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$TargetComputer /ga /n \\$PrintServer\$Printer"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net stop spooler"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net start spooler"
}

END{}
}

Function Remove-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ComputerName,
        [Parameter(Mandatory=$True)]
        [string]$ServerName,
        [Parameter(Mandatory=$True)]
        [string]$PrinterName
    )
BEGIN {}

PROCESS{
Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$TargetComputer /gd /n \\$PrintServer\$Printer"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net stop spooler"
Start-Sleep -Seconds 3
Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$TargetComputer cmd /c net start spooler"
}

END{}
}

Function Get-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ComputerName
    )
BEGIN {}

PROCESS{
Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$TargetComputer /ge"
}

END{}
}