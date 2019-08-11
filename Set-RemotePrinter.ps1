<#
.SYNOPSIS
This adds, removes, or views printers installed on remote computers (workstations only).
.DESCRIPTION
This uses the rundll32 printui.dll,PrintUIEntry command to install, remove, or view printers installed on remote workstations.
This should only be required if a print driver needs to be installed from a print server and isn't already on a computer.
Any printers installed using this tool will be available for all users on the computer.  If a printer needs to be removed,
it must be removed using this tool or the printer will reappear if you attempt to remove it from Devices and Printers.
#>

# .Net methods for hiding/showing the console in the background
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

function Show-Console
{
    $consolePtr = [Console.Window]::GetConsoleWindow()

    # Hide = 0,
    # ShowNormal = 1,
    # ShowMinimized = 2,
    # ShowMaximized = 3,
    # Maximize = 3,
    # ShowNormalNoActivate = 4,
    # Show = 5,
    # Minimize = 6,
    # ShowMinNoActivate = 7,
    # ShowNoActivate = 8,
    # Restore = 9,
    # ShowDefault = 10,
    # ForceMinimized = 11

    [Console.Window]::ShowWindow($consolePtr, 4)
}

function Hide-Console
{
    $consolePtr = [Console.Window]::GetConsoleWindow()
    #0 hide
    [Console.Window]::ShowWindow($consolePtr, 0)
}


#Hides the Powershell console window.
Hide-Console

$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Checks if the account running has certain text in its name, if not, it will relaunch the script as an administrator.
if ($CurrentUser -notlike "*z0*") {
    # Self-elevate the script if required
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine -WindowStyle Hidden
        Exit
    }
}

Function Confirm-IsEmpty ([string[]]$Fields){
    BEGIN { }

    PROCESS {
        [boolean[]]$Test = $Null
        foreach ($Field in $Fields){
            if($Field -eq $null -or $Field.Trim().Length -eq 0)
            {
               $Test += $true    
            }
        $Test += $false
        }
        if ($Test -contains $true)
        {
            return $true
        }
        else {
            return $false
        }
    }

    END { }
} #Confirm-IsEmpty
Function Add-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ServerName,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$PrinterName
    )
    BEGIN { }

    PROCESS {
        Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$ComputerName /ga /n \\$ServerName\$PrinterName" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net stop spooler" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net start spooler" -WindowStyle Hidden
    }

    END { }
} #Add-RemotePrinter

Function Remove-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ServerName,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$PrinterName
    )
    BEGIN { }

    PROCESS {
        Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$ComputerName /gd /n \\$ServerName\$PrinterName" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net stop spooler" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net start spooler" -WindowStyle Hidden
    }

    END { }
} #Remove-RemotePrinter

Function Get-RemotePrinter {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ComputerName
    )
    BEGIN { }

    PROCESS {
        Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$ComputerName /ge" -WindowStyle Hidden
    }

    END { }
} #Get-RemotePrinter

#Creates a basic Windows Form to serve as the GUI.
Function New-Form {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Set-RemotePrinter'
    $form.Size = New-Object System.Drawing.Size(400, 300)
    $form.StartPosition = 'CenterScreen'

    $TargetLabel = New-Object System.Windows.Forms.Label
    $TargetLabel.Location = New-Object System.Drawing.Point(75, 20)
    $TargetLabel.Size = New-Object System.Drawing.Size(225, 20)
    $TargetLabel.Text = 'Target Computer:'
    $form.Controls.Add($TargetLabel)

    $TargetComputerBox = New-Object System.Windows.Forms.TextBox
    $TargetComputerBox.Location = New-Object System.Drawing.Point(75, 40)
    $TargetComputerBox.Size = New-Object System.Drawing.Size(225, 20)
    $form.Controls.Add($TargetComputerBox)

    $ServerLabel = New-Object System.Windows.Forms.Label
    $ServerLabel.Location = New-Object System.Drawing.Point(75, 70)
    $ServerLabel.Size = New-Object System.Drawing.Size(225, 20)
    $ServerLabel.Text = 'Print Server:'
    $form.Controls.Add($ServerLabel)

    $PrintServerBox = New-Object System.Windows.Forms.TextBox
    $PrintServerBox.Location = New-Object System.Drawing.Point(75, 90)
    $PrintServerBox.Size = New-Object System.Drawing.Size(225, 20)
    $form.Controls.Add($PrintServerBox)

    $PrinterLabel = New-Object System.Windows.Forms.Label
    $PrinterLabel.Location = New-Object System.Drawing.Point(75, 120)
    $PrinterLabel.Size = New-Object System.Drawing.Size(225, 20)
    $PrinterLabel.Text = 'Printer Name:'
    $form.Controls.Add($PrinterLabel)

    $PrinterBox = New-Object System.Windows.Forms.TextBox
    $PrinterBox.Location = New-Object System.Drawing.Point(75, 140)
    $PrinterBox.Size = New-Object System.Drawing.Size(225, 20)
    $form.Controls.Add($PrinterBox)

    $AddButton = New-Object System.Windows.Forms.Button
    $AddButton.Location = New-Object System.Drawing.Point(75, 180)
    $AddButton.Size = New-Object System.Drawing.Size(75, 23)
    $AddButton.Text = 'Add'
    $form.Controls.Add($AddButton)

    $RemoveButton = New-Object System.Windows.Forms.Button
    $RemoveButton.Location = New-Object System.Drawing.Point(150, 180)
    $RemoveButton.Size = New-Object System.Drawing.Size(75, 23)
    $RemoveButton.Text = 'Remove'
    $form.Controls.Add($RemoveButton)

    $ViewButton = New-Object System.Windows.Forms.Button
    $ViewButton.Location = New-Object System.Drawing.Point(225, 180)
    $ViewButton.Size = New-Object System.Drawing.Size(75, 23)
    $ViewButton.Text = 'View'
    $form.Controls.Add($ViewButton)

    #Button click events.
    $AddButton.Add_Click( { 
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text,$PrintServerBox.Text,$PrinterBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A textbox is empty!",0,"Oops!",48+0)
        }
        else{
        Add-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text 
        }
    })

    $RemoveButton.Add_Click( { 
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text,$PrintServerBox.Text,$PrinterBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A textbox is empty!",0,"Oops!",48+0)
        }
        else{
        Remove-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text 
        }
    })

    $ViewButton.Add_Click( { 
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A textbox is empty!",0,"Oops!",48+0)
        }
        else{
        Get-RemotePrinter -ComputerName $TargetComputerBox.Text 
        }
    })


    #This actually creates the form as defined above and makes it visible.
    $form.ShowDialog()


} #New-Form

New-Form
