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
    #Show the Powershell console when called.
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
} #Show-Console

function Hide-Console
{
    #Hides the Powershell console window when called.
    $consolePtr = [Console.Window]::GetConsoleWindow()
    #0 hide
    [Console.Window]::ShowWindow($consolePtr, 0)
} #Hide-Console


#Hides the Powershell console window.
#Comment out and call Show-Console if you need to see it.
Hide-Console

#Gets the current user account running the script.
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Checks if the account running has certain text in its name, if not, it will relaunch the script as an administrator.
if ($CurrentUser -notlike "*z0*") {
    # Self-elevate the script if required
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine -WindowStyle Hidden
        Exit
    }
} #Self-elevate check.

Function Confirm-IsEmpty ([string[]]$Fields){
    #Checks whether the input is blank.
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

Function Add-OutputBoxLine {
    #Adds messages to the Status textbox.
    Param ($Message)
    $StatusBox.AppendText("$Message`r`n")
    $StatusBox.Refresh()
    $StatusBox.ScrollToCaret()
} #Add-OutputBoxLine

Function Add-RemotePrinter {
    #Adds a printer using rundll32 printui.dll,PrintUIEntry.
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
        Add-OutputBoxLine -Message "Adding printer $PrinterName on $Computername"
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net stop spooler" -WindowStyle Hidden
        Add-OutputBoxLine -Message "Stopping spooler on $ComputerName"
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net start spooler" -WindowStyle Hidden
        Add-OutputBoxLine -Message "Starting spooler on $ComputerName"
    }

    END { }
} #Add-RemotePrinter

Function Remove-RemotePrinter {
    #Removes a printer that was added using rundll32 printui.dll,PrintUIEntry.
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
        Add-OutputBoxLine -Message "Removing printer $PrinterName on $Computername"
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net stop spooler" -WindowStyle Hidden
        Add-OutputBoxLine -Message "Stopping spooler on $ComputerName"
        Start-Sleep -Seconds 3
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName cmd /c net start spooler" -WindowStyle Hidden
        Add-OutputBoxLine -Message "Starting spooler on $ComputerName"
    }

    END { }
} #Remove-RemotePrinter

Function Get-RemotePrinter {
    #Views printers that were added using rundll32 printui.dll,PrintUIEntry.
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ComputerName
    )
    BEGIN { }

    PROCESS {
        Start-Process -FilePath "$env:windir\System32\rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /c \\$ComputerName /ge" -WindowStyle Hidden
        Add-OutputBoxLine -Message "Viewing installed printers on $ComputerName"
    }

    END { }
} #Get-RemotePrinter

Function New-Form {
    #Load Assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    #Store form colors in variables.
    $FormBackColor = "#222222"
    $FormForeColor = "#c5c9ca"
    $PanelBackColor = "#3b3f42"
    $TextboxBackColor = "#2b2b2b"
    $TextboxForeColor = "#c3803c"
    $ButtonBackColor = "#2e4058"

    #Create a form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Set-RemotePrinter'
    $form.Size = New-Object System.Drawing.Size(400, 340)
    $form.StartPosition = 'CenterScreen'
    $Form.Opacity = 1 #0.95
    $Form.BackColor = $FormBackColor
    $Form.ForeColor = $FormForeColor
    $form.formborderstyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    #Panel to group form objects.
    $Panel = New-Object Windows.Forms.Panel
    $Panel.Location = '5,5'
    $Panel.size = '375,290'
    $Panel.BackColor = $PanelBackColor
    $Form.Controls.Add($Panel)

    $TargetLabel = New-Object System.Windows.Forms.Label
    $TargetLabel.Location = New-Object System.Drawing.Point(75, 20)
    $TargetLabel.Size = New-Object System.Drawing.Size(225, 20)
    $TargetLabel.BackColor = "Transparent"
    $TargetLabel.Text = 'Target Computer:'
    $Panel.Controls.Add($TargetLabel)

    $TargetComputerBox = New-Object System.Windows.Forms.TextBox
    $TargetComputerBox.Location = New-Object System.Drawing.Point(75, 40)
    $TargetComputerBox.Size = New-Object System.Drawing.Size(225, 20)
    $TargetComputerBox.ForeColor = $TextboxForeColor
    $TargetComputerBox.BackColor = $TextboxBackColor
    $TargetComputerBox.BorderStyle = "FixedSingle"
    $Panel.Controls.Add($TargetComputerBox)

    $ServerLabel = New-Object System.Windows.Forms.Label
    $ServerLabel.Location = New-Object System.Drawing.Point(75, 70)
    $ServerLabel.Size = New-Object System.Drawing.Size(225, 20)
    $ServerLabel.BackColor = "Transparent"
    $ServerLabel.Text = 'Print Server:'
    $Panel.Controls.Add($ServerLabel)

    $PrintServerBox = New-Object System.Windows.Forms.TextBox
    $PrintServerBox.Location = New-Object System.Drawing.Point(75, 90)
    $PrintServerBox.Size = New-Object System.Drawing.Size(225, 20)
    $PrintServerBox.ForeColor = $TextboxForeColor
    $PrintServerBox.BackColor = $TextboxBackColor
    $PrintServerBox.BorderStyle = "FixedSingle"
    $Panel.Controls.Add($PrintServerBox)

    $PrinterLabel = New-Object System.Windows.Forms.Label
    $PrinterLabel.Location = New-Object System.Drawing.Point(75, 120)
    $PrinterLabel.Size = New-Object System.Drawing.Size(225, 20)
    $PrinterLabel.BackColor = "Transparent"
    $PrinterLabel.Text = 'Printer Name:'
    $Panel.Controls.Add($PrinterLabel)

    $PrinterBox = New-Object System.Windows.Forms.TextBox
    $PrinterBox.Location = New-Object System.Drawing.Point(75, 140)
    $PrinterBox.Size = New-Object System.Drawing.Size(225, 20)
    $PrinterBox.ForeColor = $TextboxForeColor
    $PrinterBox.BackColor = $TextboxBackColor
    $PrinterBox.BorderStyle = "FixedSingle"
    $Panel.Controls.Add($PrinterBox)

    $AddButton = New-Object System.Windows.Forms.Button
    $AddButton.Location = New-Object System.Drawing.Point(75, 180)
    $AddButton.Size = New-Object System.Drawing.Size(75, 23)
    $AddButton.BackColor = $ButtonBackColor
    $AddButton.FlatStyle = "Flat"
    $AddButton.Text = 'Add'
    $Panel.Controls.Add($AddButton)

    $RemoveButton = New-Object System.Windows.Forms.Button
    $RemoveButton.Location = New-Object System.Drawing.Point(150, 180)
    $RemoveButton.Size = New-Object System.Drawing.Size(75, 23)
    $RemoveButton.BackColor = $ButtonBackColor
    $RemoveButton.FlatStyle = "Flat"
    $RemoveButton.Text = 'Remove'
    $Panel.Controls.Add($RemoveButton)

    $ViewButton = New-Object System.Windows.Forms.Button
    $ViewButton.Location = New-Object System.Drawing.Point(225, 180)
    $ViewButton.Size = New-Object System.Drawing.Size(75, 23)
    $ViewButton.BackColor = $ButtonBackColor
    $ViewButton.FlatStyle = "Flat"
    $ViewButton.Text = 'View'
    $Panel.Controls.Add($ViewButton)

    #Outputs status messages to the user.
    $StatusBox = New-Object System.Windows.Forms.TextBox
    $StatusBox.Location = New-Object System.Drawing.Point(40, 220)
    $StatusBox.Size = New-Object System.Drawing.Size(295, 60)
    $StatusBox.ForeColor = $TextboxForeColor
    $StatusBox.BackColor = $TextboxBackColor
    $StatusBox.BorderStyle = "FixedSingle"
    $StatusBox.ReadOnly = $true
    $StatusBox.Multiline = $true
    $Panel.Controls.Add($StatusBox)

    #Button click events.
    $AddButton.Add_Click( { 
        $StatusBox.Clear()
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text,$PrintServerBox.Text,$PrinterBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A field is empty!",0,"Oops!",48+0)
        }
        else{
        Add-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text -Verbose
        }
    })

    $RemoveButton.Add_Click( { 
        $StatusBox.Clear()
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text,$PrintServerBox.Text,$PrinterBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A field is empty!",0,"Oops!",48+0)
        }
        else{
        Remove-RemotePrinter -ComputerName $TargetComputerBox.Text -ServerName $PrintServerBox.Text -PrinterName $PrinterBox.Text 
        }
    })

    $ViewButton.Add_Click( { 
        $StatusBox.Clear()
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text){
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            $wshell.Popup("A field is empty!",0,"Oops!",48+0)
        }
        else{
        Get-RemotePrinter -ComputerName $TargetComputerBox.Text 
        }
    })


    #This actually creates the form as defined above and makes it visible.
    $form.ShowDialog()


} #New-Form

New-Form
