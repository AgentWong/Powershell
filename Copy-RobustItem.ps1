<#
.SYNOPSIS
Sets up Robocopy command using a GUI.
.DESCRIPTION
This leverages a GUI to setup a Robocopy command on a remote computer using psexec to ensure
that there is only a point to point connection between the remote computer and the server.
#>

# .Net methods for hiding/showing the console in the background
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

function Show-Console {
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

function Hide-Console {
    $consolePtr = [Console.Window]::GetConsoleWindow()
    #0 hide
    [Console.Window]::ShowWindow($consolePtr, 0)
} #Hide-Console


#Hides the Powershell console window.
#Comment out and call Show-Console if you need to see it.
Hide-Console

#Gets the current user account running the script.
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name


    # Self-elevate the script if required
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine -WindowStyle Hidden
        Exit
    } #Self-elevate check.

Function Confirm-IsEmpty ([string[]]$Fields) {
    #Checks whether the input is blank.
    BEGIN { }

    PROCESS {
        [boolean[]]$Test = $Null
        foreach ($Field in $Fields) {
            if ($null -eq $Field -or $Field.Trim().Length -eq 0) {
                $Test += $true    
            }
            $Test += $false
        }
        if ($Test -contains $true) {
            return $true
        }
        else {
            return $false
        }
    }

    END { }
} #Confirm-IsEmpty

Function Copy-RobustItem {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ComputerName,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$ServerPath,
        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $True)]
        [string]$LocalPath
    )
    BEGIN { }

    PROCESS {
        #The backtick is used before each double quote so it is translated in the command.
        #This properly quotes the filepath and eliminates problems with filepaths that have spaces.
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName -h robocopy `"$ServerPath`" `"$LocalPath`"  /MIR /R:1 /W:1 /MT:20 /V /ETA >> C:\Scripts\Logs\Copy-RobustItemLog.txt 2>&1"
    }

    END { }
} #Copy-RobustItem

#Creates a basic Windows Form to serve as the GUI.
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

    #Creates the form.
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Copy-RobustItem'
    $form.Size = New-Object System.Drawing.Size(400, 300)
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
    $Panel.size = '375,250'
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

    $ServerPathLabel = New-Object System.Windows.Forms.Label
    $ServerPathLabel.Location = New-Object System.Drawing.Point(75, 70)
    $ServerPathLabel.Size = New-Object System.Drawing.Size(225, 40)
    $ServerPathLabel.BackColor = "Transparent"
    $ServerPathLabel.Text = 'Source Directory UNC Path'
    $Panel.Controls.Add($ServerPathLabel)

    $ServerPathBox = New-Object System.Windows.Forms.TextBox
    $ServerPathBox.Location = New-Object System.Drawing.Point(75, 110)
    $ServerPathBox.Size = New-Object System.Drawing.Size(225, 20)
    $ServerPathBox.ForeColor = $TextboxForeColor
    $ServerPathBox.BackColor = $TextboxBackColor
    $ServerPathBox.BorderStyle = "FixedSingle"
    $Panel.Controls.Add($ServerPathBox)

    $LocalPathLabel = New-Object System.Windows.Forms.Label
    $LocalPathLabel.Location = New-Object System.Drawing.Point(75, 140)
    $LocalPathLabel.Size = New-Object System.Drawing.Size(225, 30)
    $LocalPathLabel.BackColor = "Transparent"
    $LocalPathLabel.Text = 'Local Directory Path'
    $Panel.Controls.Add($LocalPathLabel)

    $LocalPathBox = New-Object System.Windows.Forms.TextBox
    $LocalPathBox.Location = New-Object System.Drawing.Point(75, 170)
    $LocalPathBox.Size = New-Object System.Drawing.Size(225, 20)
    $LocalPathBox.ForeColor = $TextboxForeColor
    $LocalPathBox.BackColor = $TextboxBackColor
    $LocalPathBox.BorderStyle = "FixedSingle"
    $Panel.Controls.Add($LocalPathBox)

    $CopyButton = New-Object System.Windows.Forms.Button
    $CopyButton.Location = New-Object System.Drawing.Point(150, 200)
    $CopyButton.Size = New-Object System.Drawing.Size(75, 23)
    $CopyButton.BackColor = $ButtonBackColor
    $CopyButton.FlatStyle = "Flat"
    $CopyButton.Text = 'Robocopy'
    $Panel.Controls.Add($CopyButton)

    #Button click events.
    $CopyButton.Add_Click( { 
            if (Confirm-IsEmpty -Fields $TargetComputerBox.Text, $ServerPathBox.Text, $LocalPathBox.Text) {
                $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
                $wshell.Popup("A field is empty!", 0, "Oops!", 48 + 0)
            }
            elseif((Test-Connection -ComputerName $TargetComputerBox.Text -Count 1 -Quiet) -eq $false){
                $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
                $wshell.Popup("The computer is not online!", 0, "Oops!", 48 + 0)
            }
            else {
                Copy-RobustItem -ComputerName $TargetComputerBox.Text -ServerPath $ServerPathBox.Text -LocalPath $LocalPathBox.Text 
            }
        })

    #This actually creates the form as defined above and makes it visible.
    $form.ShowDialog()


} #New-Form

New-Form
