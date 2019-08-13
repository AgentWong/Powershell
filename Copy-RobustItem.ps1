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
        Start-Process -FilePath "$env:windir\System32\psexec.exe" -ArgumentList "\\$ComputerName robocopy \\$ServerPath $LocalPath"
    }

    END { }
} #Copy-RobustItem

#Creates a basic Windows Form to serve as the GUI.
Function New-Form {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Copy-RobustItem'
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

    $ServerPathLabel = New-Object System.Windows.Forms.Label
    $ServerPathLabel.Location = New-Object System.Drawing.Point(75, 70)
    $ServerPathLabel.Size = New-Object System.Drawing.Size(225, 40)
    $ServerPathLabel.Text = 'Local Netapp Path (ex: \\local-netapp1\Common_PC_Software\Autodesk\2018\Acad)'
    $form.Controls.Add($ServerPathLabel)

    $ServerPathBox = New-Object System.Windows.Forms.TextBox
    $ServerPathBox.Location = New-Object System.Drawing.Point(75, 110)
    $ServerPathBox.Size = New-Object System.Drawing.Size(225, 20)
    $form.Controls.Add($ServerPathBox)

    $LocalPathLabel = New-Object System.Windows.Forms.Label
    $LocalPathLabel.Location = New-Object System.Drawing.Point(75, 140)
    $LocalPathLabel.Size = New-Object System.Drawing.Size(225, 30)
    $LocalPathLabel.Text = 'Local Directory (ex: C:\DRV\Autodesk\2018\Acad)'
    $form.Controls.Add($LocalPathLabel)

    $LocalPathBox = New-Object System.Windows.Forms.TextBox
    $LocalPathBox.Location = New-Object System.Drawing.Point(75, 170)
    $LocalPathBox.Size = New-Object System.Drawing.Size(225, 20)
    $form.Controls.Add($LocalPathBox)

    $CopyButton = New-Object System.Windows.Forms.Button
    $CopyButton.Location = New-Object System.Drawing.Point(150, 200)
    $CopyButton.Size = New-Object System.Drawing.Size(75, 23)
    $CopyButton.Text = 'Robocopy'
    $form.Controls.Add($CopyButton)

    $form.Topmost = $true

    #Button click events.
    $CopyButton.Add_Click( { Copy-RobustItem -ComputerName $TargetComputerBox.Text -ServerPath $ServerPathBox.Text -LocalPath $LocalPathBox.Text })

    #This actually creates the form as defined above and makes it visible.
    $form.ShowDialog()


} #New-Form

New-Form
