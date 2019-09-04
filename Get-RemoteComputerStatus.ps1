<#
.SYNOPSIS
A proof-of-concept scanning tool intended to speed up scanning of WMI/CIM information.

.DESCRIPTION
An experimental script meant to execute data gathering queries on the remote computer in question using Invoke-Command and runspaces.
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
    #Hides the Powershell console window when called.
    $consolePtr = [Console.Window]::GetConsoleWindow()
    #0 hide
    [Console.Window]::ShowWindow($consolePtr, 0)
} #Hide-Console


#Hides the Powershell console window.
#Comment out and call Show-Console if you need to see it.
Show-Console


# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine -WindowStyle Hidden
    Exit
}
Import-Module ActiveDirectory

#Functions

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

Function Add-OutputBoxLine {
    #Adds messages to the Status textbox.
    Param ($Message)
    [string]$OutMessage = $Message
    $StatusBox.AppendText("$OutMessage`r`n")
} #Add-OutputBoxLine

Function Get-RemoteComputerInfo {
    BEGIN { 
        #region Runspace Pool

        $RunspacePool = [runspacefactory]::CreateRunspacePool(

            1, #Min Runspaces

            [int]$env:NUMBER_OF_PROCESSORS + 1 #Max Runspaces

        )
        $RunspacePool.ApartmentState = "STA"
        $RunspacePool.ThreadOptions = "ReuseThread"
        [void]$RunspacePool.Open()

        $Jobs = @()
    }

    PROCESS {
            
        #-------------------------------------------------Main Instance Queries---------------------------------------------------------------#
            

        #Win32_ComputerSystem
        $ComputerSystemJob = [powershell]::Create()
        [void]$ComputerSystemJob.AddScript( { Get-CimInstance -ClassName Win32_ComputerSystem -Property UserName, Model, Manufacturer, Name } )
        $ComputerSystemJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'ComputerSystem'
            Pipe   = $ComputerSystemJob;
            Status = $ComputerSystemJob.BeginInvoke()
        }

        #Win32_OperatingSystem
        $OperatingSystemJob = [powershell]::Create()
        [void]$OperatingSystemJob.AddScript( { Get-CimInstance -ClassName Win32_OperatingSystem })
        $OperatingSystemJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'OperatingSystem'
            Pipe   = $OperatingSystemJob
            Status = $OperatingSystemJob.BeginInvoke()
        }

        #Win32_BIOS
        $BIOSJob = [powershell]::Create()
        [void]$BIOSJob.AddScript( { Get-CimInstance -ClassName Win32_BIOS } )
        $BIOSJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'BIOS'
            Pipe   = $BIOSJob
            Status = $BIOSJob.BeginInvoke()
        }

        #Disk space
        $DiskJob = [powershell]::Create()
        [void]$DiskJob.AddScript( { Get-CimInstance -ClassName Win32_LogicalDisk -Filter `
                    "name='C:'" })
        $DiskJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Disk'
            Pipe   = $DiskJob
            Status = $DiskJob.BeginInvoke()
        }

        #User Profiles
        $UserProfilesJob = [powershell]::Create()
        [void]$UserProfilesJob.AddScript( { Get-CimInstance -ClassName Win32_UserProfile | 
                Measure-Object | Select-Object -ExpandProperty Count } )
        $UserProfilesJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'UserProfiles'
            Pipe   = $UserProfilesJob
            Status = $UserProfilesJob.BeginInvoke()
        }

        #Network Adapter
        $NetAdapterJob = [powershell]::Create()
        [void]$NetAdapterJob.AddScript( { Get-CimInstance -ClassName Win32_NetworkAdapter | 
                Where-Object { ($null -ne $_.NetConnectionID) -and ($true -eq $_.NetEnabled) } | Select-Object -First 1 } )
        $NetAdapterJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'NetAdapter'
            Pipe   = $NetAdapterJob
            Status = $NetAdapterJob.BeginInvoke()
        }

        #Net Adapter Configuration
        $NetAdapterConfigJob = [powershell]::Create()
        [void]$NetAdapterConfigJob.AddScript( { Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                Where-Object { $null -ne $_.IPAddress } } )
        $NetAdapterConfigJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'NetAdapterConfig'
            Pipe   = $NetAdapterConfigJob
            Status = $NetAdapterConfigJob.BeginInvoke()
        }

        #---------------------------------------------------------------Selective Queries---------------------------------------------------------------------
            
        #Lock screen
        $LockJob = [powershell]::Create()
        [void]$LockJob.AddScript( { Get-CimInstance -ClassName Win32_Process -Filter `
                    "name='logonui.exe'" | Select-Object -ExpandProperty Name } )
        $LockJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Lock'
            Pipe   = $LockJob
            Status = $LockJob.BeginInvoke()
        }

        #Secure Boot
        $SecureBootJob = [powershell]::Create()
        [void]$SecureBootJob.AddScript( `
            { Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\control\SecureBoot\State" -Name "UEFISecureBootEnabled" | Select-Object -ExpandProperty "UEFISecureBootEnabled" } )
        $SecureBootJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'SecureBoot'
            Pipe   = $SecureBootJob
            Status = $SecurebootJob.BeginInvoke()
        }

        #Bitlocker
        $BitlockerJob = [powershell]::Create()
        [void]$BitlockerJob.AddScript( { Get-CimInstance -NameSpace "root/CIMV2/Security/MicrosoftVolumeEncryption" `
                    -ClassName Win32_EncryptableVolume -Filter "driveletter='C:'" } )
        $BitlockerJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Bitlocker'
            Pipe   = $BitlockerJob
            Status = $BitlockerJob.BeginInvoke()
        }

        #----------------------------------SCCM-----------------------------------#
        $SCCMVersionJob = [powershell]::Create()
        [void]$SCCMVersionJob.AddScript(`
            { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client" -Name "ProductVersion" | Select-Object -ExpandProperty "ProductVersion" } )
        $SCCMVersionJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'SCCMVersion'
            Pipe   = $SCCMVersionJob
            Status = $SCCMVersionJob.BeginInvoke()
        }

        $SCCMInfoJob = [powershell]::Create()
        [void]$SCCMInfoJob.AddScript( {
                $UpdateSession = [activator]::CreateInstance([type]::GetTypeFromProgID("Microsoft.Update.Session"))
                $Searcher = $UpdateSession.CreateupdateSearcher()
                $HistoryCount = $Searcher.GetTotalHistoryCount()
                $Searcher.QueryHistory(0, $HistoryCount) | Select-Object Title, Date
            } )
        $SCCMInfoJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'SCCMInfo'
            Pipe   = $SCCMInfoJob
            Status = $SCCMInfoJob.BeginInvoke()
        }

        #Reboot Required
        $RebootPendingJob = [powershell]::Create()
        [void]$RebootPendingJob.AddScript( `
            { Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" } )
        $RebootPendingJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'RebootPending'
            Pipe   = $RebootPendingJob
            Status = $RebootPendingJob.BeginInvoke()
        }

        #CcmExec
        $CcmExecJob = [powershell]::Create()
        [void]$CcmExecJob.AddScript( { Get-CimInstance -ClassName Win32_Service -Filter `
                    "name='CcmExec'" } )
        $CcmExecJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'CcmExec'
            Pipe   = $CcmExecJob
            Status = $CcmExecJob.BeginInvoke()
        }

        #Bits
        $BitsJob = [powershell]::Create()
        [void]$BitsJob.AddScript( { Get-CimInstance -ClassName Win32_Service -Filter `
                    "name='bits'" } )
        $BitsJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Bits'
            Pipe   = $BitsJob
            Status = $BitsJob.BeginInvoke()
        }

        #Winmgmt
        $WinmgmtJob = [powershell]::Create()
        [void]$WinmgmtJob.AddScript( { Get-CimInstance -ClassName Win32_Service -Filter `
                    "name='Winmgmt'" } )
        $WinmgmtJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Winmgmt'
            Pipe   = $WinmgmtJob
            Status = $WinmgmtJob.BeginInvoke()
        }

        #Wuauserv
        $WuauservJob = [powershell]::Create()
        [void]$WuauservJob.AddScript( { Get-CimInstance -ClassName Win32_Service -Filter `
                    "name='Wuauserv'" } )
        $WuauservJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'Wuauserv'
            Pipe   = $WuauservJob
            Status = $WuauservJob.BeginInvoke()
        }

        #SCCM Last Error
        $SCCMLastErrorJob = [powershell]::Create()
        [void]$SCCMLastErrorJob.AddScript( { Get-CimInstance -ClassName Win32_Directory -Filter `
                    "name='C:\\Windows\\ccmsetup\\LastError'" })
        $SCCMLastErrorJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'SCCMLastError'
            Pipe   = $SCCMLastErrorJob
            Status = $SCCMLastErrorJob.BeginInvoke()
        }

        #-----------------------------------------DNS------------------------------------------#
        $DNSSuffixJob = [powershell]::Create()
        [void]$DNSSuffixJob.AddScript( `
            { Get-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters" -Name "SearchList" | Select-Object -ExpandProperty "SearchList" } )
        $DNSSuffixJob.RunspacePool = $RunspacePool
        $Jobs += [PSCustomObject]@{
            Name   = 'DNSSuffix'
            Pipe   = $DNSSuffixJob
            Status = $DNSSuffixJob.BeginInvoke()
        }

        #Wait for parallel jobs to finish.
        while ($Jobs.Status.IsCompleted -notcontains $true) { Start-Sleep -Milliseconds 500 }

        #Receive results of jobs.
        $ComputerSystemResult = $Jobs | Where-Object { $_.Name -eq 'ComputerSystem' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $OperatingSystemResult = $Jobs | Where-Object { $_.Name -eq 'OperatingSystem' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $BIOSResult = $Jobs | Where-Object { $_.Name -eq 'BIOS' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $DiskResult = $Jobs | Where-Object { $_.Name -eq 'Disk' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $LockResult = $Jobs | Where-Object { $_.Name -eq 'Lock' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $UserProfilesResult = $Jobs | Where-Object { $_.Name -eq 'UserProfiles' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $NetAdapterResult = $Jobs | Where-Object { $_.Name -eq 'NetAdapter' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $NetAdapterConfigResult = @()
        $NetAdapterConfigResult = $Jobs | Where-Object { $_.Name -eq 'NetAdapterConfig' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $SecureBootResult = $Jobs | Where-Object { $_.Name -eq 'SecureBoot' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $BitlockerResult = $Jobs | Where-Object { $_.Name -eq 'Bitlocker' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $SCCMVersionResult = $Jobs | Where-Object { $_.Name -eq 'SCCMVersion' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $SCCMInfoResult = $Jobs | Where-Object { $_.Name -eq 'SCCMInfo' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $RebootPendingResult = $Jobs | Where-Object { $_.Name -eq 'RebootPending' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $CcmExecResult = $Jobs | Where-Object { $_.Name -eq 'CcmExec' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $BitsResult = $Jobs | Where-Object { $_.Name -eq 'Bits' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $WinmgmtResult = $Jobs | Where-Object { $_.Name -eq 'Winmgmt' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $WuauservResult = $Jobs | Where-Object { $_.Name -eq 'Wuauserv' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        $SCCMLastErrorResult = $Jobs | Where-Object { $_.Name -eq 'SCCMLastError' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
        [string]$DNSSuffixResult = $Jobs | Where-Object { $_.Name -eq 'DNSSuffix' } | ForEach-Object { $_.Pipe.EndInvoke($_.Status); $_.Pipe.Dispose() }
            
        #Pre-Evaluation

        #VPN check
        $IsVPN = $null
        $VPNAdapter = $null
        ForEach ($NetAdapterConfigItem in $NetAdapterConfigResult) {
            if ($NetAdapterConfigItem.Description -like "*AnyConnect*") {
                $IsVPN = $true
                $VPNAdapter = $NetAdapterConfigItem
            }
        }

        #Expands and defines properties.
        $UserNamePre = $ComputerSystemResult | Select-Object -ExpandProperty UserName
        $UserName = $UserNamePre -replace '(.*[\\\/])', ''
        $Manufacturer = $ComputerSystemResult | Select-Object -ExpandProperty Manufacturer
        $Model = $ComputerSystemResult | Select-Object -ExpandProperty Model
        $FinalModel = "$Manufacturer $Model"
        $HostName = $ComputerSystemResult | Select-Object -ExpandProperty Name
        $NetSpeed = ($NetAdapterResult | Select-Object -ExpandProperty Speed) / 1000000
        $OS = $OperatingSystemResult | Select-Object -ExpandProperty Caption
        $Version = $OperatingSystemResult | Select-Object -ExpandProperty Version
        $CurrentTime = $OperatingSystemResult | Select-Object -ExpandProperty LocalDateTime
        $InstallDate = $OperatingSystemResult | Select-Object -ExpandProperty InstallDate
        $LastBoot = $OperatingSystemResult | Select-Object -ExpandProperty LastBootUpTime
        $OSFinal = "$OS $Version"
        $Serial = $BIOSResult | Select-Object -ExpandProperty SerialNumber
        $BIOSVersion = $BIOSResult | Select-Object -ExpandProperty Caption
        $BIOSRelease = $BIOSResult | Select-Object -ExpandProperty ReleaseDate
        $BIOSVersionFinal = "$BIOSVersion (Release Date $BIOSRelease)"
        $FreeSpace = ($DiskResult | Select-Object -ExpandProperty FreeSpace) / 1GB
        $DiskSize = ($DiskResult | Select-Object -ExpandProperty size) / 1GB
        $FreeSpaceFormat = [math]::round($FreeSpace, 0)
        $Percent = $FreeSpace / $DiskSize
        $FinalPercent = "{0:P}" -f $Percent
        $FreeDiskSpace = "$FinalPercent, $FreeSpaceFormat GB"
        $CcmExecResultCalc = $CcmExecResult | Select-Object Name, StartMode, State, Status
        $CcmExec = $CcmExecResultCalc.StartMode + " / " + $CcmExecResultCalc.State + " / " + $CcmExecResultCalc.Status
        $BitsResultCalc = $BitsResult | Select-Object Name, StartMode, State, Status
        $Bits = $BitsResultCalc.StartMode + " / " + $BitsResultCalc.State + " / " + $BitsResultCalc.Status
        $WinmgmtResultCalc = $WinmgmtResult | Select-Object Name, StartMode, State, Status
        $Winmgmt = $WinmgmtResultCalc.StartMode + " / " + $WinmgmtResultCalc.State + " / " + $WinmgmtResultCalc.Status
        $WuauservResultCalc = $WuauservResult | Select-Object Name, StartMode, State, Status
        $Wuauserv = $WuauservResultCalc.StartMode + " / " + $WuauservResultCalc.State + " / " + $WuauservResultCalc.Status

        #--------------------------Evaluate-------------------------#

        #Lock Screen
        if ($null -eq $LockResult) {
            $Screen = "Unlocked and in use."
        }
        else {
            $Screen = "Locked."
        }

        #Bitlocker

        if ($BitlockerResult.ProtectionStatus -eq 1) {
            $BitlockerStatus = "On"
        }
        else {
            if ($BitlockerResult.IsVolumeInitializedForProtection -eq $true) {
                $BitlockerStatus = "Suspended"
            }
            else {
                $BitlockerStatus = "Off"
            }
        }
        if ($BitlockerResult.ConversionStatus -eq 1) {
            $BitlockerConversion = "Fully Encrypted"
        }
        elseif ($BitlockerResult.ConversionStatus -eq 3) {
            $BitlockerConversion = "Decryption in Progress"
        }
        elseif ($BitlockerResult.ConversionStatus -eq 0) {
            $BitlockerConversion = "Fully Decrypted"
        }
        else {
            $BitlockerConversion = "Encryption in Progress"
        }

        #Secure Boot
        if ($SecureBootResult -eq 1) {
            $SecureBoot = "Enabled"
        }
        else {
            $SecureBoot = "Disabled"
        }
        #Connection type
        if ($IsVPN) {
            $NetConnectType = "VPN"
            $IPAddressArr = @()
            $IPAddressArr = $VPNAdapter | Select-Object -ExpandProperty IPAddress
            $IPAddress = $IPAddressArr[0]
        }
        else {
            $NetConnectType = $NetAdapterResult | Select-Object -First 1 -ExpandProperty NetConnectionID
            $IPAddressArr = @()
            $IPAddressArr = $NetAdapterConfigResult[0] | Select-Object -ExpandProperty IPAddress
            $IPAddress = $IPAddressArr[0]
        }
        #SCCM Status
        if (($null -ne $SCCMVersionResult) -and ($null -eq $SCCMLastErrorResult)) {
            $SCCMStatus = "OK"
        }
        else {
            $SCCMStatus = "ERROR"
        }
        #SCCM Folder Date
        $LastDate = $null
        $LastUpdate = $null
        foreach ($Update in $SCCMInfoResult) {
            if (($Update.Date -ge $LastDate) -or ($null -eq $LastDate)) {
                $LastUpdate = $Update.Title
                $LastDate = $Update.Date
            }
        }
        #Reboot Pending
        if ($RebootPendingResult -eq 1) {
            $RebootPending = "Yes"
        }
        else {
            $RebootPending = "No"
        }
        #DNS
        if ($null -eq $DNSSuffixResult) {
            $DNSSuffix = "DNS Suffixes NOT CONFIGURED"
        }
        else {
            $DNSSuffix = $DNSSuffixResult -Split ","
        }
            
        $NetConnectTypeFinal = "$NetConnectType $NetSpeed Mbps"

        [PSCustomObject]@{
            'UserName'            = $UserName
            'HostName'            = $HostName
            'Screen'              = $Screen
            'UserProfiles'        = $UserProfilesResult
            'Model'               = $FinalModel
            'IPAddress'           = $IPAddress
            'OS'                  = $OSFinal
            'Serial'              = $Serial
            'BIOSVersion'         = $BIOSVersionFinal
            'CurrentTime'         = $CurrentTime
            'InstallDate'         = $InstallDate
            'NetConnectType'      = $NetConnectTypeFinal
            'LastBootTime'        = $LastBoot
            'FreeDiskSpace'       = $FreeDiskSpace
            'SecureBoot'          = $SecureBoot
            'BitlockerStatus'     = $BitlockerStatus
            'BitlockerConversion' = $BitlockerConversion
            'SCCMStatus'          = $SCCMStatus
            'SCCMVersion'         = $SCCMVersionResult
            'SCCMUpdate'          = $LastUpdate
            'SCCMLastDate'        = $LastDate
            'RebootPending'       = $RebootPending
            'CcmExec'             = $CcmExec
            'Bits'                = $Bits
            'Winmgmt'             = $Winmgmt
            'Wuauserv'            = $Wuauserv
            'DNSSuffix'           = $DNSSuffix
        }
    }
    END { 
        #Cleans up the jobs.
        [void]$RunspacePool.Close()
        [void]$RunspacePool.Dispose()
        [GC]::Collect()
    }
}

Function Set-TextBlock {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Object]$TextBlock,
        [Parameter(Mandatory = $true)]
        [String]$Text
    )
    $TextBlock.Text = $Text
}

Function Clear-TextBlock {
    $LoggedOnUserTextBlock.Text = ""
    $UserADDescTextBlock.Text = ""
    $ComputerADDescTextBlock.Text = ""
    $HostNameTextBlock.Text = ""
    $DisplayStatusTextBlock.Text = ""
    $UserProfilesTextBlock.Text = ""
    $ModelTextBlock.Text = ""
    $IPAddressTextBlock.Text = ""
    $OSTextBlock.Text = ""
    $ServiceTagTextBlock.Text = ""
    $BIOSVersionTextBlock.Text = ""
    $CurrentTimeTextBlock.Text = ""
    $OSInstallDateTextBlock.Text = ""
    $NetConnectionTextBlock.Text = ""
    $PingTextBlock.Text = ""
    $LastBootTextBlock.Text = ""
    $FreeSpaceTextBlock.Text = ""
    $BIOSSecureBootTextBlock.Text = ""
    $BitlockerStatusTextBlock.Text = ""
    $BitlockerConversionTextBlock.Text = ""
    $SCCMStatusTextBlock.Text = ""
    $SCCMVersionTextBlock.Text = ""
    $SCCMLastDateTextBlock.Text = ""
    $SCCMLastUpdateTextBlock.Text = ""
    $RebootPendingTextBlock.Text = ""
    $CcmExecTextBlock.Text = ""
    $BitsTextBlock.Text = ""
    $WinmgmtTextBlock.Text = ""
    $WuauservTextBlock.Text = ""
    [void]$DNSListBox.Clear()
}

#GUI Elements
#The form was designed in Visual Studio 2019 Community Edition.  The GUI is helpful for initial setup, although adding repeated controls is easier by manipulating the XML code directly.
#This leverages Windows Presentation Framework and is largely recommended over WinForms.
Add-Type -AssemblyName PresentationFramework
[xml]$xaml = @"
<Window x:Name="Get_ComputerStatus"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Get-RemoteComputerStatus" Height="1000" Width="564.5" Foreground="#c5c9ca" Background="#FF222222" ResizeMode="NoResize" FontFamily="Segoe UI Semibold">
    <Window.Resources>
        <Style TargetType="TextBlock" >
            <Setter Property="Foreground" Value="#00FFFF" />
            <Setter Property="FontSize" Value="12" />
        </Style>
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="#c5c9ca" />
            <Setter Property="FontSize" Value="12" />
        </Style>
        <Style TargetType="Button">
            <Setter Property="FontSize" Value="12" />
            <Setter Property="Foreground" Value="#c5c9ca" />
            <Setter Property="Background" Value="#2e4058" />
        </Style>
    </Window.Resources>
    <ScrollViewer>
        <Grid Width="558">
            <Label x:Name="TargetComputerLabel" Content="Target Computer:" HorizontalAlignment="Left" Margin="108,14,0,0" VerticalAlignment="Top"/>
            <TextBox x:Name="TargetComputerTextBox" Foreground="#c3803c" Background="#2b2b2b" HorizontalAlignment="Left" Height="20" Margin="108,40,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="300"/>
            <Button x:Name="ScanButton" Content="Scan Computer" HorizontalAlignment="Left" Margin="108,80,0,0" VerticalAlignment="Top" Width="145" Height="24"/>
            <Button x:Name="CopyButton" Content="Copy Hostname" HorizontalAlignment="Left" Margin="263,80,0,0" VerticalAlignment="Top" Width="145" Height="24"/>
            <GroupBox x:Name="UserInfoGroupBox" Header="User Info" HorizontalAlignment="Left" Height="125" Margin="10,115,0,0" VerticalAlignment="Top" Width="515">
                <Grid x:Name="UserInfoGrid" HorizontalAlignment="Left" Height="105" VerticalAlignment="Top" Width="505" Margin="0,0,0,0">
                    <Label x:Name="LoggedOnUserLabel" Content="Logged On User:" HorizontalAlignment="Left" Margin="10,5,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="LoggedOnUserTextBlock" HorizontalAlignment="Left" Margin="200,10,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="ComputerADDescLabel" Content="Computer AD Description:" HorizontalAlignment="Left" Margin="10,20,0,0" VerticalAlignment="Top" RenderTransformOrigin="-0.354,0.044"/>
                    <TextBlock x:Name="ComputerADDescTextBlock" HorizontalAlignment="Left" Margin="200,25,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="UserADDescLabel" Content="User AD Description:" HorizontalAlignment="Left" Margin="10,48,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="UserADDescTextBlock" HorizontalAlignment="Left" Margin="200,53,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="DisplayStatusLabel" Content="Display Status:" HorizontalAlignment="Left" Margin="10,80,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="DisplayStatusTextBlock" HorizontalAlignment="Left" Margin="200,85,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                </Grid>
            </GroupBox>
            <GroupBox x:Name="MachineInfoGroupBox" Header="Machine Info" HorizontalAlignment="Left" Height="291" Margin="10,250,0,0" VerticalAlignment="Top" Width="515">
                <Grid x:Name="MachineInfoGrid" HorizontalAlignment="Left" Height="281" VerticalAlignment="Top" Width="505" Margin="0,0,0,0">
                    <Label x:Name="HostNameLabel" Content="Hostname:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="HostnameTextBlock" HorizontalAlignment="Left" Margin="200,15,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="UserProfilesLabel" Content="User Profiles:" HorizontalAlignment="Left" Margin="10,25,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="UserProfilesTextBlock" HorizontalAlignment="Left" Margin="200,30,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="ModelLabel" Content="Model:" HorizontalAlignment="Left" Margin="10,40,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="ModelTextBlock" HorizontalAlignment="Left" Margin="200,45,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="IPAddressLabel" Content="IP Address:" HorizontalAlignment="Left" Margin="9,55,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="IPAddressTextBlock" HorizontalAlignment="Left" Margin="200,60,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="OS" Content="OS:" HorizontalAlignment="Left" Margin="10,70,0,0" VerticalAlignment="Top" RenderTransformOrigin="0.154,0.401"/>
                    <TextBlock x:Name="OSTextBlock" HorizontalAlignment="Left" Margin="200,75,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="ServiceTagLabel" Content="Service Tag:" HorizontalAlignment="Left" Margin="10,85,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="ServiceTagTextBlock" HorizontalAlignment="Left" Margin="200,90,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="BIOSVersionLabel" Content="BIOS Version:" HorizontalAlignment="Left" Margin="10,100,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="BIOSVersionTextBlock" HorizontalAlignment="Left" Margin="200,105,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="BIOSSecureBootLabel" Content="BIOS Secure Boot:" HorizontalAlignment="Left" Margin="10,115,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="BIOSSecureBootTextBlock" HorizontalAlignment="Left" Margin="200,120,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="CurrentTimeLabel" Content="Current Time:" HorizontalAlignment="Left" Margin="10,130,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="CurrentTimeTextBlock" HorizontalAlignment="Left" Margin="200,135,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="OSInstallDateLabel" Content="OS Install Date:" HorizontalAlignment="Left" Margin="10,145,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="OSInstallDateTextBlock" HorizontalAlignment="Left" Margin="200,150,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="NetConnectionLabel" Content="Network Connection Type:" HorizontalAlignment="Left" Margin="10,160,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="NetConnectionTextBlock" HorizontalAlignment="Left" Margin="200,165,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="PingLabel" Content="Ping Latency:" HorizontalAlignment="Left" Margin="10,175,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="PingTextBlock" HorizontalAlignment="Left" Margin="200,180,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Grid.Column="1"/>
                    <Label x:Name="LastBootLabel" Content="Last Boot Time:" HorizontalAlignment="Left" Margin="10,190,0,0" VerticalAlignment="Top" Grid.ColumnSpan="2"/>
                    <TextBlock x:Name="LastBootTextBlock" HorizontalAlignment="Left" Margin="200,195,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="FreeSpaceLabel" Content="Free Space:" HorizontalAlignment="Left" Margin="10,205,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="FreeSpaceTextBlock" HorizontalAlignment="Left" Margin="200,210,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="BitlockerStatusLabel" Content="Bitlocker Status:" HorizontalAlignment="Left" Margin="10,220,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="BitlockerStatusTextBlock" HorizontalAlignment="Left" Margin="200,225,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="BitlockerConversionLabel" Content="Bitlocker Conversion:" HorizontalAlignment="Left" Margin="10,235,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="BitlockerConversionTextBlock" HorizontalAlignment="Left" Margin="200,240,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                </Grid>
            </GroupBox>
            <GroupBox x:Name="SCCMGroupBox" Header="SCCM" HorizontalAlignment="Left" Height="199" Margin="10,546,0,0" VerticalAlignment="Top" Width="515">
                <Grid x:Name="SCCMGrid" HorizontalAlignment="Left" Height="172" VerticalAlignment="Top" Width="505" Margin="0,0,0,0">
                    <Label x:Name="SCCMStatusLabel" Content="SCCM:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="SCCMStatusTextBlock" HorizontalAlignment="Left" Margin="200,15,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="SCCMVersionLabel" Content="SCCM Version:" HorizontalAlignment="Left" Margin="10,25,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="SCCMVersionTextBlock" HorizontalAlignment="Left" Margin="200,30,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="SCCMLastDateLabel" Content="Last SCCM Download Date:" HorizontalAlignment="Left" Margin="10,40,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="SCCMLastDateTextBlock" HorizontalAlignment="Left" Margin="200,45,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="SCCMLastUpdateLabel" Content="Last SCCM Update:" HorizontalAlignment="Left" Margin="10,55,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="SCCMLastUpdateTextBlock" HorizontalAlignment="Left" Margin="200,60,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="RebootPendingLabel" Content="Reboot Pending:" HorizontalAlignment="Left" Margin="10,85,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="RebootPendingTextBlock" HorizontalAlignment="Left" Margin="200,90,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="CcmExecLabel" Content="CcmExec:" HorizontalAlignment="Left" Margin="10,100,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="CcmExecTextBlock" HorizontalAlignment="Left" Margin="200,105,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="BitsLabel" Content="Bits:" HorizontalAlignment="Left" Margin="10,115,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="BitsTextBlock" HorizontalAlignment="Left" Margin="200,120,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="WinmgmtLabel" Content="Winmgmt:" HorizontalAlignment="Left" Margin="10,130,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="WinmgmtTextBlock" HorizontalAlignment="Left" Margin="200,135,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                    <Label x:Name="WuauservLabel" Content="Wuauserv:" HorizontalAlignment="Left" Margin="10,145,0,0" VerticalAlignment="Top"/>
                    <TextBlock x:Name="WuauservTextBlock" HorizontalAlignment="Left" Margin="200,150,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top"/>
                </Grid>
            </GroupBox>
            <GroupBox x:Name="DNSGroupBox" Header="DNS" HorizontalAlignment="Left" Height="182" Margin="10,750,0,0" VerticalAlignment="Top" Width="515">
                <ListBox x:Name="DNSListBox" HorizontalAlignment="Left" Height="140" Foreground="#c5c9ca" Background="#2b2b2b" Margin="10,10,0,0" VerticalAlignment="Top" Width="481"/>
            </GroupBox>
        </Grid>
    </ScrollViewer>
</Window>
"@

$Reader = New-Object System.Xml.XmlNodeReader $xaml
$Form = [windows.markup.xamlreader]::Load($reader)


#Bind Controls
$TargetComputerBox = $Form.FindName("TargetComputerTextBox")
$ScanButton = $Form.FindName("ScanButton")
$CopyNameButton = $Form.FindName("CopyButton")
$LoggedOnUserTextBlock = $Form.FindName("LoggedOnUserTextBlock")
$ComputerADDescTextBlock = $Form.FindName("ComputerADDescTextBlock")
$UserADDescTextBlock = $Form.FindName("UserADDescTextBlock")
$DisplayStatusTextBlock = $Form.FindName("DisplayStatusTextBlock")
$HostnameTextBlock = $Form.FindName("HostnameTextBlock")
$UserProfilesTextBlock = $Form.FindName("UserProfilesTextBlock")
$ModelTextBlock = $Form.FindName("ModelTextBlock")
$IPAddressTextBlock = $Form.FindName("IPAddressTextBlock")
$OSTextBlock = $Form.FindName("OSTextBlock")
$ServiceTagTextBlock = $Form.FindName("ServiceTagTextBlock")
$BIOSVersionTextBlock = $Form.FindName("BIOSVersionTextBlock")
$BIOSSecureBootTextBlock = $Form.FindName("BIOSSecureBootTextBlock")
$CurrentTimeTextBlock = $Form.FindName("CurrentTimeTextBlock")
$OSInstallDateTextBlock = $Form.FindName("OSInstallDateTextBlock")
$NetConnectionTextBlock = $Form.FindName("NetConnectionTextBlock")
$PingTextBlock = $Form.FindName("PingTextBlock")
$LastBootTextBlock = $Form.FindName("LastBootTextBlock")
$FreeSpaceTextBlock = $Form.FindName("FreeSpaceTextBlock")
$BitlockerStatusTextBlock = $Form.FindName("BitlockerStatusTextBlock")
$BitlockerConversionTextBlock = $Form.FindName("BitlockerConversionTextBlock")
$SCCMStatusTextBlock = $Form.FindName("SCCMStatusTextBlock")
$SCCMVersionTextBlock = $Form.FindName("SCCMVersionTextBlock")
$SCCMLastDateTextBlock = $Form.FindName("SCCMLastDateTextBlock")
$SCCMLastUpdateTextBlock = $Form.FindName("SCCMLastUpdateTextBlock")
$RebootPendingTextBlock = $Form.FindName("RebootPendingTextBlock")
$CcmExecTextBlock = $Form.FindName("CcmExecTextBlock")
$BitsTextBlock = $Form.FindName("BitsTextBlock")
$WinmgmtTextBlock = $Form.FindName("WinmgmtTextBlock")
$WuauservTextBlock = $Form.FindName("WuauservTextBlock")
$DNSListBox = $Form.FindName("DNSListBox")

#Button click events.
[void]$ScanButton.Add_Click( { 
        [void]$StatusBox.Clear()
        Clear-TextBlock
        $Online = Test-Connection -ComputerName $TargetComputerBox.Text -Count 1 -Quiet

        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text) {
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            [void]$wshell.Popup("A field is empty!", 0, "Oops!", 48 + 0)
        }
        elseif ($Online -eq $false) {
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            [void]$wshell.Popup("The computer is not online!", 0, "Oops!", 48 + 0)
        }
        else {
            $Time = Measure-Command -Expression {
                $CompName = $TargetComputerBox.Text
                $Session = New-PSSession -ComputerName $CompName
                $ComputerInfo = Invoke-Command -Session $Session -ScriptBlock ${Function:Get-RemoteComputerInfo}
                Remove-PSSession -Session $Session

                #Post-Evaluation
                $Online2 = Test-Connection -ComputerName $CompName -Count 1
                [string]$LatencyPre = $Online2.ResponseTime
                $Latency = $LatencyPre + "ms"
                $ComputerAD = Get-ADComputer -Identity $ComputerInfo.HostName -Property Description | Select-Object -ExpandProperty Description
                if ($ComputerInfo.Username) {
                    $UserADPre = Get-ADUser -Identity $ComputerInfo.UserName -Property Name, TelephoneNumber, Description
                    $UserADName = $UserADPre.Name
                    $UserADPhone = $UserADPre.TelephoneNumber
                    $UserADDesc = $UserADPre.Description
                    $UserAD = "$UserADName " + "/" + " $UserADPhone " + "/" + " $UserADDesc"
                }
                else {
                    $ComputerInfo.UserName = "No user logged on."
                    $UserAD = "No user logged on."
                }
                $ComputerInfo | Add-Member -NotePropertyName Latency -NotePropertyValue $Latency
                $ComputerInfo | Add-Member -NotePropertyName ComputerAD -NotePropertyValue $ComputerAD
                $ComputerInfo | Add-Member -NotePropertyName UserAD -NotePropertyValue $UserAD


                if ($null -ne $ComputerInfo) {
                    Set-TextBlock -TextBlock $LoggedOnUserTextBlock -Text $ComputerInfo.UserName
                    Set-TextBlock -TextBlock $UserADDescTextBlock -Text $ComputerInfo.UserAD
                    Set-TextBlock -TextBlock $ComputerADDescTextBlock -Text $ComputerInfo.ComputerAD
                    Set-TextBlock -TextBlock $HostNameTextBlock -Text $ComputerInfo.HostName
                    Set-TextBlock -TextBlock $DisplayStatusTextBlock -Text $ComputerInfo.Screen
                    Set-TextBlock -TextBlock $UserProfilesTextBlock -Text $ComputerInfo.UserProfiles
                    Set-TextBlock -TextBlock $ModelTextBlock -Text $ComputerInfo.Model
                    Set-TextBlock -TextBlock $IPAddressTextBlock -Text $ComputerInfo.IPAddress
                    Set-TextBlock -TextBlock $OSTextBlock -Text $ComputerInfo.OS
                    Set-TextBlock -TextBlock $ServiceTagTextBlock -Text $ComputerInfo.Serial
                    Set-TextBlock -TextBlock $BIOSVersionTextBlock -Text $ComputerInfo.BIOSVersion
                    Set-TextBlock -TextBlock $CurrentTimeTextBlock -Text $ComputerInfo.CurrentTime
                    Set-TextBlock -TextBlock $OSInstallDateTextBlock -Text $ComputerInfo.InstallDate
                    Set-TextBlock -TextBlock $NetConnectionTextBlock -Text $ComputerInfo.NetConnectType
                    Set-TextBlock -TextBlock $PingTextBlock -Text $ComputerInfo.Latency
                    Set-TextBlock -TextBlock $LastBootTextBlock -Text $ComputerInfo.LastBootTime
                    Set-TextBlock -TextBlock $FreeSpaceTextBlock -Text $ComputerInfo.FreeDiskSpace
                    Set-TextBlock -TextBlock $BIOSSecureBootTextBlock -Text $ComputerInfo.SecureBoot
                    Set-TextBlock -TextBlock $BitlockerStatusTextBlock -Text $ComputerInfo.BitlockerStatus
                    Set-TextBlock -TextBlock $BitlockerConversionTextBlock -Text $ComputerInfo.BitlockerConversion
                    Set-TextBlock -TextBlock $SCCMStatusTextBlock -Text $ComputerInfo.SCCMStatus
                    Set-TextBlock -TextBlock $SCCMVersionTextBlock -Text $ComputerInfo.SCCMVersion
                    Set-TextBlock -TextBlock $SCCMLastDateTextBlock -Text $ComputerInfo.SCCMLastDate
                    Set-TextBlock -TextBlock $SCCMLastUpdateTextBlock -Text $ComputerInfo.SCCMUpdate
                    Set-TextBlock -TextBlock $RebootPendingTextBlock -Text $ComputerInfo.RebootPending
                    Set-TextBlock -TextBlock $CcmExecTextBlock -Text $ComputerInfo.CcmExec
                    Set-TextBlock -TextBlock $BitsTextBlock -Text $ComputerInfo.Bits
                    Set-TextBlock -TextBlock $WinmgmtTextBlock -Text $ComputerInfo.Winmgmt
                    Set-TextBlock -TextBlock $WuauservTextBlock -Text $ComputerInfo.Wuauserv

                    $DNSSuffixes = $ComputerInfo.DNSSuffix
                    foreach ($DNSSuffix in $DNSSuffixes) {
                        [void]$DNSListBox.Items.Add($DNSSuffix)
                    }
                }
                [GC]::Collect()
            }
        }
    })
#Copies hostname in textbox to clipboard.
[void]$CopyNameButton.Add_Click( { 
        [void]$StatusBox.Clear()
        if (Confirm-IsEmpty -Fields $TargetComputerBox.Text) {
            $wshell = New-Object -ComObject Wscript.Shell -ErrorAction Stop
            [void]$wshell.Popup("A field is empty!", 0, "Oops!", 48 + 0)
        }
        else {
            Set-Clipboard -Value $TargetComputerBox.Text
        }
    })

[void]$form.ShowDialog()
