<#
.SYNOPSIS
Gets computer objects from AD.  The output will then be exported to a CSV file for easy organizing.

.DESCRIPTION
Asks the user to specify a predefined Organizational Unit.  This is limited and is not designed to be universal, adjust as needed.  For best performance, the computer
running this script and the computers to be checked should be roughly in the same geographical area as crossing any firewalls or IPS will slow its progress and may cause
check failure.  Runspaces allow multi-threading, so a multi-core computer is recommended.
#>

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
    Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    Exit
} #Self-elevate check close.

function Show-Menu {
    #Provides simple user interface to determine which OU is checked.
    param (
        [string]$Title = 'Organizational Unit'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host "1: ABC."
    Write-Host "2: DEF."
    Write-Host "3: GHI."
    Write-Host "Q: Press 'Q' or anything else to quit."
} #Show-Menu close.

Show-Menu Title "'Organizational Unit'"
$selection = Read-Host "Which OU are you checking?"
$Base = $null
#The searchbase is intentionally limited and specific to a computers OU so that it doesn't probe servers.
#It's also specific to a local domain simply because it wouldn't be practical to run this across domains unless Powershell Remoting is enabled.
#If PSRemoting is ever enabled, another separate script should be made which utilizes Invoke-Command and local cmdlets instead.
switch ($selection) {
    '1' {
        'You chose #ABC'
        $SearchBase = "OU=Computers,OU=ABC,DC=contoso,DC=com"
        $Base = "ABC"
    } '2' {
        'You chose #DEF'
        $SearchBase = "OU=Computers,OU=DEF,DC=contoso,DC=com"
        $Base = "DEF"
    } '3' {
        'You chose #GHI'
        $SearchBase = "OU=Computers,OU=GHI,DC=contoso,DC=com"
        $Base = "GHI"
    } 'q' {
        Exit
    }
} #Switch close.

$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate, LastLogonTimeStamp | Sort-Object Name

#This strange incrementation is needed to properly pass through the variable as intended as the count method was giving strange results.
$Count = 0
foreach ($i in $Computers) {
    $Count++
}
$Date = Get-Date -Format MM-dd-yyyy_hh-mm

function Get-CIMRegValue {             
    #The Cim method to query the registry utilizes uint32 values to determine which hive to query, this simplifies the process by declaring the values with the proper types.
    [CmdletBinding(DefaultParameterSetName = "UseComputer")]             

    param (             
        [parameter(Mandatory = $true)]            
        [ValidateSet("HKCR", "HKCU", "HKLM", "HKUS", "HKCC")]            
        [string]$hive,            

        [parameter(Mandatory = $true)]            
        [string]$key,            

        [parameter(Mandatory = $false)]            
        [string]$value,            

        [parameter(Mandatory = $true)]            
        [string]            
        [Validateset("DWORD", "EXPANDSZ", "MULTISZ", "QWORD", "SZ", "ENUMVAL")]            
        $type,            

        [parameter(ValueFromPipeline = $true,            
            ValueFromPipelineByPropertyName = $true)]            
        [parameter(ParameterSetName = "UseComputer")]             
        [string]$computer = "$env:COMPUTERNAME",            

        [parameter(ValueFromPipeline = $true,            
            ValueFromPipelineByPropertyName = $true)]            
        [parameter(ParameterSetName = "UseCIMSession")]             
        [Microsoft.Management.Infrastructure.CimSession]$cimsession            
    )             
    BEGIN { }#begin             
    PROCESS {            
        switch ($hive) {            
            "HKCR" { [uint32]$hdkey = 2147483648 } #HKEY_CLASSES_ROOT            
            "HKCU" { [uint32]$hdkey = 2147483649 } #HKEY_CURRENT_USER            
            "HKLM" { [uint32]$hdkey = 2147483650 } #HKEY_LOCAL_MACHINE            
            "HKUS" { [uint32]$hdkey = 2147483651 } #HKEY_USERS            
            "HKCC" { [uint32]$hdkey = 2147483653 } #HKEY_CURRENT_CONFIG            
        }#Switch hive close.    

        switch ($type) {            
            "DWORD" { $methodname = "GetDwordValue" }            
            "EXPANDSZ" { $methodname = "GetExpandedStringValue" }            
            "MULTISZ" { $methodname = "GetMultiStringValue" }            
            "QWORD" { $methodname = "GetQwordValue" }            
            "SZ" { $methodname = "GetStringValue" }     
            "ENUMVAL" { $methodname = "EnumValues" }       
        }#Switch type close
        if ($type -ne "ENUMVAL") {
            $arglist = @{hDefKey = $hdkey; sSubKeyName = $key; sValueName = $value }  
        }#If close.
        else {
            $arglist = @{hDefKey = $hdkey; sSubKeyName = $key }
        }#Else close.

        switch ($psCmdlet.ParameterSetName) {            
            "UseComputer" { $result = Invoke-CimMethod -Namespace "root\cimv2" -ClassName StdRegProv -MethodName $methodname -Arguments $arglist -ComputerName $computer }            
            "UseCIMSession" { $result = Invoke-CimMethod -Namespace "root\cimv2" -ClassName StdRegProv -MethodName $methodname -Arguments $arglist -CimSession $cimsession }            
            default { Write-Host "Error!!! Should not be here" }            
        }#Switch close.          

        switch ($type) {            
            "DWORD" { $result | Select-Object -ExpandProperty uValue }            
            "EXPANDSZ" { $result | Select-Object -ExpandProperty sValue }            
            "MULTISZ" { $result | Select-Object -ExpandProperty sValue }            
            "QWORD" { $result | Select-Object -ExpandProperty uValue }            
            "SZ" { $result | Select-Object -ExpandProperty sValue }  
            "ENUMVAL" { $result | Select-Object -ExpandProperty sNames }          
        }#Switch type close.       

    }#process             
    END { }#end  
}
Function Get-ComputerStatus {
    #Use of runspaces allows parallel processing so multiple computers can be checked at the same time.
    #The computer running this script should have as much bandwidth and CPU cores as possible.
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Computers
    )
    BEGIN { 
        #Imports a custom function into the runspacepool.
        $Definition = Get-Content Function:\Get-CIMRegValue -ErrorAction Stop
        $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList 'Get-CIMRegValue', $Definition

        #Sets maximum threads.  Triple the available processors has been good to maximum performance.
        [int]$Throttle = [int]$env:NUMBER_OF_PROCESSORS * 4 #Max Runspaces
        $Initial = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        [void]$Initial.Commands.Add($SessionStateFunction)
        $RunspacePool = [runspacefactory]::CreateRunspacePool($Initial)
        [void]$RunspacePool.SetMaxRunspaces($Throttle)
        $RunspacePool.ApartmentState = "STA"
        $RunspacePool.ThreadOptions = "ReuseThread"
        [void]$RunspacePool.Open()
        $Results = @()
        $Jobs = @()

        #Timeout for the script, in minutes.
        [int]$Timeout = 8
    }#Begin close.

    PROCESS {
        foreach ($Computer in $Computers) {
            [DateTime]$OutLastLogonDate = $Computer.LastLogonDate
            [DateTime]$OutLastLogonTimeStamp = $Computer.LastLogonTimeStamp
            #Checks Active Directory to see if the computer object has a Bitlocker Recovery Password stored.
            $BitLockerADRecovery = Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
                -SearchBase $Computer.distinguishedName -Properties msFVE-RecoveryPassword | Select-Object -ExpandProperty msFVE-RecoveryPassword
            $BitlockerRecoverySet = $null -ne $BitLockerADRecovery
            $CimJob = [powershell]::Create()
            [void]$CimJob.AddScript(
                {
                    param(
                        [Object]$Computer,
                        [DateTime]$LastLogonDate,
                        [DateTime]$LastLogonTimeStamp,
                        [Object]$BitLockerADRecovery,
                        [Boolean]$BitlockerRecoverySet
                    )
            
                    $ComputerName = $Computer.Name

                    #Compares the two logon dates to see which one is more recent and uses that value.
                    #This is useful if the computer checked into a different domain controller than the one you queried.
                    If ($LastLogonDate -ge $LastLogonTimeStamp) {
                        $LogonDate = $LastLogonDate
                    }
                    else {
                        $LogonDate = $LastLogonTimeStamp
                    }
                    
                    #Tests to see if the computer is online and pingable.  Count is 1 to increase speed.
                    $TestConn = Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue
                    $Online = $null -ne $TestConn
                    $RemoteAddress = $TestConn.IPV4Address

                    #Separate DNS test.  A lack of a DNS record is an obvious indication of a problem.
                    $NameResolutionSucceeded = $null -ne (Resolve-DnsName -Name $ComputerName)
                    if ($Online) {
                        #Objects are returned as array entries.

                        #Uses Dcom protocol to allow establishing a Cimsession without PSRemoting enabled.
                        $Option = New-CimSessionOption -Protocol Dcom

                        #Establishes Cimsession using IP Address.
                        $Session = New-CimSession -ComputerName $ComputerName -SessionOption $Option -ErrorAction SilentlyContinue
                        if ($null -ne $Session) {
                            #Runs query to find actual hostname of the computer.
                            $CS = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystem `
                                -Property Name, Model
                            $HostName = $CS.Name
                            $Model = $CS.Model

                            #Checks if SCCM is installed
                            $SCCM = $null -ne (Get-CimInstance -CimSession $Session -ClassName CIM_DataFile `
                                    -Filter "drive='C:' AND path='\\Windows\\ccmsetup\\'")
                            $SCCMRegistry = $null -ne (Get-CIMRegValue -hive HKLM -key "SOFTWARE\Microsoft\SMS\Mobile Client" `
                                    -type ENUMVAL -cimsession $Session)
                            $WMI = $null -ne (Get-CimInstance -CimSession $Session -ClassName 'SMS_Client' -Namespace 'root\ccm')

                            #Checks Operating System version.
                            $OSVersion = (Get-CimInstance -CimSession $Session -ClassName Win32_OperatingSystem).Version
                    
                            #Checks Bitlocker.
                            $Bitlocker = Get-CimInstance -CimSession $Session -NameSpace "root/CIMV2/Security/MicrosoftVolumeEncryption" `
                                -ClassName Win32_EncryptableVolume -Filter "driveletter='C:'"
                            #These two will retrieve the Bitlocker recovery password from the remote computer so it can be compared with AD stored password.
                            $ProtectorID = Invoke-CimMethod -InputObject $Bitlocker -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = 3 } `
                            | Select-Object -ExpandProperty VolumeKeyProtectorID
                            $RecoveryPassword = Invoke-CimMethod -InputObject $Bitlocker -MethodName GetKeyProtectorNumericalPassword -Arguments `
                            @{ VolumeKeyProtectorID = $ProtectorID } | Select-Object -ExpandProperty NumericalPassword

                            #This registry key is incremented with every Cumulative Update and is a reliable way to tell whether a computer is behind in patches.
                            $CUVersion = Get-CIMRegValue -Hive HKLM -Key "SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
                                -Value "UBR" -Type DWORD -CimSession $Session

                            $Session | Remove-CimSession
                        }#If null session close.


                        #Checks to see if the computer name in AD matches the hostname from the Win32_ComputerSystem query.
                        #If this does not match, it indicates that the DNS record is incorrect (the IP resolves to a different computer than the one you tried to reach).
                        $NameMatch = $HostName -eq $ComputerName

                        #Calculates the state of Bitlocker based on a couple of values.
                        if ($Bitlocker.ProtectionStatus -eq 1) {
                            $BitlockerStatus = "On"
                        }
                        else {
                            if ($Bitlocker.IsVolumeInitializedForProtection -eq $true) {
                                $BitlockerStatus = "Suspended"
                            }
                            else {
                                $BitlockerStatus = "Off"
                            }
                        }#Bitlocker if/else close.
                        #Compares the remote computer's Bitlocker recovery password with the one stored in Active Directory.
                        $BitlockerMatch = $false
                        foreach ($BitlockerRecoveryKey in $BitlockerADRecovery) {
                            if ($RecoveryPassword -eq $BitlockerRecoveryKey) {
                                $BitlockerMatch = $true
                            }
                        }
                        if (-Not $NameMatch) {
                            $BitlockerMatch = "Wrong DNS"
                        }
                        $Version = $OSVersion + "." + $CUVersion

                    }#Online check close.
                    else {
                        $HostName = "Not Online."
                        $Model = "Not Online."
                        $SCCM = "Not Online."
                        $SCCMRegistry = "Not Online."
                        $NameMatch = "Not Online."
                        $WMI = "Not Online."
                        $Version = "Not Online."
                        $HostName = "Not Online."
                        $Model = "Not Online."
                        $BitlockerStatus = "Not Online."
                        $BitlockerMatch = "Not Online."
                    }#If / else offline check close.
                    #Outputs all results as a custom PSObject.
                    [PSCustomObject]@{
                        #Computer targeted.
                        'Computer'        = $ComputerName

                        #Whether you could resolve an IP Address from DNS.
                        'DNS'             = $NameResolutionSucceeded

                        #Whether the computer is pingable.
                        'Ping'            = $Online

                        #Most recent date computer was seen in Active Directory.
                        'LogonDate'       = $LogonDate

                        #IP Address from pinging computer name.
                        'IPAddress'       = $RemoteAddress

                        #Whether ccmsetup folder is present.
                        'SCCM'            = $SCCM

                        #Whether SCCM registry entry is present.
                        'SCCMRegistry'    = $SCCMRegistry

                        #Whether SMS_Client WMI namespace is present.
                        'WMI'             = $WMI

                        #Major/minor version of Windows (Feature Update/Cumulative Update)
                        'Version'         = $Version

                        #What the remote computer reports its own hostname is from WMI.
                        'HostName'        = $HostName

                        #Model of the computer from WMI.
                        'Model'           = $Model

                        #Whether the hostname from WMI matches what you tried to reach from Active Directory.
                        'NameMatch'       = $NameMatch

                        #Whether Active Directory has a Bitlocker recovery password stored.
                        'ADBitlocker'     = $BitlockerRecoverySet

                        #Current status of Bitlocker on the computer.
                        'BitlockerStatus' = $BitlockerStatus

                        #Whether the remote computer's recovery password matches anything stored in Active Directory.
                        'BitlockerMatch'  = $BitlockerMatch

                    }#PScustomobject close.
                }#Addscript close.
            )#Addscript close.
            [void]$CimJob.AddArgument($Computer).AddArgument($OutLastLogonDate).AddArgument($OutLastLogonTimeStamp).AddArgument($BitLockerADRecovery).AddArgument($BitlockerRecoverySet)
            $CimJob.RunspacePool = $RunspacePool
            [Collections.Arraylist]$Jobs += [PSCustomObject]@{
                Pipe   = $CimJob
                Status = $CimJob.BeginInvoke()
                Timer  = Get-Date
            }#PSCustomobject close.
        }#Foreach computer close.
        $Progress = 0
        while ($Jobs) {
            foreach ($Job in $Jobs.ToArray()) {
                #Terminates thread if it runs longer than the specified timeout.
                $TimeoutStatus = (New-TimeSpan -Start $Job.Timer).TotalMinutes -ge $Timeout
                if (($Job.Status.IsCompleted)) {
                    $Results += $Job.Pipe.EndInvoke($Job.Status)
                    [void]$Job.Pipe.Dispose()
                    [void]$Jobs.Remove($Job)
                    $Progress++
                    Write-Progress -Activity "Checking Status of computers..." -Status "Checking: $Progress of $Count" -PercentComplete (($Progress / $Count) * 100) -Id 1
                }
                elseif ($TimeoutStatus) {
                    [void]$Job.Pipe.Stop()
                    [void]$Job.Pipe.Dispose()
                    [void]$Jobs.Remove($Job)
                    $Progress++
                    Write-Progress -Activity "Checking Status of computers..." -Status "Checking: $Progress of $Count" -PercentComplete (($Progress / $Count) * 100) -Id 1
                }#Job status close.
            }#Foreach close.
        }#While jobs loop close.
    }#Process close.
    END { 
        #Cleans up the jobs.
        [void]$RunspacePool.Close()
        [void]$RunspacePool.Dispose()
        [GC]::Collect()
        Return $Results
    }#End close.
}#Main function close.

#Exports the output from the array into a CSV file.
$Result = Get-ComputerStatus -Computers $Computers 

$Result | Select-Object Computer, NameMatch, HostName, Model, DNS, Ping, LogonDate, IPAddress, SCCM, SCCMRegistry, WMI, Version, ADBitlocker, `
    BitlockerMatch, BitlockerStatus | Sort-Object Computer | Export-Csv "C:\Scripts\Reports\ADComputerStatus$($Base)_$($Date).csv" -NoTypeInformation
