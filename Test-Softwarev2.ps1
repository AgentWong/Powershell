<#
Gets computer objects from AD.  Then uses a for loop to check for presence of software folder and a file
that the software generates when it is activated.  The output will then be exported to a CSV file for easy organizing.
#>

#Gets the current user account running the script.
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Checks if the account running has certain text in its name, if not, it will relaunch the script as an administrator.
if ($CurrentUser -notlike "*z0*") {
    # Self-elevate the script if required
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
} #Self-elevate check.

$SearchBase = "MyOU"
$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate | Sort-Object Name

$Date = Get-Date -f MM-dd-yyyy

Workflow QueryComputers {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Computers
    )
    foreach -Parallel ($Computer in $Computers) {
        $HostName = $Null
        $NameMatch = $Null
        $Software = $Null
        $LogonDate = InlineScript {
            $using:Computer | Select-Object -ExpandProperty LastLogonDate
        }
        $ComputerName = $Computer | Select-Object -ExpandProperty Name
        $Online = Test-NetConnection -ComputerName $ComputerName -InformationLevel Detailed
        $PingSucceeded = $Online | Select-Object -ExpandProperty PingSucceeded
        $RemoteAddress = $Online | Select-Object -ExpandProperty RemoteAddress
        $NameResolutionSucceeded = $Online | Select-Object -ExpandProperty NameResolutionSucceeded
        if ($PingSucceeded -eq $True) {
            $Holder = InlineScript {
                $Option = New-CimSessionOption -Protocol Dcom
                $Session = New-CimSession -ComputerName $using:RemoteAddress -SessionOption $Option
                if ($null -ne $Session) {
                    $HolderHostName = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystem `
                        -Property Name | Select-Object -ExpandProperty Name
                    $HolderSoftware = $null -eq (Get-CimInstance -CimSession $Session -ClassName CIM_DataFile `
                            -Filter "drive='C:' AND path='\\Program Files\\Software\\var\\' AND extension='cfg'")
                    $Session | Remove-CimSession
                    $HolderHostName
                    $HolderSoftware
                }
            }
            $HostName = $Holder[0]
            $Software = $Holder[1]
            $NameMatch = $HostName -eq $ComputerName

        }
        else {
            $HostName = "Not Online."
            $Software = "Not Online."
            $NameMatch = "Not Online."
        } 

        [PSCustomObject]@{
            'Computer'  = $ComputerName
            'DNS'       = $NameResolutionSucceeded
            'Ping'      = $PingSucceeded
            'LogonDate' = $LogonDate
            'IPAddress' = $RemoteAddress
            'Software'  = $Software
            'HostName'  = $HostName
            'NameMatch' = $NameMatch
        } 
    }
}

#Exports the output from the array into a CSV file.
QueryComputers -Computers $Computers | Select-Object Computer, NameMatch, HostName, DNS, Ping, LogonDate, IPAddress, Software | 
Sort-Object Computer | Export-Csv "C:\DRV\Scripts\Reports\SoftwareStatus_$Date.csv" -NoTypeInformation
