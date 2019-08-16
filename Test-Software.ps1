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

$Progress = 0
$SearchBase = "MyOU"
$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate | Sort-Object Name
$Count = $Computers.Count
$Date = Get-Date -f MM-dd-yyyy

Function QueryComputers {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Object[]]$Computers
    )
    foreach($Computer in $Computers) {
            $HostName = $Null
            $NameMatch = $Null
            $Software = $Null
            $LogonDate = $Computer.LastLogonDate
            $ComputerName = $Computer.Name
            
            $Online = Test-NetConnection -ComputerName $ComputerName -InformationLevel Detailed
            $PingSucceeded = $Online.PingSucceeded
            $RemoteAddress = $Online.RemoteAddress
            $NameResolutionSucceeded = $Online.NameResolutionSucceeded
            if ($PingSucceeded -eq $True) {
                $Option = New-CimSessionOption -Protocol Dcom
                
                $Session = New-CimSession -ComputerName $RemoteAddress -SessionOption $Option
                Write-Verbose "Opening new Cim session $Session to computer $RemoteAddress with option $Option."
                if($null -ne $Session){
                $HostName = Get-CimInstance -CimSession $Session -ClassName Win32_ComputerSystem `
                -Property Name | Select-Object -ExpandProperty Name
                $NameMatch = $ComputerName -eq $HostName
                Start-Sleep -Seconds 2
                $Software = $null -eq (Get-CimInstance -CimSession $Session -ClassName CIM_DataFile `
                -Filter "drive='C:' AND path='\\Program Files\\Software\\var\\' AND extension='cfg'")
                $Session | Remove-CimSession
                }
            }
            else {
                $HostName = "Not Online."
                $Avamar = "Not Online."
            } 

            [PSCustomObject]@{
                'Computer'  = $ComputerName
                'DNS'       = $NameResolutionSucceeded
                'Ping'      = $PingSucceeded
                'LogonDate' = $LogonDate
                'IPAddress' = $RemoteAddress
                'Software'    = $Software
                'HostName'  = $HostName
                'NameMatch' = $NameMatch
            } 

            Start-Sleep -Seconds 2
            $Progress++
            Write-Progress -Activity "Checking Avamar status..." -Status "Checking: $Progress of $($Count)" -PercentComplete (($Progress / $Count) * 100) -Id 1
        }
}

#Exports the output from the array into a CSV file.
QueryComputers -Computers $Computers | Select-Object Computer, NameMatch, HostName, DNS, Ping, LogonDate, IPAddress, Software | 
Sort-Object Computer | Export-Csv "C:\DRV\Scripts\Reports\SoftwareStatus_$Date.csv" -NoTypeInformation
