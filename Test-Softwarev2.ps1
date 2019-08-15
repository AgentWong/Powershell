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

workflow QueryComputers {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [Object[]]$Computers
    )
    foreach -Parallel ($Computer in $Computers) {
        sequence {
            #Sets variables.
            $HostName = $Null
            $NameMatch = $Null
            $Software = $Null
            $LogonDate = $_.LastLogonDate

            #Tests to see if the computer is pingable.
            $Online = Test-NetConnection -PSComputerName $_.Name -InformationLevel Detailed
            if ($Online.PingSucceeded -eq $True) {
                $HostName = Get-WmiObject -PSComputerName $Online.RemoteAddress -ClassName Win32_ComputerSystem `
                -Property Name | Select-Object -ExpandProperty Name
                $NameMatch = $_.Name -eq $HostName
                Start-Sleep -Seconds 2
                $Software = $null -eq (Get-WmiObject -PSComputerName $Online.RemoteAddress -ClassName CIM_DataFile `
                -Filter "drive='C:' AND path='\\Program Files\\Software\\var\\' AND extension='cfg'")
            }
            else {
                $HostName = "Not Online."
                $Software = "Not Online."
            } #Ping Test.

            #Creates a custom Powershell Object to append to the storage array.
            [PSCustomObject]@{
                'Computer'  = $_.Name
                'DNS'       = $Online.NameResolutionSucceeded
                'Ping'      = $Online.PingSucceeded
                'LogonDate' = $LogonDate
                'IPAddress' = $Online.RemoteAddress
                'Software'  = $Software
                'HostName'  = $HostName
                'NameMatch' = $NameMatch
            } #Close custom PSObject Hash Table.
            Start-Sleep -Seconds 2

            #Tracks progress as it goes through each loop.
            $Progress++
            Write-Progress -Activity "Checking Software status..." -Status "Checking: $Progress of $($Count)" `
            -PercentComplete (($Progress / $Count) * 100) -Id 1

        } #sequence
    } #foreach
} #Workflow

#Exports the output from the array into a CSV file.
QueryComputers | Select-Object Computer, NameMatch, HostName, DNS, Ping, LogonDate, IPAddress, Software | 
Sort-Object Computer | Export-Csv "C:\DRV\Scripts\Reports\SoftwareStatus_$Date.csv" -NoTypeInformation
