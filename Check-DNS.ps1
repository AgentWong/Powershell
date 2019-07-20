<#
.SYNOPSIS
Checks computers in OU of AD for DNS problems.

.DESCRIPTION
Attempts to ping every computer in a specified OU.  It checks to see whether the computer name resolves to an IP Address.
Next it pulls the date since it was last seen by Active Directory.  It lists the IP Address.  It will then attempt to access the hidden C share by hostname.
If the share test fails by hostname, there may be DNS issues.  It then tries to access the C share by IP address instead.  Lastly it reads the
C:\Windows\debug\NetSetup.LOG file and uses RegEx to find the hostname.

#>

#Sets variables.
$Progress = 0
$SearchBase = "<Organizational Unit>"
$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate | Sort-Object Name
$Count = $Computers.Count
$Date = Get-Date -f MM-dd-yyyy

#Custom array to store the ouput.
$Store = @()

#Loops through each computer.
$Computers | ForEach-Object {
    $TestCon = Test-NetConnection -ComputerName $_.Name -InformationLevel "Detailed"
    $Ping = $TestCon.PingSucceeded
    $Resolve_IP = $TestCon.NameResolutionSucceeded
    $IP = $TestCon.RemoteAddress
    $ComputerName = $_.Name
    $HostName = $Null
    $NameTest = $Null
    $IPTest = $Null
    $LogonDate = $_.LastLogonDate

    $NamePathCheck = "\\$ComputerName\c$"
    $IPPathCheck = "\\$IP\c$"
    if ($Ping -eq $True) {
        #Tests the C share by hostname.
        $NameTest = Test-Path $NamePathCheck
        if ($NameTest -eq $False) {
            #Tests the C share by IP address.
            $IPTest = Test-Path $IPPathCheck
            if ($IPTest -eq $True) {
                #Reads the hostname off the NetSetup.LOG file.
                $Hostname = Select-String -Path "\\$IP\c$\Windows\debug\NetSetup.LOG" -Pattern 'NetbiosName: (\w.*)' |
                Select-Object -Last 1 | ForEach-Object { $_.Matches.Groups[1].Value }
            }
        }
    }
    #Creates a custom Powershell object to store the results of the loop.
    $Store += New-Object PSObject -Property @{
        'Computer'   = $_.Name
        'Resolve_IP' = $Resolve_IP
        'Ping'       = $Ping
        'IPAddress'  = $IP
        'Name_Test'  = $NameTest
        'IP_Test'    = $IPTest
        'HostName'   = $HostName
        'LogonDate'  = $LogonDate
    }
    #Pause needed as rapid share access leads to access being blocked.
    Start-Sleep -Seconds 2

    #Tracks progress and number of computer objects that need to be looped through.
    $Progress++
    Write-Progress -Activity "Checking DNS resolution of computers..." -Status "Checking: $Progress of $($Count)" -PercentComplete (($Progress / $Count) * 100) -Id 1
}

#Exports the results to a CSV file where the data can be easily read and filtered in MS Excel.
$Store | Select-Object Computer, Resolve_IP, LogonDate, Ping, IPAddress, Name_Test, IP_Test, HostName |
Export-Csv C:\Scripts\Reports\DNS_Check_$Date.csv -NoTypeInformation
