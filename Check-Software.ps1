<#
Gets computer objects from AD.  Then uses a for loop to check for presence of software folder and a file
that the software generates when it is activated.  The output will then be exported to a CSV file for easy organizing.
#>

$Progress = 0
$SearchBase = "OU"
$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase -Properties LastLogonDate | Sort-Object Name
$Count = $Computers.Count
$Date = Get-Date -f MM-dd-yyyy

#Custom array to store the ouput.
$Store = @()

$Computers | ForEach-Object {
    $ScriptPath = $_.Name
    $HostName = $Null
    $DNSPathCheck = $Null
    $Software = $Null
    $Activated = $Null
    $IPNameCheck = $Null
    $IPSoftware = $Null
    $IPActivated = $Null
    $LogonDate = $_.LastLogonDate

    #This is what the tool checks for to see if Software is installed and activated.
    $SoftwarePath = "\\$ScriptPath\c$\Program Files\software"
    $ActivationPath = "\\$ScriptPath\c$\Program Files\software\file.config"
    $PathCheck = "\\$ScriptPath\c$"

    #Tests to see if the computer is pingable.
    $Online = Test-NetConnection -ComputerName $_.Name -InformationLevel Detailed
    if($Online.PingSucceeded -eq $True){
        #This checks the root of the C drive.  If DNS is inaccurate, it will fail.
        $DNSPathCheck = Test-Path $PathCheck
        if($DNSPathCheck -eq $True){
            $Software = Test-Path $SoftwarePath
            $Activated = Test-Path $ActivationPath
        }
        else
        {
            $Software = 'FALSE'
            $Activated = 'FALSE'

            $IPPath = $Online.RemoteAddress

            #If DNS check fails, it uses the IP address in the path instead and copies the NetSetup.LOG file which will contain the real
            #hostname of the computer.  It uses both the computer name and ip address in the log name.
            $IPTestPath = Test-Path \\$IPPath\c$\Windows\debug\NetSetup.LOG
            if($IPTestPath -eq $True){
                #Reads the hostname off the NetSetup.LOG file.
                $HostName = Select-String -Path "\\$IPPath\c$\Windows\debug\NetSetup.LOG" -Pattern 'NetbiosName: (\w.*)' |
                Select-Object -Last 1 | % {$_.Matches.Groups[1].Value}

                $IPNameCheck = 'TRUE'

                #Uses IP in path to check Avamar.
                $IPSoftware = Test-Path "\\$IPPath\c$\Program Files\software"
                $IPActivated = Test-Path "\\$IPPath\c$\Program Files\software\file.config"
            }
            else{
                $IPNameCheck = 'FALSE'
            } #Close IP Path Test.
        } #Close DNS Path Test.
    }
    else
    {
        $IPNameCheck = "Not Online."
        $DNSPathCheck = "Not Online."
        $Software = "Not Online."
        $Activated = "Not Online."
    } #Close Ping Test.

    #Creates a custom Powershell Object to append to the storage array.
    $store += New-Object PSObject -Property @{
    'Computer' = $_.Name
    'DNS' = $Online.NameResolutionSucceeded
    'Ping' = $Online.PingSucceeded
    'LogonDate' = $LogonDate
    'IPAddress' = $Online.RemoteAddress
    'DNS_Check' = $DNSPathCheck
    'IPNameCheck' = $IPNameCheck
    'Software' = $Software
    'Activated' = $Activated
    'HostName' = $HostName
    'IP_Software' = $IPSoftware
    'IP_Activated' = $IPActivated
    } #Close custom PSObject Hash Table.
    Start-Sleep -Seconds 2
    #Tracks progress as it goes through each loop.
    $Progress++
    Write-Progress -Activity "Checking Avamar status..." -Status "Checking: $Progress of $($Count)" -PercentComplete (($Progress / $Count) * 100) -Id 1
} #Close For-Each Loop.

#Exports the output from the array into a CSV file.
$Store | Select-Object Computer,DNS,Ping,LogonDate,IPAddress,DNS_Check,IPNameCheck,Software,Activated,HostName,IP_Software,IP_Activated |
Export-Csv "C:\Scripts\Reports\AvamarStatus_$Date.csv" -NoTypeInformation
