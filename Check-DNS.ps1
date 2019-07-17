<#
Reserved for comments.
#>

$OutPath = "C:\DRV\Scripts\Reports"
$Progress = 0
$SearchBase = <MySearchBase>
$Computers = Get-ADComputer -Filter * -SearchBase $SearchBase | Sort-Object Name
$Count = $Computers.Count
$Date = Get-Date -f MM-dd-yyyy

#Custom array to store the ouput.
$Store = @()

$Computers | ForEach-Object  {
    $TestCon = Test-NetConnection -ComputerName $_.Name -InformationLevel "Detailed"
    $Ping = $TestCon.PingSucceeded
    $DNS_Initial = $TestCon.NameResolutionSucceeded
    $IP = $TestCon.RemoteAddress
    $ComputerName = $_.Name

    $NamePathCheck = "\\$ComputerName\c$"
    $IPPathCheck = "\\$IP\c$"
    if($Ping){
        $NameTest = Test-Path $NamePathCheck
        if($NameTest -eq $False){
            $IPTest = Test-Path $IPPathCheck
        }
    }
    $Store += New-Object PSObject -Property @{
    'Computer' = $_.Name
    'DNS_Initial' = $DNS_Initial
    'Ping' = $Ping
    'IPAddress' = $IP
    'Name_Test' = $NameTest
    'IP_Test' = $IPTest
    }

    $Progress++
    Write-Progress -Activity "Checking DNS resolution of computers..." -Status "Checking: $Progress of $($Count)" -PercentComplete (($Progress / $Count) * 100) -Id 1
}

$Store | Select-Object Computer,DNS_Initial,Ping,IPAddress,Name_Test,IP_Test |
Export-Csv C:\DRV\Scripts\Reports\DNS_Check_$Date.csv -NoTypeInformation
