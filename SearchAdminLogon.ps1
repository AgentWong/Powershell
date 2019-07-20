Get-WinEvent -computer "DomainController1" -LogName Security -FilterXPath `
"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 864000000]] and EventData[Data[@Name='TargetUserName'] `
= 'Administrator'] and EventData[Data[@Name='IpAddress'] != '-']]" | 
Select-Object MachineName, @{l = 'LogonAccount'; e = { $_.Properties[6].Value + `
    "\" + $_.Properties[5].Value + " " + $_.Properties[18].value }}