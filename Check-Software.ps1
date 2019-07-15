<#
Gets computer objects from AD.  Then uses a for loop to check for presence of software folder and a file
that the software generates when it is activated.  The output will then be exported to a CSV file for easy organizing.
#>

$Computers = 'localhost'
$Array = @()

ForEach ($Computer in $Computers) {
    $Software = Test-Path "\\$Computer\C$\Program Files\ASUS\"
    $Activated = Test-Path "\\$Computer\c$\Program Files\ASUS\AuraSDK\AuraSdk_x64.dll"

    $Array += New-Object PSObject -Property @{
        'ComputerName' = $Computer
        'Software' = $Software
        'Activated' = $Activated
    }

}

$Array | Select-Object ComputerName,Software,Activated