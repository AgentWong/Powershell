<#
Usage is simple.  First you query Win32_NetworkAdapter class for objects with a NetConnectionID that is not null.
This reflects the real network adapters you see in the GUI.  The GUID is used to identify them.  You can't enable
certain settings like "Use this connection's DNS suffix in DNS registration" using the WMI method if there is no IP 
address for the adapter.
However you can enable and edit these settings by editing the registry.  The loop goes through each GUID and uses
the GUID in the registry path where the settings are stored and edits them as needed.
#>

#Gets GUID of Real Network Adapters.
$Adapters = Get-WMIObject Win32_NetworkAdapter | Where-Object { $_.NetConnectionID -ne $null } |
Select-Object -ExpandProperty GUID

#Gets Primary DNS suffix of the computer.
$Domain = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name Domain | Select-Object -ExpandProperty Domain

#Disables IPv6 per Microsoft's instructions.
#https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
-Name DisabledComponents -Value "0xFF"

#Enables registration of DNS suffix on Adapter.  Uses GUID in path to target specific network adapters.
#Sets DNS suffix of the adapter to be the same as the primary DNS suffix on the computer.
ForEach($Adapter in $Adapters){
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Adapter" `
-Name RegisterAdapterName -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Adapter" `
-Name RegistrationEnabled -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Adapter" `
-Name Domain -Value $Domain
}
