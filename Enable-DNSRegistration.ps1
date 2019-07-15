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

#Enables registration of DNS suffix on Adapter.
ForEach($Adapter in $Adapters){
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$Adapter" `
-Name RegisterAdapterName -Value 1
}