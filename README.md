Get-LogonHistory-mult
=====================

This is remake script of user Craig Meinschein https://github.com/pfaffle Get-LogonHistory.ps1

His scpirt was very helpful for me. I added some new feautures for our customer expectations:

•	Optimized request Get-Eventlog contitions

•	Automatically detect OS language (EN or RUS) , Get-Wmi-Object  add addtional function

•	User dialog for enter multiple local or remote computernames or batch csv file 

•	User dialog for enter last few days count for pase eventlog 

•	Match user information with Active Directory user and find some Active Directory attributes such mail, telephonenumber

•	Export to csv file for hanling in MS Excel Export-csv -Append (requires Powershell 3.0)


