## Unprotect-CiscoPassword7

PowerShell script which decrypts Cisco password 7 encrypted passwords from switch and router configs.

### Example

    PS C:\> Import-Module c:\downloads\Unprotect-CiscoPassword7.ps1
    PS C:\> Unprotect-CiscoPassword7 '046E1803362E595C260E0B240619050A2D'
    
    UseYourOwnString

### Example
You have some Cisco configs saved as `.txt` files on your local disk, and want to get all the passwords from all the files:

```
PS C:\> Import-Module c:\downloads\Unprotect-CiscoPassword7.ps1

PS C:\> Get-ChildItem -Path "C:\CiscoConfigs\" -Recurse  |
    Select-String -Pattern 'password 7'    |
    ForEach-Object { 
        Unprotect-CiscoPassword7 $_.Line
    }
```
