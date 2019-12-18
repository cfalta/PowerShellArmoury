# PowerShellArmoury

The PowerShell Armoury is meant for Pentesters or Auditors who use a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.

You do not have to hassle with updating nishang, powersploit, ... manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next pentest.
In addition, your new and shiny armoury is encrypted and includes a bypass for AMSI, so you dont have to worry about AV.

Note: you have to provide a valid github account as well as a personal access token, so the script can properly use the github API.

## Example usage

Create Armoury

``` powershell
Import-Module .\New-PSArmoury.ps1
New-PSArmoury -Password password -Salt salt -Config .\PSArmoury.json
```

Use Armoury

``` powershell
Get-Content -raw .\MyArmoury.ps1 | iex
```
