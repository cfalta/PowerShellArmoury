# PowerShellArmoury

<img align="left" width="200" height="300" src="https://user-images.githubusercontent.com/7213829/72599954-fae92780-3912-11ea-9ad4-7da273ee75dd.png">

The PowerShell Armoury is meant for pentesters, "insert-color-here"-teamers and everyone else who uses a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.

You do not have to hassle with updating nishang, powersploit, ... manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next engagement.
In addition, your new and shiny armoury is encrypted and includes a bypass for AMSI, so you dont have to worry about AV.

Note: you have to provide a valid github account as well as a personal access token, so the script can properly use the github API.
</br>
</br>


## Example usage

You can find a very brief introduction below. Also have a look a these two blog posts [here](https://cyberstoph.org/posts/2019/12/evading-anti-virus-with-powershell-armoury/) and [here](https://cyberstoph.org/posts/2020/02/psarmoury-1.4-now-with-even-more-armour/).

Use the following commands to create an armoury with all default settings. You can start with the sample config file in this repository for inspiration.

``` powershell
. .\New-PSArmoury.ps1
New-PSArmoury -Config .\PSArmoury.json
```
This will create an encrypted .ps1 file called "MyArmoury.ps1" in the current working directory. Password and salt for encryption are randomly generated and included in cleartext in the file. (note that we use encryption only to prevent detection on disk and not for confidentiality)

You can load the armoury into your current session by using

``` powershell
cat -raw .\MyArmoury.ps1 | iex
```

Loading your armoury invokes the following steps:
* Load all encrypted powershell functions into the current session as part of an array
* Disable AMSI
* Disable console history (can help prevent detection)
* Decrypt everything and pipe into iex 

After that, all powershell code you put in the armoury will be available. Just invoke the cmdlets as usual like this

``` powershell
Invoke-AllCheck
Invoke-Bloodhound
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

If it happens that you don't remember what you put inside the armoury, just load it and call the inventory :-)

``` powershell
Get-PSArmoury
```
