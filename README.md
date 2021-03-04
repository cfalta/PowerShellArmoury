# PowerShellArmoury

<img align="left" width="200" height="300" src="https://user-images.githubusercontent.com/7213829/72599954-fae92780-3912-11ea-9ad4-7da273ee75dd.png">

The PowerShell Armoury is meant for pentesters, "insert-color-here"-teamers and everyone else who uses a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.

You do not have to hassle with updating nishang, powersploit, ... manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next engagement.
In addition, your new and shiny armoury is encrypted and includes a bypass for AMSI, so you dont have to worry about AV.

Note: you have to provide a valid github account as well as a personal access token, so the script can properly use the github API. Do not use username/password since this will not work anyway if you have MFA enabled (and you should enable MFA). Also accessing the API with basic username/password is deprecated.
Follow [this guide](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) to create a personal access token.
</br>
</br>

## Config reference

The config file needs to be a valid json that consists of a single array with one or more objects, where every object is interpreted as a single script source. Every object has the following attributes

**Name (Mandatory)**

A name of your choice to identify the script included in this object. This is just meant as a reference for yourself.

**URL (Mandatory)**

The location to get the script content from. This can be a URL to a web resource (https://) or a local path (C:\) or a network resource (\\...). The URL is thrown into Net.Webclient or Powershells Get-Item respectively. So basically every format that one of those two can handle by default should work.

**Type (Mandatory)**

This gives a hint about the script location to the armoury creator. There are three valid types:

- GitHub
    - Will prompt for credentials so we can authenticate against the github API. Will also try to distinguish between a "raw" URL that directly poins to a file or a URL that points to a repository. If the URL points to a repository, the script will automatically search all Powershell files in that repository and include them. Like "https://github.com/cfalta/PoshRandom"
- WebDownloadSimple
    - Means a file that can be downloaded without authentication or stuff using an HTTP GET. Like "http://mywebserver.com/file.ps1"
- LocalFile
    - A file on disk like "C:\temp\test.ps1". If the path points to a directory, all files (recursive) with the extension ".ps1" will be included. 

**FileInclusionFilter (Optional)**

Will only be interpreted in an object of type "GitHub". Will be matched with Powershells "like" comparison operator against the whole filename so keep in mind that you need to include the wildcards yourself. Don't forget to include a star (\*) if you want to match part of a filename. "*.ps1" means all files that end with ".ps1" but ".ps1" just means ".ps1".

You don't have to include a filter but if you do, you have to use it. An empty InclusionFilter means no files.

**FileExclusionFilter (Optional)**

Like the InclusionFilter but obviously the other way round. Exclusion takes precedence.

## Arguments

See inline Powershell help (man -full New-PSArmoury) for more details.

**-Path**

The path to your new armoury file. The default ist ".\MyArmoury.ps1"

**-FromFile**

Load your Powershell scripts directly from a local folder or file and you don't have to provide a config file.

**-Config**

The path to your JSON-config file. Have a look at the sample that comes with this script for ideas.

**-Password**

The password that will be used to encrypt your armoury. If you do not provide a password, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

**-Salt**

The salt that will be used together with your password to generate an AES encryption key. If you do not provide a salt, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

**-OmitPassword**

This switch will remove the plaintext password from the final armoury script. Use this if confidentiality is important to you.

**-ValidateOnly**

Use this together with "-Config" to let the script validate the basic syntax of your JSON config file without executing it.

**-Use3DES**

Encrypts with 3DES instead of AES.

**-EnhancedArmour**

Instructs your armoury to require a protectecd PowerShell process. Therefore on first execution, your armoury will not load but spawn a new PowerShell that is set to run with BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON process mitigation. This prevents non-microsoft DLLs (e.g. AV/EDR products) to load into PowerShell.
Shamelessly copied from the great @_rastamouse: https://gist.github.com/rasta-mouse/af009f49229c856dc26e3a243db185ec


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
Invoke-Rubeus -Command "kerberoast /stats"
Invoke-Bloodhound
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

If it happens that you don't remember what you put inside the armoury, just load it and call the inventory :-)

``` powershell
Get-PSArmoury
```
