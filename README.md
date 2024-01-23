> [!IMPORTANT]  
> This repository is now archived. Though it was a fun journey, I think PSArmoury has outlived its usefulness.
</br>

# PowerShellArmoury

<img align="left" width="200" height="300" src="https://user-images.githubusercontent.com/7213829/72599954-fae92780-3912-11ea-9ad4-7da273ee75dd.png">

The PowerShell Armoury is meant for pentesters, "insert-color-here"-teamers and everyone else who uses a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, obfuscated file.

You do not have to hassle with updating Rubeus, PowerView, ... manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next engagement.
In addition, PSArmoury obfuscates your code and comes with an included AMSI bypass. The modular design should it make it easy for you to change the evasion or obfuscation code in case there's a detection on that.

</br>
</br>

## General structure

The current version of PSArmoury favours a modular design. 

```
 New-PSArmoury.ps1
 PSArmoury.json
 utilities
    ConvertTo-Powershell.ps1
    Invoke-Shuffle.ps1
 modules
    evasion.ps1
    obfuscation.ps1
```

The code is split into a main generator script called `New-PSArmoury.ps1`, which is the one you execute. The code for evasion, obfuscation and deobfuscation is stored in separate .ps1 files in the `modules` directory. These separate files are invoked by the main script and should make it easier for you to change specific functions (like an AMSI bypass).
In addition to the modules directory, there's also the `utilities` directory. Here you'll find standalone scripts that can be useful in specific scenarios.

## The modules directory

The default path of the modules directory is `.\modules` where the dot refers to the current working directory of your shell. You can change the path of the modules directory by using the `-ModulesDirectory` argument of `New-PSArmoury`. 
The names of the script files themselves however are hard-coded in the main script and always expected to be:

- evasion.ps1
- obfuscation.ps1

Let's have a closer look at these two.

### evasion.ps1

This script should contain the code intended to bypass whatever you intend to bypass. By default, it contains a well-known AMSI bypass (thanks amsi.fail).
Please note that:
- the code in here runs BEFORE everything else runs (e.g. deobfuscation)
- there is absolutely NO KIND OF VALIDATION! Everything you put here will be piped to IEX as is.

### obfuscation.ps1

This script should contain the code used for obfuscation and deobfuscation. The default obfuscation.ps1 uses RC2 encryption. Ready-to-use examples:

- TEMPLATE_obfuscation_RC2.ps1 --> this is the default
- TEMPLATE_obfuscation_byte_convert.ps1
- TEMPLATE_obfuscation_empty.ps1

Note that the `TEMPLATE_obfuscation_empty.ps1` really does nothing at all and serves as a template for you to build your own function.

If you want to use any one of those, just rename it to "obfuscation.ps1" and delete the default file.

If you want to create a customized version, keep the following in mind regarding obfuscation:
- The function name MUST always be "Get-PSArmouryObfuscation" with a single string-parameter called "Code" cause that's what the main script will call on any item you want to put in the armoury.
- The function SHOULD return the obfuscated version of the code again as a single string value. The main code of the scripts runs an additonal base64 encode/decode loop to make sure that we can also handle other stuff you throw at it but it would be easier if you could just make it a string ;-)
- The corresponding deobfuscation function MUST understand whatever you return here. The main script is just passing around results --> no magic happens here

And make sure to remember these things in terms of deobfuscation:
- The function name MUST always be Get-PSArmouryDeObfuscation with no parameter since it itterates over a fixed, global variable.
- The function MUST return the deobfuscated version of the code again as a single string value, ready to execute. We are just piping everything you return into IEX so the rest is up to you.

## The utilities directory

The utilities directory contains useful standalone scripts.

- ConvertTo-Powershell.ps1
    - Converts a console c# application into a powershell script. For more details, see [the corresponding blog post](https://cyberstoph.org/posts/2020/09/convertto-powershell-wrapping-applications-with-ps/).
- Invoke-Shuffle.ps1
    - A simple obfuscation script that converts a single line of code into multiple variables holding parts of the original string that are then merged and invoked during execution.

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

**-ModulesDirectory**

The path to the modules directory. The default is ".\modules".
If ModulesDirectory is used, then the EvasionPath and ObfuscationPath Parameters cannot be used.

**-EvasionPath**

The path to the evasion script. If EvasionPath and ObfuscationPath are used, then the ModulesDirectory-Parameter cannot be used.

**-ObfuscationPath**

The path to the obfuscation script. If EvasionPath and ObfuscationPath are used, then the ModulesDirectory-Parameter cannot be used.

**-ValidateOnly**

Use this together with "-Config" to let the script validate the basic syntax of your JSON config file without executing it.

**-GithubCredentials**

Pass Github username and access token as a credential object so the script won't prompt for it. Useful if you create an armoury repeatedly for testing.

Use like this:

``` powershell
$c = get-credential
New-PSArmoury -GithubCredentials $c
```

## Github access token

You have to provide a valid github username as well as a personal access token, so the script can properly use the github API. Do not use username/password since this will not work anyway if you have MFA enabled (and you should enable MFA). Also accessing the API with basic username/password is deprecated.

Follow [this guide](https://docs.github.com/en/github/authenticating-to-github/creating-a-personal-access-token) to create a personal access token. 

**Please note: the only permission we need on the access token is `public_repo` in the `repo` section.**

This is because you only need the token so Github won't block us if you parse larger repositories (like PowerSploit) for .ps1 files to include.

## Example usage

### Example 1 - All default

If you want to create an armoury with default settings (note: this will not obfuscate at all besides base64 encoding), then just run the following.

``` powershell
. .\New-PSArmoury.ps1
New-PSArmoury
```
This will create a .ps1 file called "MyArmoury.ps1" in the current working directory using
- the default config ".\PSArmoury.json"
- the default AMSI bypass found at ".\modules\evasion.ps1"
- the default obfuscation/deobfuscation (base64) found at ".\modules\obfuscation.ps1" and ".\modules\deobfuscation.ps1" respectively.

You can load the armoury into your current session by using

``` powershell
cat -raw .\MyArmoury.ps1 | iex
```

Loading your armoury invokes the following steps:
* Invoke evasion code
* Hand over control to the deobfuscation function which in turn should
* Go over every obfuscated item and 
    * deobfuscate
    * pipe into IEX

After that, all powershell code you put in the armoury will be available. Just invoke the cmdlets as usual like this

``` powershell
Invoke-Rubeus -Command "kerberoast /stats"
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

If it happens that you don't remember what you put inside the armoury, just load it and call the inventory :-)

``` powershell
Get-PSArmoury
```

### Example 2 - Use the byte-convert/json-format obfuscation technique that comes with PSArmoury and different config file

Start New-PSArmoury with the `-EvasionPath` and `-ObfuscationPath` Parameters like this:

``` powershell
New-PSArmoury -Config C:\myarmouryconfig.json -ObfuscationPath .\modules\TEMPLATE_obfuscation_byte_convert.ps1 -EvasionPath .\modules\evasion.ps1
```

### Example 3 - Create an armoury from a local folder containing powershell scripts

Note: in this case, all .ps1 files in the folder will be added since we submit a folder path. If we submit the path to a single file, then only that file we be processed.

``` powershell
New-PSArmoury -FromFile C:\myscriptfolder
```
