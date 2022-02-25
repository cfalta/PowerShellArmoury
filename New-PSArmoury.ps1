function New-PSArmoury
{
<#
.SYNOPSIS

New-PSArmoury creates a single, obfuscated file (your armoury) containing all your favourite PowerShell scripts from multiple repositories based on a config file.

Basically it's like "apt-get update" for your offensive PowerShell arsenal.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

The PowerShell Armoury is ment for Pentesters or Auditors who use a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, obfuscated file.

You don't have to hassle with updating your tools manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next pentest.

PSArmoury also tries to circumvent AV detection, e.g. an AMSI bypass is included. However it is not meant to be fully undetectable. In fact, due to a growing user base, it is very likely that the included AMSI bypass or the resulting file will get detected by AV. 
But the idea for the tool is to be modular enough for you to handle these things with small changes to the code or output.

Note that you have to provide a valid github account as well as a personal access token, so the script can properly use the github API.

.PARAMETER Path

The path to your new armoury file. The default is ".\MyArmoury.ps1"

.PARAMETER FromFile

Load your Powershell scripts directly from a local folder or file and you don't have to provide a config file.

.PARAMETER Config

The path to your JSON-config file. Have a look at the sample that comes with this script for ideas.

.PARAMETER ModulesDirectory

The path to the modules directory. The default is ".\modules".
If ModulesDirectory is used, then the EvasionPath and ObfuscationPath Parameters cannot be used.

.PARAMETER EvasionPath

The path to the evasion script. If EvasionPath and ObfuscationPath are used, then the ModulesDirectory-Parameter cannot be used.

.PARAMETER ObfuscationPath

The path to the obfuscation script. If EvasionPath and ObfuscationPath are used, then the ModulesDirectory-Parameter cannot be used.

.PARAMETER ValidateOnly

Use this together with "-Config" to let the script validate the basic syntax of your JSON config file without executing it.

.PARAMETER GithubCredentials

Pass Github username and access token as a credential object so the script won't prompt for it. Useful if you create an armoury repeatedly for testing.

Use like this:

$c = get-credential
New-PSArmoury -GithubCredentials $c

.EXAMPLE

New-PSArmoury

Description
-----------

Execute with all defaults, which means it will:

- create a .ps1 file called "MyArmoury.ps1" in the current working directory using
- the default config ".\PSArmoury.json"
- the default AMSI bypass found at ".\modules\evasion.ps1"
- the default obfuscation script found at ".\modules\obfuscation.ps1".

.EXAMPLE

New-PSArmoury -FromFile .\myfolderfullofps1scripts\

Description
-----------

Execute with defaults (see previous example), but do not use a config to retrieve source scripts. Instead use everything found in the path supplied with "-FromFile".

.LINK

https://github.com/cfalta/PowerShellArmoury

#>
[CmdletBinding(DefaultParameterSetName = "DefaultModules")]
    Param (
        [Parameter(ParameterSetName="DefaultModules")]
        [Parameter(ParameterSetName="Validate")]
        [Parameter(ParameterSetName="ModulesByFiles")]
        [Parameter(ParameterSetName="ModulesByDirectory")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path = ".\MyArmoury.ps1",

        [Parameter(ParameterSetName="DefaultModules")]
        [Parameter(ParameterSetName="Validate")]
        [Parameter(ParameterSetName="ModulesByFiles")]
        [Parameter(ParameterSetName="ModulesByDirectory")]
        [ValidateScript({Test-Path $_})]
        [String]
        $FromFile,

        [Parameter(ParameterSetName="DefaultModules")]
        [Parameter(ParameterSetName="Validate")]
        [Parameter(ParameterSetName="ModulesByFiles")]
        [Parameter(ParameterSetName="ModulesByDirectory")]
        [ValidateScript({Test-Path $_})]
        [String]
        $Config,

        [Parameter(ParameterSetName="ModulesByDirectory")]
        [ValidateScript({Test-Path $_})]
        [String]
        $ModulesDirectory,

        [Parameter(ParameterSetName="ModulesByFiles")]
        [ValidateScript({Test-Path $_})]
        [String]
        $EvasionPath,

        [Parameter(ParameterSetName="ModulesByFiles")]
        [ValidateScript({Test-Path $_})]
        [String]
        $ObfuscationPath,

        [Parameter(ParameterSetName="Validate")]
        [Switch]
        $ValidateOnly,

        [Parameter(ParameterSetName="DefaultModules")]
        [Parameter(ParameterSetName="Validate")]
        [Parameter(ParameterSetName="ModulesByFiles")]
        [Parameter(ParameterSetName="ModulesByDirectory")]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        $GithubCredentials
    )


if(-not $PSBoundParameters.ContainsKey("Config"))
{
    $Config = Join-Path -Path (Get-Location) -ChildPath "PSArmoury.json"
}

if($PSBoundParameters.ContainsKey("GithubCredentials"))
{
    $global:GitHubCredentials = $GithubCredentials
}

function Write-Banner
{
        Write-Output "                                    %%%%%%%%%%%                                  "
        Write-Output "                   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                  "
        Write-Output "           %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%          "
        Write-Output "     %%%%%%%%%%%%%%                                           %%%%%%%%%%%%%%    "
        Write-Output "%%%%%%%%%%%%           %%%%%%%%%%%%%%%%%                             %%%%%%%%%%%"
        Write-Output " %%%%%%       %%%%%%%%%%%%%%%%%%%%%%%%%%                                  %%%%%"
        Write-Output "  %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                  %%%%% "
        Write-Output "  %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                  %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%   %%%%%%%                  %%%%        @@@@@@@@@@@@@@@@@        %%%%%  "
        Write-Output "   %%%%%   %%%%%%%     %%%%%%%%%      %%      @@@@@@        @@@@         %%%%%  "
        Write-Output "   %%%%%   %%%%%%%     %%%%%%%%%%     %%      @@@@@                      %%%%%  "
        Write-Output "   %%%%%   %%%%%%%                    %%       @@@@@@@@@@@@@@@@          %%%%%  "
        Write-Output "   %%%%%   %%%%%%%                 %%%%%            @@@@@@@@@@@@@        %%%%% "
        Write-Output "   %%%%%   %%%%%%%%     %%%%%%%%%%%%%%%%       @@@@           @@@@@      %%%%% "
        Write-Output "   %%%%%   %%%%%%%%     %%%%%%%%%%%%%%%%       @@@@@@@     @@@@@@@       %%%%% "
        Write-Output "   %%%%%   %%%%%%%%     %%%%%%%%%%%%%%%%         @@@@@@@@@@@@@@          %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%% "
        Write-Output "   %%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                                 %%%%%  "
        Write-Output "   %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%%                                %%%%%   "
        Write-Output "    %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%%                               %%%%%    "
        Write-Output "     %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%%%                              %%%%%     "
        Write-Output "       %%%%%%   %%%%%%%%%%%%%%%%%%%%%%%%                            %%%%%%      "
        Write-Output "        %%%%%%    %%%%%%%%%%%%%%%%%%%%%%                           %%%%%%       "
        Write-Output "         %%%%%%%   %%%%%%%%%%%%%%%%%%%%%                         %%%%%%         "
        Write-Output "           %%%%%%    %%%%%%%%%%%%%%%%%%%                       %%%%%%%          "
        Write-Output "             %%%%%%    %%%%%%%%%%%%%%%%%                     %%%%%%%            "
        Write-Output "               %%%%%%%    %%%%%%%%%%%%%%                   %%%%%%%              "
        Write-Output "                 %%%%%%%    %%%%%%%%%%%%                 %%%%%%%                "
        Write-Output "                   %%%%%%%     %%%%%%%%%              %%%%%%%%                  "
        Write-Output "                      %%%%%%%     %%%%%%            %%%%%%%                     "
        Write-Output "                        %%%%%%%%     %%%         %%%%%%%                       "
        Write-Output "                           %%%%%%%%           %%%%%%%%                          "
        Write-Output "                              %%%%%%%%%   %%%%%%%%%                             "
        Write-Output "                                 %%%%%%%%%%%%%%                                 "
        Write-Output "                                     %%%%%%%            `n`n"
}

function Test-PSAConfig
{
    $IsValid = $True

    if($global:PSArmouryConfig)
    {
        $Index = 0
        foreach($Item in $global:PSArmouryConfig)
        {
            if(-Not($Item.Name -and $Item.Type -and $Item.URL))
            {
                Write-Warning ("PSArmoury: Error validating item at index " + $Index + ". Name, Type and URL are mandatory.")
                $IsValid = $False
            }
            if(-Not(($Item.Type -eq "GitHub") -or ($Item.Type -eq "LocalFile") -or ($Item.Type -eq "WebDownloadSimple")))
            {
                Write-Warning ("PSArmoury: Error validating item at index " + $Index + ". Type needs to be either GitHub, LocalFile or WebDownloadSimple")
                $IsValid = $False
            }
            $Index++
        }
    }

    $IsValid
}

function Invoke-PSAGithubDownload
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $URI)

    $CredentialsBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($global:GitHubCredentials.Username + ":" + $global:GitHubCredentials.GetNetworkCredential().Password)))
    $BasicAuthHeader = ("Basic " + $CredentialsBase64)   

    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent","PSArmoury")
    $wc.Headers.Add("Authorization",$BasicAuthHeader)

    $Response = $wc.DownloadString($URI)

    $Response
}

function Get-PSAGitHubItem([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL

    $GitHubType = $False

    #Assume this is a valid file URL if it contains raw
    if($BaseURL.Contains("raw"))
    {
        $GitHubType = "File"

        $ItemName = $BaseURL.Substring($BaseURL.LastIndexOf("/")+1)

        Write-Verbose ("PSArmoury: Trying to download " + $ItemName)

        $Response = Invoke-PSAGithubDownload -URI $BaseURL

        $PSO = New-Object -TypeName PSObject
        $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
        $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ItemName
        $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

        $global:PSAInventory += $PSO
    }

    #Assume this is a repo if it starts with the repo URL prefix
    if($BaseURL.StartsWith("https://api.github.com/repos/"))
    {
        $GitHubType = "Repo"

        $Response = Invoke-PSAGithubDownload -URI $BaseURL | ConvertFrom-Json

        if($PSA.Branch)
        {
            $ContentURL = $Response.contents_url.Substring(0,$Response.contents_url.LastIndexOf("/")) + "?ref=" + $PSA.Branch
        }
        else {
            $ContentURL = $Response.contents_url.Substring(0,$Response.contents_url.LastIndexOf("/"))
        }

        $ContentIndex = Invoke-PSAGithubDownload -URI $ContentURL | ConvertFrom-Json

        $NewItem = $True

        #Discover all files in the repository and download them
        while($NewItem)
        {
            $NewItem = $False
            $ContentIndex2 = @()

            foreach($ContentItem in $ContentIndex)
            {
                
                if($ContentItem.type -eq "dir")
                {
                    $ContentIndex2 += (Invoke-PSAGithubDownload -URI $ContentItem.URL | ConvertFrom-Json)
                    
                    $NewItem = $True
                }

                if($ContentItem.type -eq "file")
                {
                    $Include = $True

                    if(($PSA.FileExclusionFilter))
                    {                
                        foreach($f in $PSA.FileExclusionFilter)
                        { 
                            if($ContentItem.Name -like $f)
                            {
                                $Include = $False
                            }
                        }
                    }
                    if(($PSA.FileInclusionFilter))
                    {
                        foreach($f in $PSA.FileInclusionFilter)
                        { 
                            if($ContentItem.Name -notlike $f)
                            {
                                $Include = $False
                            }
                        }
                    }

                    if($Include)
                    {
                        Write-Verbose ("PSArmoury: Trying to download " + $PSA.Name + "/" + $ContentItem.Name)
                                        
                        try
                        {
                            $Response = Invoke-PSAGithubDownload -URI $ContentItem.download_url

                            $PSO = New-Object -TypeName PSObject
                            $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
                            $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ContentItem.Name
                            $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

                            $global:PSAInventory += $PSO
                        }
                        catch
                        {
                            Write-Warning ("PSArmoury: Error while downloading " + $PSA.Name + "/" + $ContentItem.Name)
                            Write-Warning $Error[0]
                        }           
                    }
                }
            }

            $ContentIndex = $ContentIndex2
        }
    }

    if(-not $GitHubType)
    {
        Write-Warning "Invalid GitHub URL. Only URLs to GitHub repos (starting with https://api.github.com/repos/...) or raw files (containing /raw/ in the URL) are allowed."
    }
}

function Get-PSALocalFile([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    if(Test-Path $PSA.URL)
    {
        if((Get-Item -LiteralPath $PSA.URL).PSISContainer)
        {
            $Files = Get-Childitem -LiteralPath $PSA.URL -Filter *.ps1
        }
        else 
        {
            $Files = Get-Item -LiteralPath $PSA.URL         
        }

        foreach($f in $Files)
        {
            $PSO = New-Object -TypeName PSObject
            $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
            $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $f.name
            $PSO | Add-Member -MemberType NoteProperty -Name Code -Value (get-content -raw $f.fullname)
    
            $global:PSAInventory += $PSO
        }

    }
    else {
        Write-Warning ("PSArmoury: Error while reading local file " + $PSA.URL)
    }
}

function Get-PSASimpleWebDownload([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL
    $ItemName = $BaseURL.Substring($BaseURL.LastIndexOf("/")+1)
    
    try
    {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent","PSArmoury")
    
        $Response = $wc.DownloadString($BaseURL)

        $PSO = New-Object -TypeName PSObject
        $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
        $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ItemName
        $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

        $global:PSAInventory += $PSO
    }
    catch
    {
        Write-Warning ("PSArmoury: Error while downloading " + $PSA.Name + "/" + $ItemName)
    }
    
}

function Add-Inventory
{
    $Content = 'function Get-PSArmoury{$i=@('

    foreach($Item in $global:PSAInventory)
    {
        $Content = $Content + '"' + $Item.Name + '",'
    }

    $Content = $Content.Trim(",")
    $Content = $Content + ');$i}'

    $PSO = New-Object -TypeName PSObject
    $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value "Inventory"
    $PSO | Add-Member -MemberType NoteProperty -Name Name -Value "Inventory"
    $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Content

    $global:PSAInventory += $PSO
}

function Add-Evasion
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path)
    
    
    if($Path)
    {

        $Content = Get-Content -Raw $Path

    }
    else {

        $Content = 'echo "This Armoury does not include evasion techniques. Beware of AV alerts coming up."'
    }

    $ContentB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Content))
    
    $null = $global:PSAProcessedInventory.Add($ContentB64)
}


function Write-LoaderFile
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Path)


$LoaderStub=@"
foreach(`$ef in `$global:FunkyFuncs[0..1])
{
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$ef)) | Invoke-Expression 
} 
"@

    #Delete the outputfile if it exists

    if((Test-Path -LiteralPath $Path))
    {
        Remove-Item -LiteralPath $Path -Force
    }

    #Creates a string array of encrypted scripts, which will be included in the decryption stub defined above
    $SummaryArrayDefinition = '$global:FunkyFuncs = @('
    $ArrayItemPrefix = '$Func'

    $counter = 0

    foreach($Item in $global:PSAProcessedInventory)
    {
        $SingleArrayDefinition = (($ArrayItemPrefix + $counter) + ' = ("' + $Item + '")')
   
        $SummaryArrayDefinition += (($ArrayItemPrefix + $counter) + ",")

        Add-Content $Path $SingleArrayDefinition

        $counter++
    }

    $SummaryArrayDefinition = $SummaryArrayDefinition.TrimEnd(",")
    $SummaryArrayDefinition += ")"

    #Write the string array into the loader file
    Add-Content $Path $SummaryArrayDefinition

    #Write minimal loader stub
    Add-Content $Path $LoaderStub


}

### MAIN ###

$ScriptRequirements = $True

Write-Banner

if($FromFile)
{
    $PSO = New-Object -TypeName PSObject
    $PSO | Add-Member -MemberType NoteProperty -Name "Name" -Value "LocalRepo"
    $PSO | Add-Member -MemberType NoteProperty -Name "Type" -Value "LocalFile"
    $PSO | Add-Member -MemberType NoteProperty -Name "URL" -Value $FromFile

    $global:PSArmouryConfig = @()
    $global:PSArmouryConfig += $PSO
}
else 
{

        if($Config)
        {
                try
                { 
                    $global:PSArmouryConfig = Get-Content -Raw $Config | ConvertFrom-Json
                    $ScriptRequirements = Test-PSAConfig
                    if($ValidateOnly -and $ScriptRequirements)
                    {
                        Write-Output "PSArmoury: No issues found in $($Config)."
                        $ScriptRequirements = $False
                    }         
                }
                catch
                {
                    Write-Warning "PSArmoury: Error while loading configuration file."
                    Write-Warning $Error[0]
                    $ScriptRequirements = $False
                }
        }
        else
        {
            Write-Warning "PSArmoury: No configuration file found. Please provide a valid configuration and try again."
            $ScriptRequirements = $False
        }
    
}

if($ScriptRequirements)
{
    if($PSArmouryConfig -and ($PSArmouryConfig.count -gt 0))
    {
               
        $DoObfuscation = $False
        $DoEvasion = $False

        if($ObfuscationPath -or $EvasionPath)
        {
            if($ObfuscationPath)
            {
                $ModulesObfuscation = $ObfuscationPath
                Write-Output ("PSArmoury: Obfuscation script set to " + $ModulesObfuscation)
                $DoObfuscation = $True
            }
            if($EvasionPath)
            {
                $ModulesEvasion = $EvasionPath
                Write-Output ("PSArmoury: Evasion script set to " + $ModulesEvasion)
                $DoEvasion = $True
            }

            
        }
        else 
        {   
            if(-not $PSBoundParameters.ContainsKey("ModulesDirectory"))
            {
                Write-Output ("PSArmoury: No module path submitted by user. Trying to locate default modules directory.")

                $DefaultModulesPath = Join-Path -Path (Get-Location) -ChildPath "modules"
                if(Test-Path $DefaultModulesPath)
                {
                    $ModulesDirectory = $DefaultModulesPath
                }
            }
            if($ModulesDirectory)
            {
                $ModulesObfuscation = Join-Path -Path $ModulesDirectory -ChildPath "obfuscation.ps1"
                $ModulesEvasion = Join-Path -Path $ModulesDirectory -ChildPath "evasion.ps1"
            
                Write-Output ("PSArmoury: --> Modules directory is " + $ModulesDirectory)
            
                if((Test-Path -Path $ModulesObfuscation))
                {
                    Write-Output ("PSArmoury: --> Obfuscation script is " + $ModulesObfuscation)
                    $DoObfuscation = $True
                }
                if((Test-Path -Path $ModulesEvasion))
                {
                    Write-Output ("PSArmoury: --> Evasion script is " + $ModulesEvasion)
                    $DoEvasion = $True
                }
            }

        }

        if(-not $DoObfuscation -or -not $DoEvasion)
        {
            if(-not $DoObfuscation)
            {
                Write-Warning "PSArmoury: --> No obfuscation script found!"
            }
            if(-not $DoEvasion)
            {
                Write-Warning "PSArmoury: --> No evasion script found!"
            }
            Write-Warning "Do you really want to continue? Press [Enter] to move on or [Ctrl+C] to abort."
            $null = Read-Host
        }

        Write-Output ("PSArmoury: Your armoury contains " + $PSArmouryConfig.count + " repositories. Starting to download.")

        $global:PSAInventory = @()

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        foreach($PSA in $PSArmouryConfig)
        {
            switch($PSA.Type)
            {
                GitHub{

                    if(-Not $global:GitHubCredentials)
                    {
                        $global:GitHubCredentials = Get-Credential -Message "Please enter Github username and access token"
                    }

                    Write-Output ("PSArmoury: Downloading repository " + $PSA.Name)
                    Get-PSAGitHubItem($PSA.Name)

                }

                WebDownloadSimple{

                    Write-Output ("PSArmoury: Downloading repository " + $PSA.Name)
                    Get-PSASimpleWebDownload($PSA.Name)

                }

                LocalFile{

                    Write-Output ("PSArmoury: Downloading repository " + $PSA.Name)
                    Get-PSALocalFile($PSA.Name)

                }

                default{

                }
            }
        }

        if($global:PSAInventory)
        {
            Write-Output "PSArmoury: Download complete, starting processing"
            $global:PSAProcessedInventory = New-Object -TypeName "System.Collections.ArrayList"
            $Identifier = 0

            Add-Inventory

            if($DoEvasion)
            {
                Add-Evasion -Path $ModulesEvasion
            }
            else {
                Add-Evasion
            }


            if($DoObfuscation)
            {
                   #loading module code
                   cat -raw $ModulesObfuscation | iex

                   #load deobfuscation script into output variable
                   $DeObfuscationScript= (Get-Command Get-PSArmouryDeObfuscation).ScriptBlock
                   $null = $global:PSAProcessedInventory.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($DeObfuscationScript)))

                   #Obfuscate
                   foreach($Item in $global:PSAInventory)
                   {
                       $ObfuscatedCode = Get-PSArmouryObfuscation -Code $Item.Code
                       $null = $global:PSAProcessedInventory.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ObfuscatedCode)))
                   }
       
            }
            else {
                    foreach($Item in $global:PSAInventory)
                    {
                         $null = $global:PSAProcessedInventory.Add([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Item.Code)))
                    }
            }


            Write-Output "PSArmoury: Script processing complete, creating armoury file. Happy hacking :-)"

            Write-LoaderFile -Path $Path
        }
        else
        {
            Write-Output "PSArmoury: You're venturing on a forbidden path - turn around before darkness consumes you!!! ...no seriously, this is an else-branch you should never reach cause this means that mandatory variables are not set correctly. Most likely a programming mistake - sorry ;-)"   
        }
    }
}
}