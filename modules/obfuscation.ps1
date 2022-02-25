#Obfuscation technique: encrypt with RC2

function Get-PSArmouryObfuscation
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Code)

#Create a new instance of the .NET AES provider
$RC2 = [System.Security.Cryptography.RC2]::Create()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$RC2.CreateEncryptor(),[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::UTF8.GetBytes($Code)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($RC2.IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Key" -Value ([Convert]::ToBase64String($RC2.Key))

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$RC2.Clear()

return ($CryptoResult | ConvertTo-Json -Compress)

}

function Get-PSArmouryDeObfuscation
{

    $global:FunkyFuncs[2..$global:FunkyFuncs.Length] | % {
        $ObfuscatedCode = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)) | ConvertFrom-Json

        [byte[]]$CipherText = [Convert]::FromBase64String($ObfuscatedCode.CipherText)
        [byte[]]$InitVector = [Convert]::FromBase64String($ObfuscatedCode.IV)
        [byte[]]$Key = [Convert]::FromBase64String($ObfuscatedCode.Key)

        $RC2 = [System.Security.Cryptography.RC2]::Create()
        $RC2.Key = $Key
        $RC2.IV = $InitVector

        $MemoryStream = New-Object System.IO.MemoryStream($CipherText,$True)
        $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$RC2.CreateDecryptor(),[System.Security.Cryptography.CryptoStreamMode]::Read)

        $StreamReader = New-Object System.IO.StreamReader($CryptoStream)
        $Code = $StreamReader.ReadToEnd()

        $CryptoStream.Close()
        $MemoryStream.Close()
        $RC2.Clear()

        $Code | Invoke-Expression
    }

}
