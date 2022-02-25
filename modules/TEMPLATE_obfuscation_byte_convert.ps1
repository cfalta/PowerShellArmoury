#Obfuscation technique: convert .ps1 code to byte arrays and convert the byte arrays to compressed json format
function Get-PSArmouryObfuscation
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Code)

$ByteArray = [System.Text.Encoding]::UTF8.GetBytes($Code)

$ObfuscatedCode = $ByteArray | ConvertTo-Json -Compress

return $ObfuscatedCode

}

function Get-PSArmouryDeObfuscation
{

    $global:FunkyFuncs[2..$global:FunkyFuncs.Length] | % {
        
        $ObfuscatedCode = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))

        $ByteArray =  $ObfuscatedCode | ConvertFrom-Json
    
        $Code = [System.Text.Encoding]::UTF8.GetString($ByteArray)

        $Code | Invoke-Expression
    }

}