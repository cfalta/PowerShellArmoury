#This function is used to obfuscate Powershell Code.
#It takes a string as an argument and returns the obfuscated version.
#The function is expected to always has the following format:

function Get-PSArmouryObfuscation
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Code)

#### Your changes in here but return the result in the $ObfuscatedCode variable

        $ObfuscatedCode = $Code

#### Your changes in here but return the result in the $ObfuscatedCode variable

   return $ObfuscatedCode
 }

# Attention:
#
# The function name MUST always be "Get-PSArmouryObfuscation" with a single [string] parameter called "Code".
# The function SHOULD return the obfuscated version of the code again as a single string value. The main code of the scripts runs an additonal base64 encode/decode loop to make sure that we can also handle other stuff you throw at us but it would be easier if you could just make it a string ;-)
# The corresponding deobfuscation function MUST understand whatever you return here. The main script is just passing around results, no magic happens here.
#

###########

# This function is used to deobfuscate the code.
# It itterates over a global array that is set by the main loader function. This array contains the obfuscated functions.
# The function is expected to always has the following format:

function Get-PSArmouryDeObfuscation
{

    $global:FunkyFuncs[2..$global:FunkyFuncs.Length] | % {
        
        $ObfuscatedCode = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))

#### Your changes in here but return the result in the $Code variable

        $Code = $ObfuscatedCode

#### Your changes in here but return the result in the $Code variable

        $Code | Invoke-Expression
    }

}

# Attention:
#
# The function name MUST always be Get-PSArmouryDeObfuscation with no parameter since it itterates over a fixed, global variable.
# The function MUST return the deobfuscated version of the code again as a single string value, ready to execute. As you see, we are just piping everything you return into IEX so the rest is up to you.
#