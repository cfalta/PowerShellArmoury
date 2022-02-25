function ConvertTo-Powershell
{
<#
.SYNOPSIS

Creates powershell wrapper for a C# console application. This allows you to call a powershell function (Invoke-YourBinaryName), which internally unwraps the binary and calls
a predefined function.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Puts a copy of a C# binary inside a powershell function. The main goal is to run a C# console application like Rubeus, Seatbelt or others natively from powershell.

Example: instead of running "Rubeus.exe hash /password:123" you can then run 'Invoke-Rubeus -Command "hash /password:123"'

The name of the resulting PS function is always Invoke-"Filename" without the extension

[System.Reflection.Assembly]::Load is used to load the C# code. The "namespace","class" and "function" parameters of ConvertTo-Powershell are used to tell the resulting PS function where to pipe the commands to.

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
    $Outpath
    )

$filename = (Get-Item -LiteralPath $Path).name
$fullname = (Get-Item -LiteralPath $Path).fullname
$functionname = $filename.substring(0,$filename.lastindexof("."))
$file = [Convert]::ToBase64String([IO.File]::ReadAllBytes($fullname))

if(-not $PSBoundParameters['Namespace'] -OR -not $PSBoundParameters['Class'] -or -not $PSBoundParameters['Function'])
{
    $ep = Get-EntryPoint -Path $fullname
    if ($ep.IsPrivate)
    {
        $ldrcommand = "[" + $ep.reflectedtype.namespace + "." + $ep.reflectedtype.name + "].GetMethod('" + $ep.name + "',`$bindingFlags`)"
    }
    else {
        $ldrcommand = "[" + $ep.reflectedtype.namespace + "." + $ep.reflectedtype.name + "].GetMethod('" + $ep.name + "')"
    }
}
else {
    $ldrcommand = "[" + $namespace + "." + $class + "].GetMethod('" + $function + "')"
}

$FunctionHeader=@"
function Invoke-$functionname([string]`$Command)
{
"@

$FunctionBodyNoProtection=@"
`$Message="$file"
"@

$FunctionTrailer=@"
`$Assembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String(`$Message))
`$vars = New-Object System.Collections.Generic.List[System.Object]

foreach (`$args in `$Command.Split(" "))
{
    `$vars.Add(`$args)
}

`$passed = [string[]]`$vars.ToArray()
`$BindingFlags= [Reflection.BindingFlags] "NonPublic,Static"
`$PrivateMethod = $ldrcommand
`$PrivateMethod.Invoke`(`$Null`,@(,`$passed`))
}
"@

if(-not $Outpath)
{
    $Outpath = Join-Path (Get-Location) ("Invoke-" + $functionname + ".ps1")
}

if((Test-Path -LiteralPath $Outpath))
{
    Remove-Item -LiteralPath $Outpath -Force
}

Add-Content $Outpath $FunctionHeader
Add-Content $Outpath $FunctionBodyNoProtection
Add-Content $Outpath $FunctionTrailer

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