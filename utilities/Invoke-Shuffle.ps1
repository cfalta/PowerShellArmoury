function Invoke-Shuffle
{
    [CmdletBinding()]
    [Alias("shuffle")]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path,
    
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [int]
    $Length = 4
    
    )

    if($Path)
    {
        $fileobj = get-item $path
        if($fileobj.psiscontainer -eq $true)
        {
            Write-Output "Please supply the path to a file and not a directory"
        }else
        {
            $r = Shuffle-File -Path $fileobj.fullname
            if($r)
            {
                $r | Set-Content -Path ($fileobj.BaseName + "-shuffle" + $fileobj.Extension)
            }
        }

    }
    else
    {
        $c = Get-Clipboard
        if($c)
        {   
            $result = Convert-ToShuffle -Text $c
        }
        $result |Set-Clipboard

    }

}

function Shuffle-File
{
    [CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateScript({Test-Path $_})]
    [String]
    $Path)

    $outbuffer = @()
    $fastforward = $false
    foreach($line in [IO.File]::Readlines($Path))
    {

        if($line -eq "" -or $line.startswith("#"))
        {
            continue
        }

        if($line.contains('@"'))
        {
            $fastforward = $true
            $outbuffer += $line
            continue
        }

        if($line.contains('"@'))
        {
            $fastforward = $false
            $outbuffer += $line
            continue
        }

        if($fastforward)
        {   
            $outbuffer += $line
            continue
        }
        
        $outbuffer += Convert-ToShuffle -Text $line
    }

    $outbuffer
    
}
function Convert-ToShuffle
{
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Text)

            $c = $Text
            $varlist = New-Object -TypeName "System.Collections.ArrayList"
            $invokerbase = Get-RandomInvoker
            $invoker = $invokerbase[0]
            $go = $true
            $counter = 0
            while($go)
            {
               
                if($c.length -le $Length+1)
                {
                    $splitlength = $c.Length
                    $go = $false
                }
                else
                {
                    $splitlength = $Length
                }
                
                $varname = "$" + (Get-RandomString)
                $temp= $varname + "=" + "'" + $c.substring(0,$splitlength) + "'"

                $null=$varlist.add($temp)
                $invoker = $invoker + $varname + " + "

                $c = $c.substring($splitlength)
                $counter++
            }
       
        $invoker = $invoker.TrimEnd(" ","+")
        $invoker = $invoker + $invokerbase[1]

        $result =""
        foreach($v in $varlist)
        {
            $result = $result + "`n" + $v
        }
        $result = $result + "`n" + $invoker
        $result

}

function Get-RandomString
{
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [int]
    $Length = 5)

    if($Length -gt 0 -and $Length -lt 1024)
    {
        $Alphabet = @("0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z")
        
        for($i=1;$i -le $Length;$i++)
        {
            $RandomString += $Alphabet | Get-Random    
        }

        return($RandomString)
    }
}

function Get-RandomInvoker
{
    $InvokerTemplates = @{
        0 = @("iex(",")")
        1 = @("(",") | iex")
        2 = @("invoke-Expression -command (",")")
    }

    $count = $InvokerTemplates.count - 1
    $rand = Get-Random -Minimum 0 -Maximum $count
    $InvokerTemplates[$rand]
}