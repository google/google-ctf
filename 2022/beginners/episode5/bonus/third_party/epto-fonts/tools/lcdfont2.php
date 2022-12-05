#!/usr/bin/php
<?php
/*
 * lcdfont2
 * Copyright (C) 2016 by EPTO
 * Questo file è parte del progetto "EPTO-Fonts".
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This source code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this source code; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Questo file è codificato in UTF-8 senza BOM.
 * 
 * Meglio zittire i notice, non dovrebbero esserci, ma parliamo pur sempre di PHP!
 * Visto che negli ultimi anni ne hanno inventate di nuove ad ogni versione... non si sa mai!
 */
 
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_USER_WARNING &~E_NOTICE);

////////////// Sezione font e caratteri.

$FONTINFOSTRUCT = array(		//	Struttura costante per le informazioni sui caratteri.
//			       Nome         Len   Comando    Multi token  
	1	=>	array('charset'     ,0   ,'@CP'      ,false ) ,
	2	=>	array('height'      ,1   ,'@FH'      ,false ) ,
	3	=>	array('max'         ,2   ,'@MAX'     ,false ) ,
	4	=>	array('info'        ,0   ,'@INF'     ,true  ) ,
	5	=>	array('ver'         ,1   ,'@VER'     ,false ) ,
	6	=>	array('name'        ,0   ,'@NAME'    ,true)   ,
	7	=>	array('map'         ,0   ,'@CHR'     ,false ) ,
	8	=>	array('mode'        ,1   ,'@MOD'     ,false ) ,
	9	=>	array('width'		,1	 ,'@FW'		 ,false ) )
	;

/*
 * Il tag delle informazioni sui font è un sistema prodotto nel 1992
 * per salvare informazioni sui font bitmap.
 * Parte del supporto è stato rimosso (font più o meno larghi di 8 pixel).
 * */

function data2Map($raw) {
	$map=array();
	$j = strlen($raw);
	$i = 0;
	for ($fi=0;$fi<$j;$fi++) {
		$cx=ord($raw[$i++]);
		if ($cx==0) break;
		$t0='';
		for ($si = 0; $si<$cx; $si++) {
			$t0.=$raw[$i++];
			}
		$cx=ord($raw[$i++]);
		$t1='';
		for ($si = 0; $si<$cx; $si++) {
			$t1.=$raw[$i++];
			}
		$map[$t0]=$t1;
		}
	return $map;
	}

function getFontInfo(&$font) {	// Legge il tag delle informazioni sui caratteri.
	global $FONTINFOSTRUCT;
	
	$bp = strlen($font)-1;
	if ($bp<6) return false;
	$t0 = substr($font,$bp-5);
	if (strpos($t0,'INFO')===2) {
		$t0 = unpack('v',$t0);
		$t0 = $t0[1];
		$bp -=$t0;
		$bp-=4;
		if ($bp<5 or $bp>strlen($font)) return false; 
		$t0 = substr($font,$bp);
		$info=array();
		$j = strlen($t0);
		$i=0;
		for ($fi=0;$fi<$j;$fi++) {
			$ch=ord($t0[$i++]);
			if ($ch==0) break;
			if (isset($FONTINFOSTRUCT[$ch])) {
					$ji = $t0[$i++].$t0[$i++];
					$ji = unpack('v',$ji);
					$ji = $ji[1];
					
					$t1='';
					for ($ii=0;$i<$j && $ii<$ji;$ii++) {
						$t1.=$t0[$i++];
						}
					$ji = $FONTINFOSTRUCT[$ch][1];
					if ($ji>0) {
						$t1=str_pad($t1,2,chr(0),STR_PAD_RIGHT);
						$t1=unpack('v',$t1);
						$t1=$t1[1];
						}
					$info[ $FONTINFOSTRUCT[$ch][0] ] = $t1;
				} else {
					$ji = ord($t0[$i++]);
					$i+=$ji;
				}
			}
		$font = substr($font,0,$bp);
		return $info;
		} else return false;
	}

function loadFont($file) {
	$font = file_get_contents($file) or die("Errore nel file font.\n");
	$inf = getFontInfo($font);
	if (!is_array($inf)) $inf=array('ver' => 1);
	if (!isset($inf['max'])) $inf['max']=256;
	if (!isset($inf['charset'])) $inf['charset']='CP437';
	if (!isset($inf['height'])) $inf['height'] = strlen($font) >=3072 ? 16: 8; // 8x256 byte = font 8x8, 16x256 byte = font 8x16. Ho messo una via di mezzo perchè alcuni file hanno roba alla fine.
	if (isset($inf['map'])) $inf['map'] = data2Map($inf['map']);
	$inf['font'] = $font;
	$font=null;
	return $inf;
	}

function charBmp(&$font,$ch) {	// Da carattere a relativa bitmap (Array MxN).
	$ch = $ch % $font['max'];
	$bp = $ch*$font['height'];
		
	$bmp = substr($font['font'],$bp,$font['height']);
	$map = array_pad(array(),8,array_pad(array(),$font['height'],0));
	for ($y = 0 ;$y<$font['height'];$y++) {
		for ($x=0;$x<8;$x++) {
			$bit = ord($bmp[($font['height']-1) - $y]) & 1<<(7^$x);
			$map[$x][$y] = $bit ? 1:0;
			}
		}
	return $map;
	}

function nonZero(&$font,$ch) {	//	Ritorna true se un carattere non è vuoto.
	$ch = $ch % $font['max'];
	$bp = $ch*$font['height'];
	
	$bmp = substr($font['font'],$bp,$font['height']);
	$ori=0;
	$cx = strlen($bmp);
	for ($ax=0;$ax<$cx;$ax++) $ori|=ord($bmp[$ax]);
	return $ori==0?false:true;
	}

// Uso getopt, non è il metodo migliore. Usare con cura!
$par = getopt("i:o:f:cvVr");
if (!isset($par['i']) or !isset($par['o']) or $par['i']=='' or $par['o']=='') {
exit("lcdfont2 -i <binaryFont> -o <LEDKFont> [-V] [-v] [-r] [-c] [-f <firstChar>]
		-V -v	Verbose.
		-i	Imposta il font binario in lettura.
		-o	Imposta il file da creare.
		-r	Imposta la modalita`mirror.
		-c	Cerca il primo carattere.
		-f	Imposta manualmente il primo carattere.
		
");
}

$font = loadFont($par['i']);
if ($font['height']>7) echo "Warning: Il font sarà tagliato verticalmente.\n";

if (isset($par['f'])) {
	$font['first'] = intval($par['f']);
	if ($font['first']>=$font['max']) die("Errore sul parametro -f\n");
	} else {
	if (isset($par['c'])) {
		if (isset($par['v'])) echo "Ricerca dei caratteri...\n";
		for ($i=0;$i<$font['max'];$i++) {
			$font['first']=0;	
			if (nonZero($font,$i)) {
				$font['first']=$i;
				break;
				}
			}
		for ($i=$font['max'];$i>=$font['first'];$i--) {
			if (nonZero($font,$i)) {
				$font['max']=$i;
				break;
				}
			}
		} else {
		$font['first']=0;	
		}
	}

if ($font['max']>255) {
	$font['max']=255;
	echo "Warning: Saranno considerati solo i primi 256 caratteri.\n";
	}
	
if (isset($par['v'])) echo "Primo carattere: {$font['first']}\nMax Caratteri: {$font['max']}\nFont: {$font['width']}x{$font['height']}\n";

$head=chr($font['first']&255).chr($font['max']&255);
$t0 = $font['width']&15;
$t1 = $font['height'];
if ($t1>7) $t1=7;
$font['outh'] = $t1;
$head.=chr($t0).chr($t1);
$out='';
$verbose = isset($par['V']);
$rev = isset($par['r']);

for ($ch=$font['first'];$ch<$font['max'];$ch++) {
	$bmp = charBmp($font,$ch);
	if ($verbose) echo "\n";
	$charBmp='';
	$kernLeft=0;
	$kernRight=0;
	$kernStat=0;

	for ($x=0;$x<$font['width'];$x++) {
		$byte=0;
		if ($rev) $xx = $font['width']-$x-1; else $xx=$x;
		
		for ($y=0;$y<$font['outh'];$y++) {
			if ($bmp[$xx][$y]!=0) {
				$byte|=pow(2,$y);
				if ($verbose) echo '*';
				} else {
				if ($verbose) echo '.';
				}
			}
			
			if ($kernStat==0) {
				if ($byte==0) $kernLeft++; else $kernStat=1;
			}
			
			if ($kernStat!=0 and $byte!=0) $kernRight++;
			
			$charBmp.=chr($byte);
			if ($verbose) echo "\n";
		}
		
	if ($kernStat==0) {
		$kernLeft=0;
		$kernRight=$font['width']>>1;
		}
	
	if ($ch>127) {
		$kernByte=0xff; 
		} else {
		$kernByte = ( ($kernLeft & 15 )<<4 ) | ($kernRight&15) ;
		}
	
	if ($verbose) echo "KL $kernLeft\nKR $kernRight\n\n";
	$out.=chr($kernByte).$charBmp;
	
	}

$out = 'LEDK'.$head.$out;	
file_put_contents($par['o'],$out) or die("Errore nel file di output `{$par['o']}`\n");
$out='';

?>
