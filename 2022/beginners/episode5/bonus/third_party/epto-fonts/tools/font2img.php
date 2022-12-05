#!/usr/bin/php
<?php
/*
 * font2img
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
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT & ~E_USER_WARNING &~E_NOTICE);

$FONTINFOSTRUCT = array(		//	Struttura costante per le informazioni sui caratteri.
//			       Nome         Len  
	1	=>	array('charset'     ,0 ) ,
	2	=>	array('height'      ,1 ) ,
	3	=>	array('max'         ,2 ) ,
	4	=>	array('info'        ,0 ) ,
	5	=>	array('ver'         ,1 ) ,
	6	=>	array('name'        ,0 ) ,
	7	=>	array('map'         ,0 ) ,
	8	=>	array('mode'        ,1 ) ,
	9	=>	array('width'		,1 ) )
	;
	
function charBmp(&$im,$x0,$y0,$pal,$pixx,$pixy,&$font,$ch) {	// Da carattere a relativa bitmap (Array MxN).
	$bp = ($ch % $font['max'])*$font['height'];
	$FW = $font['width'] ? $font['width'] : 8;
	if ($FW>8) $FW=8;
	
	$bmp = substr($font['font'],$bp,$font['height']);
	for ($y = 0 ;$y<$font['height'];$y++) {
		for ($x=0;$x<$FW;$x++) {
			$bit = ord($bmp[$y]) & 1<<(7-$x);
			imagefilledrectangle($im,$x0+$x*$pixx,$y0+$y*$pixy,$pixx+$x0+$x*$pixx-1,$pixy+$y0+$y*$pixy-1,$pal[$bit ? 1:0]);
			}
		}
	return $FW;
	}
	
function getFontInfo(&$font) {	// Legge il tag delle informazioni sui caratteri.
	global $FONTINFOSTRUCT;
	$info['width'] = 8;
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
	
function data2Map($raw) {	//	Esporta un array nome => valore
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
	
function loadFont($file) { // Carica un font
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

function Helpex() {
	debug_print_backtrace();
?>
img2font -i <font> -o <immagine> [ --pxx <val> ] [ --pxy <val> ] [ -N ] 
         [ --chl <val> ] [ --tpl <val> ] [ --mktpl <val> ] [ -n ]

Trasforma un font in un'immagine.

  -i        File di font.
  -o        File immagine PNG a 24 bit da creare.
  -N        Sostituisce il carattere * nel parametri -o e --mktpl con il
             nome del file di input senza estensione.
  --mktpl   Crea il template.
  -n	    Usa la suddivisione dei caratteri.
  --pxx     Larghezza pixel dell'immagine per ogni pixel del carattere.
  --pxy     Altezza pixel dell'immagine per ogni pixel del carattere.
  --chl     Caratteri pre ogni linea.
  --tpl     Template (file ini contenente tutti i parametri con lo
            lo stesso nome della riga di comando senza "--" o "-".
  Tutti i parametri per y possono essere omessi e prendono come valore
  il parametro per x.
  Dimensione massima caratteri: 8x16.

<?	
	exit;
	}

function getVal($cur,$def=0) {
	$cur=intval($cur);
	if ($cur==0) $cur=$def;
	if ($cur<1) Helpex();
	return $cur;
	}

function getValS($cur,$def='') {
	if ($cur=='') $cur=$def;
	if ($cur=='') Helpex();
	return $cur;
	}
	
$opt = getopt('ti:o:nN',array('pxx:','pxy:','chl:','tpl:','mktpl:'));
if ($opt===false or count($opt)==0 or isset($opt['h'])) Helpex();
$div = isset($opt['n']);

if (isset($opt['tpl'])) {
	$x= parse_ini_file($opt['tpl'],true) or die("Errore nel template `{$opt['tpl']}`\n");
	if (!isset($x['font2img'])) die("Il file template deve iniziare con una riga [font2img] per essere vaildo.\n");
	$x=$x['font2img'];
	unset($opt['tpl']);
	unset($x['tpl']);
	$opt=array_merge($opt,$x);
	$x=null;
	}

$fileInput = getValS(@$opt['i']);
$fileOutput = getValS(@$opt['o']);

if (isset($opt['N'])) {
	$fileOutput = str_replace('*',pathinfo($fileInput,PATHINFO_FILENAME),$fileOutput);
	}

$font = loadFont($fileInput);
$font['width'] = $font['width'] ? $font['width'] : 8;

$maxChar = $font['max'];

$pixX=getVal(@$opt['pxx'],1);
$pixY=getVal(@$opt['pxy'],$pixX);

$charXLine = getVal(@$opt['chl'],16);

if (isset($opt['mktpl'])) {
	$tpl = array(
		'i'		=>	$fileOutput,
		'chw'	=>	$font['width'],
		'chh'	=>	$font['height'],
		'name'	=>	$font['name'],
		'code'	=>	$font['charset'],
		'pxx'	=>	$pixX,
		'pxy'	=>	$pixY,
		'chars'	=>	$font['max'],
		'first'	=>	0,
		'icw'	=>	$font['width']*$pixX,
		'ich'	=>	$font['height']*$pixY,
		'px'	=>	0,
		'py'	=>	0)
		;
	
	if ($div) {
		$tpl['icw']+=$pixX;
		$tpl['ich']+=$pixY;
		$tpl['n']='true';
		}
	
	$t0="[img2font]\n";
	foreach($tpl as $k => $v) $t0.="$k=$v\n";
	
	if (isset($opt['N'])) {
		$opt['mktpl'] = str_replace('*',pathinfo($fileInput,PATHINFO_FILENAME),$opt['mktpl']);
		}
	
	file_put_contents($opt['mktpl'],$t0) or die("Non riesco a salvare `{$opt['mktpl']}`\n");
	$t0=$tpl=null;
	}

$imgH = intval($maxChar / $charXLine) + ( ($maxChar % $charXLine)!=0 ? 1:0) ;
$imgHC = $imgH;
$imgW = $charXLine * $pixX * $font['width'];
$imgH = $imgH * $pixY * $font['height'];

if ($div) {
	$imgW+=$pixX * $charXLine;
	$imgH+=$pixY * $imgHC;
	}
	
$imgHC++;

$im = imagecreatetruecolor($imgW,$imgH);
$pal[0] = imagecolorallocate($im,0,0,0);
$pal[1] = imagecolorallocate($im,255,255,255);
if ($div) {
	$pal[2] = imagecolorallocate($im,0x20,0,0);
	$chbW = $pixX*$font['width'];
	$chbH = $pixY*$font['height'];
	$chbWf = $chbW+$pixX-1;
	$chbHf = $chbH+$pixY-1;
}
	
$FW = $div ? 1 + $font['width'] : $font['width'];
$FH = $div ? 1 + $font['height'] : $font['height'];

$cod = 0;
for ($cy = 0; $cy<$imgHC;$cy++) {
	for ($cx = 0; $cx<$charXLine; $cx++) {
		$x0 = $cx*$pixX*$FW;
		$y0 = $cy*$pixY*$FH;
		if ($div) {
			imagefilledrectangle($im,$x0+$chbW,$y0,$x0+$chbWf,$y0+$chbHf,$pal[2]);
			imagefilledrectangle($im,$x0,$y0+$chbH,$x0+$chbWf,$y0+$chbHf,$pal[2]);
			}
		charBmp($im,$x0,$y0,$pal,$pixX,$pixY,$font,$cod);
		if ($cod++>$font['max']) break;
		}
	if ($cod>$font['max']) break;
	}

imagepng($im,$fileOutput) or die("Non riesco a salvare `$fileOuptut`\n");
$font=null;
?>