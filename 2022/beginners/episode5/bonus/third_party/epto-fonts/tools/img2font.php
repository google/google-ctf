#!/usr/bin/php
<?php
/*
 * img2font
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

function Helpex() {
?>
img2font -i <immagine> [ -o <output> ] [ -n ] --chw <val> [ --chh <val> ]
   --pxx <val> [ --pxy <val> ] --px <val> [ --py <val> ]
   --icw <val> [ --ich <val> ] [--first <val> ] [ --chars <val> ]
   [ --code <val> ] [ --name <val> ] [ --tpl <tpl> ] [ -a ]

Trasforma un immagine di un set caratteri in un font.

  -i        File immagine PNG a 24 bit da leggere.
  -o        File sorgente font da scrivere (se manca sara' STDOUT).
  -n        Attiva noise gate con livello colore minimo 0xC0 (192).
  -a        Crea sorgenge solo con caratteri ASCII (usa * per i pixel).
  --icw     Larghezza carattere nell'immagine.
  --ich     Alterzza carattere nell'immagine.
  --chw     Larghezza carattere.
  --chh     Altezza carattere.
  --px      Posizione X nel pixel del carattere immagine.
  --py      Posizione Y nel pixel del carattere immagine.
  --pxx     Larghezza pixel dell'immagine per ogni pixel del carattere.
  --pxy     Altezza pixel dell'immagine per ogni pixel del carattere.
  --first   Primo carattere.
  --chars   Numero di caratteri (totali del font).
  --code    Codifica.
  --name    Nome del font.
  --N       Rimpiazza su -o il carattere * con il nome del file.
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
	
$opt = getopt('i:o:hnaN',array('chw:','chh:','pxx:','pxy:','px:','py:','icw:','ich:','first:','chars:','code:','name:','tpl:'));
if ($opt===false or count($opt)==0 or isset($opt['h'])) Helpex();

if (isset($opt['tpl'])) {
	$x= parse_ini_file($opt['tpl'],true) or die("Errore nel template `{$opt['tpl']}`\n");
	if (!isset($x['img2font'])) die("Il file template deve iniziare con una riga [img2font] per essere vaildo.\n");
	$x=$x['img2font'];
	unset($opt['tpl']);
	unset($x['tpl']);
	$opt=array_merge($opt,$x);
	$x=null;
	}

$fileInput = getValS(@$opt['i']);
if (isset($opt['N'])) {
	$opt['o'] = str_replace('*',pathinfo($fileInput,PATHINFO_FILENAME),getValS(@$opt['o']));
	}

$chw = getVal(@$opt['icw']);
$chh = getVal(@$opt['ich'],$chw);

$pixX=getVal(@$opt['pxx'],1);
$pixY=getVal(@$opt['pxy'],$pixX);

$pointX=intval(@$opt['px'],0);
$pointY=intval(@$opt['py'] ? $opt['py'] : $pointX);

$chWi = getVal(@$opt['chw']);
if ($chWi<1 or $chWi>8) Helpex();

$chHe = getVal(@$opt['chh'],$chWi);

$chBase = intval(@$opt['first']);
$numChars=getVal(@$opt['chars'],256);

$cPage=getValS(@$opt['code'],'ASCII');
$fName=getValS(@$opt['name'],pathinfo($fileInput,PATHINFO_FILENAME));
$im = imagecreatefrompng($fileInput) or die("Immagine PNG RGB non valida `$fileInput`\n");
$noise = 0xFFFFFF;
if (isset($opt['n'])) $noise=0xC0C0C0;

if (isset($opt['o'])) ob_start();
echo "@CP $cPage\n";
echo "@FH $chHe\n";
echo "@FW $chWi\n";
echo "@MAX $numChars\n";
echo "@VER 2\n";
echo "@NAME $fName\n";

$chXx = intval(imagesx($im) / $chw);
for ($cod = $chBase; $cod<$numChars;$cod++) {
	echo "@CH $cod ; ".dechex($cod)."\n";
	
	$rawCod = $cod-$chBase;
	$charX0 = ($rawCod % $chXx) * $chw;
	$charY0 = floor($rawCod / $chXx) * $chh;
	
	for ($y=0;$y<$chHe;$y++) {
		$byte='';
		for ($x=0;$x<$chWi;$x++) {
			$px = $charX0 + $pointX + $pixX*$x;
			$py = $charY0 + $pointY + $pixY*$y;
			$rgb = imagecolorat($im,$px,$py) & $noise;
			$bit = $rgb!=0;
			if ($bit) $byte.='*'; else $byte.=' ';
			}
		$byte = str_pad($byte,8,' ',STR_PAD_RIGHT);
		$byte = substr($byte,0,8);
		if (!isset($opt['a'])) $byte = str_replace('*','█',$byte);
		echo "$byte\n";
		}
	echo "\n";
	}

if (isset($opt['o'])) file_put_contents($opt['o'],ob_get_clean()) or die("Errore output su: `{$opt['o']}`\n");
imagedestroy($im);

?>