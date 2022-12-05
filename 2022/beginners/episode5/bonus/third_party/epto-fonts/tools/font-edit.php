#!/usr/bin/php
<?php
/*
 * font-edit
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

$FONTINFOSTRUCTREV = array(		//	Comandi per i font.
	'@//'	=>	0,
	'@CP'	=>	1,
	'@FH'	=>	2,
	'@MAX'	=>	3,
	'@INF'	=>	4,
	'@VER'	=>	5,
	'@NAME'	=>	6,
	'@CHR'	=>	0,
	'@MOD'  =>  8,
	'@FW'	=>	9)
	;

/*
 * Il tag delle informazioni sui font è un sistema prodotto nel 1992
 * per salvare informazioni sui font bitmap.
 * Parte del supporto è stato rimosso (font più o meno larghi di 8 pixel).
 * */

function map2Data($map) {
	$raw='';
	foreach($map as $k => $v) {
		$raw.=chr( strlen($k) ) .$k . chr( strlen($v) ).$v;
		}
	$raw.=chr(0).chr(0);
	return $raw;
	}

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

function setFontInfo(&$font,$info) {	//	Scrive le informazioni sui caratteri.
	global $FONTINFOSTRUCT;
	$raw='';
	
	foreach($FONTINFOSTRUCT as $k => $v) {
		$id = $v[0];
		if (!isset($info[$id])) continue;
		$raw.=chr($k);
		$sz = $v[1] ? $v[1] : strlen($info[$id]);
		if ($sz == 1) 
			$dta = chr($info[$id]); 
			else if ($sz == 2) 
			$dta = pack('v',$info[$id]);
			else 
			$dta=$info[$id];
		$raw.=pack('v',$sz);
		$raw.=$dta;
		}
	$raw.=chr(0);
	$raw.=pack('v',strlen($raw)+1).'INFO';
	$font.=$raw;
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

function saveFont($file,$font) {
	$raw = $font['font'];
	
	if (@$font['ver']) {
		unset($font['font']);
		if (isset($font['map'])) $font['map'] = map2Data($font['map']);
		setFontInfo($raw,$font);
		}
	
	file_put_contents($file,$raw) or die("Non riesco a salvare il font.\n");
	}

function charBmp(&$font,$ch) {	// Da carattere a relativa bitmap (Array MxN).

	$bp = $ch*$font['height'];
	$ch = $ch % $font['max'];
	
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

function showChar($map,$ch) {	// Estrae il carattere.
	$fontHeight = count($map[0]);
	echo "@CH $ch ; 0x".dechex($ch)."\n";
	for ($y=0;$y<$fontHeight;$y++) {
		for ($x=0;$x<8;$x++) {
			$b = $map[$x][($fontHeight-1)^$y];
			echo $b ? '█' : ' ';
			}
		echo "\n";
		}
	echo "\n";
	}

// Uso getopt, non è il metodo migliore. Usare con cura!
$par = getopt("i:u:o:p:h:m:NA",array('dump:','update:','show-map:','cp:'));

// Guida con -h -? oppure senza argomenti.
if ($par===false or @$argv[1]=='-?' or count($argv)<2) {
	echo "Strumento di manipolazione dei font.\n\n";
	echo "font-edit [ -h <fontH> ] { -d <font> | -u <textFont> -o <fontFile> }\n";
	echo "font-edit [ -h <fontH> ] { --dump <font> | --update <font> }\n";
	echo "font-edit [ -h <fontH> ] [ -m <maxChar> ] [ -p <ptr> ] -i <rawFont> -o <font>\n";
	echo "          [ --cp <charSet> ]\n";
	echo "font-edit --show-map <fontFile>\n\n";
	
	echo "  -d --dump    Estrae il font come file TXT\n";
	echo "  -u --update  Converte un font di testo in file binario.\n";
	echo "  -o           Imposta il file di uscita.\n";
	echo "  -N           Sostituisce il carattere * sul parametro -o con il nome del file\n";
	echo "               da leggere.\n";  
	echo "  -i           Converte un font raw in font92.\n";
	echo "  -p           Imposta un puntatore per l'inizio della tabella\n";
	echo "               dei caratteri.\n";
	echo "  -h { 8|16 }  Forza l'altezza dei caratteri.\n";
	echo "  -m           Imposta il numero di caratteri durante la conversione.\n";
	echo "  --cp         Imposta il charset durante la conversione.\n";
	echo "  --show-map   Visualizza i caratteri definiti con i nomi.\n";
	echo "     N.B.: I file di testo sono in formato: UTF-8 senza BOM, acapo = NL\n\n";
	exit;
	}

if (isset($par['d']) and isset($par['dump'])) die("C'è qualquadra che non cosa!\n");
if (isset($par['u']) and isset($par['update'])) die("C'è qualquadra che non cosa!\n");
if (isset($par['i']) and (isset($par['d']) or isset($par['u']) or isset($par['dump']) or isset($par['update']))) die("C'è qualquadra che non cosa!\n");

if (isset($par['update'])) $par['u'] = $par['update'];
if (isset($par['dump'])) $par['d'] = $par['dump'];

if (isset($par['show-map'])) {
	$font = loadFont($par['show-map']);
	if (!isset($font['map'])) exit;
	
	foreach($font['map'] as $km => $vm) {
				echo "@CHR ".str_pad($km,16)." U".wordwrap(bin2hex($vm),4,'-U',true)."\n";
				}
	exit;
	}

if (isset($par['N'])) {
	$fi0=false;
	foreach(array('dump','d','update','u') as $k0) {
		if (isset($par[$k0]) and $par[$k0]!='') {
			$fi0=$par[$k0];
			break;
			}
		}
		
	if ($fi0===false) die("Errore specifiche file input!\n");
	$par['o'] = str_replace('*',pathinfo($fi0,PATHINFO_FILENAME),@$par['o']);
	}

if (isset($par['i']) and isset($par['o'])) {
	$ptr = isset( $par['p'] ) ? intval($par['p']) : 0;
	$he = isset( $par['h'] ) ? intval($par['h']) : 8;
	$font = array(
			'height'	=>	$he		,
			'charset'	=>	isset($par['cp']) ? $par['cp'] : 'CP437'	,
			'max'		=>	isset($par['m']) ? intval($par['m']) : 256	,
			'ver'		=>	1											,
			'font'		=>	null)
		;
	
	$f = fopen($par['i'],'rb') or die("Errore nel file font.\n");
	$sz = filesize($par['i']);
	if ($ptr<0 or $ptr>=$sz) die("Errore nel puntatore -p\n");
	fseek($f,$ptr,SEEK_SET);
	$font['font'] = @fread($f,$font['max'] * $font['height']);
	if ($font['font']===false) die("Errore di lettura.\n");
	$cn = strlen($font['font']) / $font['height'];
	if ($cn!=$font['max']) {
		$font['max'] = floor($cn);
		echo "Attenzione: Da questa posizione ci sono solo {$font['max']} caratteri.\n";
		$sz = $cn * $font['max'];
		$font['font']=substr($font['font'],0,$sz);
		}
	saveFont($par['o'],$font);
	exit;
	}

if (isset($par['d']) and isset($par['u'])) die("C'è qualquadra che non cosa!\n");

if (isset($par['d'])) {
	$font = loadFont($par['d']);
	if (isset($par['h']) and $par['h']==8) $font['height']=8;
	if (isset($par['h']) and $par['h']==16) $font['height']=16;
	ob_start();
	foreach($FONTINFOSTRUCT as $k => $v) {
		$id = $v[0];
		$cmd = $v[2];
		if ($cmd=='@CHR' and isset($font['map']) and is_array($font['map']) and count($font['map'])>0 ) {
			foreach($font['map'] as $km => $vm) {
				echo "@CHR $km U".wordwrap(bin2hex($vm),4,'-U',true)."\n";
				}
			continue;
			}
		if (isset($font[$id])) echo $cmd.' '.$font[$id]."\n";
		}	
	for ($a = 0;$a<$font['max'];$a++) {
		$map = charBmp($font,$a);
		showChar($map,$a);
		}
	file_put_contents($par['o'],ob_get_clean());
	exit;
	}

if (isset($par['u'])) {
	$txt = file($par['u']) or die("\nErrore nel file di testo!\n");
	$font = array(
		'ver'		=>	1,
		'charset'	=>	'CP437',
		'max'		=>	256,
		'height'	=>	8,
		'font'		=>	null )
		;
	
	$fontHeight = 8;
	if (isset($par['h']) and $par['h']==8) $font['height']=8;
	if (isset($par['h']) and $par['h']==16) $font['height']=16;
	$font['font'] = str_pad('',$font['height']*$font['max'],chr(0));
	$curCh=0;
	$curBmp=str_pad('',$font['height'],chr(0));
	$curY=0;
	$test0=false;
	$fase=0;
	$started=false;
	foreach($txt as $lin => $li) {
		$line=$lin+1;
		$li=trim($li,"\t\r\n");
		$li=str_replace('█','*',$li);
		if (strlen($li)) {
			
			if ($li[0]=='@') {
				$li=str_replace("\t",' ',$li);
				while(strpos($li,'  ')!==false) $li=str_replace('  ',' ',$li);
				$li=trim($li,' ');
				list($a,$b,$c) = explode(' ',$li.'  ');
				
				if ($a=='@CHS') {
					$a='@CHR';
					$b=mb_convert_encoding($b,'UNICODE','UTF-8');
					$b=unpack('n*',$b);
					$b=$b[1];
					$b='#'.$b;
					}
				
				if ($a=='@RMAP') {
					list($a,$z,$b,$c,$d) = explode(' ',$li.'     ');
					$a='@CHR';
					$c='UFFFF-U'.
						substr(str_pad($b,4,'0',STR_PAD_LEFT),0,4).
						'-U'. substr(str_pad($c,2,'0',STR_PAD_LEFT),0,2). 
						substr(str_pad($d,2,'0',STR_PAD_LEFT),0,2);
					$b=$z;
					}
				
				if (isset($FONTINFOSTRUCTREV[$a])) {
					if (@$FONTINFOSTRUCT[ @$FONTINFOSTRUCTREV[$a] ][3]) {
						list($a,$b)=explode(' ',$li.' ',2);
						$b=trim($b,' ');
						}
						
					if ($test0 or $fase!=0) die("Riga $line: Non era atteso $a\nFile: `{$par['u']}`\n");
					if ($a=='@CHR') {
						if (!isset($font['map'])) $font['map']=array();
						$c=str_replace(array('u','U','-'),'',$c);
						$font['map'][$b] = hex2bin($c);
						continue;
						}
						
					if (!$FONTINFOSTRUCTREV[$a]) continue;
					$k0 = $FONTINFOSTRUCTREV[$a];
					$tp = $FONTINFOSTRUCT[$k0][1];
					$k0 = $FONTINFOSTRUCT[$k0][0];
					$font[ $k0 ] = $b;
					if ($tp) $font[ $k0 ] = intval($font[ $k0 ]);
					}
					
				if ($a == '@CH') {
					if (!$started) {
						$started=true;
						$font['font'] = str_pad('',$font['height']*$font['max'],chr(0));
						}
					if ($fase!=0) die("Riga $line: Non era atteso @CH\nFile: `{$par['u']}`\n");
					$b = intval($b) % $font['max'];
					$test0=true;
					$curY=0;
					$fase=1;
					$curCh=$b;
					$curBmp=$curBmp=str_pad('',$font['height'],chr(0));
					}
				continue;
				}
			
			if (strlen($li)!=8) die("Riga $line: Doveva essere lunga 8 caratteri.\nFile: `{$par['u']}`\n");
			if ($curY >= $font['height']) {
				echo "Riga $line: Il carattere $curCh doveva finire qui. ($curY)\nFile: `{$par['u']}`\n";
				if (!isset($par['A'])) exit;
			}
			if ($fase!=1) die("Riga $line: Non era atteso un carattere in questo punto.\nFile: `{$par['u']}`\n");
			
			$byte=0;
			for ($x = 0 ; $x<8;$x++) {
				$ch = $li[$x];
				if ($ch!=' ') $byte|= 1<<(7^$x);
				}
			$bp = ($curCh * $font['height']) + $curY;
			$font['font'][$bp] = chr($byte);
			$curY++;
			
			} else { //strlen = 0
			$fase=0;
			}
		}
		
	saveFont($par['o'],$font);
	}

?>
