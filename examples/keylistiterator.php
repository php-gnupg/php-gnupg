<?php
require_once    (dirname(__FILE__)."/main.php");

$iterator	=	new gnupg_keylistiterator("php.net");
foreach($iterator as $key => $value){
	echo $key." -> ".$value."\n";
}
?>
