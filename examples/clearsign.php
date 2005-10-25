<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	addSignKey			($fingerprint,$passphrase);
$text		=	$gnupg	->	sign	($mailtext);
echo $text;
?>
