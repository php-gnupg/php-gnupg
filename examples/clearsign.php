<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	setSignerKey		($fingerprint);
$gnupg		->	setPassPhrase		($passphrase);
$text		=	$gnupg	->	sign	($mailtext);
echo $text;
?>
