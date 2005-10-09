<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	setSignerKey		($fingerprint);
$gnupg		->	setEncryptKey		($fingerprint);
$gnupg		->	setPassPhrase		($passphrase);
$text		=	$gnupg	->	encryptsign	($mailtext);
echo $text;
echo "\n-------------------------\n";
$plaintext	=	false;
$retval		=	$gnupg		->	decryptverify		($text,$plaintext);
print_r($retval);
print_r($plaintext);
?>
