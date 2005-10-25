<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	addSignKey			($fingerprint,$passphrase);
$gnupg		->	addEncryptKey		($fingerprint);
$text		=	$gnupg	->	encryptsign	($mailtext);
echo $text;
echo "\n-------------------------\n";
$plaintext	=	false;
$gnupg		->	addDecryptKey		($fingerprint,$passphrase);
$retval		=	$gnupg		->	decryptverify		($text,$plaintext);
print_r($retval);
print_r($plaintext);
?>
