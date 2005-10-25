<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	addEncryptKey		($fingerprint);
$text		=	$gnupg	->	encrypt	($mailtext);
echo $text;
?>
