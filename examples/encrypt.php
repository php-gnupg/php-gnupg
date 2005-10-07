<?php
require_once	(dirname(__FILE__)."/main.php");

$gnupg		->	setEncryptKey		($fingerprint);
$text		=	$gnupg	->	encrypt	($mailtext);
echo $text;
?>
