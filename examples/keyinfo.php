<?php
require_once    (dirname(__FILE__)."/main.php");

$keyinfo	=	$gnupg		->	keyinfo	($fingerprint);
print_r($keyinfo)
?>
