<?php
require_once    (dirname(__FILE__)."/main.php");
$result	=	$gnupg	->	export($fingerprint);
print_r($result);
?>
