<?php
require_once    (dirname(__FILE__)."/main.php");
$result	=	$gnupg	->	export($testkey);
print_r($result);
?>
