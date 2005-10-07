<?php
dl("gnupg.so");

$fingerprint    =       "8660281B6051D071D94B5B230549F9DC851566DC";
$mailtext       =       "Test test Test TeSt";
$passphrase     =       "incorrect";

$gnupg			=		new gnupg	();
?>
