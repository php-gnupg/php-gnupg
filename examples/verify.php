<?php
require_once	(dirname(__FILE__)."/main.php");

$mailtext	=	'
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Test test Test TeSt
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.5 (GNU/Linux)

iD8DBQFDRWw6BUn53IUVZtwRAoVKAJ9P0E0PKcpEuWeHNxgZRbctpETbGQCgv0Nq
TmrOEDxc5AihrFREY+IYPp4=
=933C
-----END PGP SIGNATURE-----
';

$plaintext	=	false;

$info		=	$gnupg	->	verify	($mailtext,$plaintext);

print_r($info);
echo "\n".$plaintext."\n";
?>
