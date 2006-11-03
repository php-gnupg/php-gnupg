--TEST--
encrypt and decrypt a text
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
gnupg_addencryptkey($gpg, $fingerprint);
$enc = gnupg_encrypt($gpg, $plaintext);

$gpg = NULL;

$gpg = gnupg_init();
gnupg_adddecryptkey($gpg, $fingerprint, $passphrase);
$ret = gnupg_decrypt ($gpg, $enc);

var_dump($ret);
?>
--EXPECTF--
string(7) "foo bar"
