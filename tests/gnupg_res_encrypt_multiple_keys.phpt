--TEST--
encrypt and decrypt a text using multiple keys
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::reset_key();
gnupgt::import_first();
gnupgt::import_second();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
gnupg_addencryptkey($gpg, $fingerprint);
gnupg_addencryptkey($gpg, $fingerprint2);
$enc = gnupg_encrypt($gpg, $plaintext);

gnupgt::reset_key();
gnupgt::import_first();
gnupgt::import_second();

$gpg = NULL;
$gpg = gnupg_init();
gnupg_adddecryptkey($gpg, $fingerprint2, $passphrase2);
$ret = gnupg_decrypt ($gpg, $enc);

var_dump($ret);
?>
--EXPECTF--
string(7) "foo bar"
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
