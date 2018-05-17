--TEST--
encrypt and decrypt a text
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

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
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>