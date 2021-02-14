--TEST--n
delete a key from the keyring
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_deletekey($gpg, $fingerprint, true);
var_dump($ret);
?>
--EXPECT--
bool(true)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>