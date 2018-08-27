--TEST--n
get keyinfo
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_keyinfo($gpg, $fingerprint);
gnupgt::check_keyinfo(gnupg_keyinfo($gpg, $fingerprint), false);
gnupgt::check_keyinfo(gnupg_keyinfo($gpg, $fingerprint, true), true);

?>
Done
--EXPECT--
Done
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>