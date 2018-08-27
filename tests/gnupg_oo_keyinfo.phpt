--TEST--
get keyinfo
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg->keyinfo($fingerprint, true);

gnupgt::check_keyinfo($gpg->keyinfo($fingerprint), false);
gnupgt::check_keyinfo($gpg->keyinfo($fingerprint, true), true);

?>
Done
--EXPECT--
Done
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
