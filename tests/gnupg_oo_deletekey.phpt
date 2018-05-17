--TEST--
delete a key from the keyring
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg->deletekey($fingerprint,true);
var_dump($ret);
?>
--EXPECT--
bool(true)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>