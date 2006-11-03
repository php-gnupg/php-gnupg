--TEST--n
delete a key from the keyring
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg -> deletekey($fingerprint,true);
var_dump($ret);
?>
--EXPECT--
bool(true)
