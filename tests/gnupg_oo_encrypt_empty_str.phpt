--TEST--
encrypt and decrypt a text
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$gpg->addencryptkey($fingerprint);
$enc = $gpg->encrypt("");

$gpg = new gnupg();
$gpg->adddecryptkey($fingerprint, $passphrase);
$ret = $gpg->decrypt($enc);
var_dump($ret);
?>
--EXPECTF--
string(0) ""
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
