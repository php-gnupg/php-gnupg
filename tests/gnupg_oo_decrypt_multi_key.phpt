--TEST--
encrypt and decrypt a text with multiple keys
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_keys();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$gpg->addencryptkey($fingerprint);
$gpg->addencryptkey($fingerprint2);
$gpg->addencryptkey($fingerprint3);
$enc = $gpg->encrypt($plaintext);

$gpg = new gnupg();
$gpg->adddecryptkey($fingerprint2, $passphrase2);
$ret = $gpg->decrypt($enc);

var_dump($ret);
?>
--EXPECTF--
string(7) "foo bar"
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
