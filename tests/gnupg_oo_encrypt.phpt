--TEST--
encrypt and decrypt a text
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$gpg -> addencryptkey($fingerprint);
$enc = $gpg -> encrypt($plaintext);

$gpg = NULL;

$gpg = new gnupg();
$gpg -> adddecryptkey($fingerprint, $passphrase);
$ret = $gpg -> decrypt ($enc);

var_dump($ret);
?>
--EXPECTF--
string(7) "foo bar"
