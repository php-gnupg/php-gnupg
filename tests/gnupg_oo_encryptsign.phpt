--TEST--
encryptsign and decryptverify a text
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$gpg -> addencryptkey($fingerprint);
$gpg -> addsignkey($fingerprint, $passphrase);
$enc = $gpg -> encryptsign($plaintext);

$gpg = NULL;
$plaintext = false;

$gpg = new gnupg();
$gpg -> adddecryptkey($fingerprint, $passphrase);
$ret = $gpg -> decryptverify ($enc, $plaintext);

var_dump($ret);
var_dump($plaintext);
?>
--EXPECTF--
array(1) {
  [0]=>
  array(5) {
    ["fingerprint"]=>
    string(40) "64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E"
    ["validity"]=>
    int(0)
    ["timestamp"]=>
    int(%d)
    ["status"]=>
    int(0)
    ["summary"]=>
    int(0)
  }
}
string(7) "foo bar"
