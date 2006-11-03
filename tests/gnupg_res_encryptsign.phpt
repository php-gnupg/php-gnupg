--TEST--
encryptsign and decryptverify a text
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
gnupg_addencryptkey($gpg, $fingerprint);
gnupg_addsignkey($gpg, $fingerprint, $passphrase);
$enc = gnupg_encryptsign($gpg, $plaintext);

$gpg = NULL;
$plaintext = false;

$gpg = gnupg_init();
gnupg_adddecryptkey($gpg, $fingerprint, $passphrase);
$ret = gnupg_decryptverify ($gpg, $enc, $plaintext);

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
