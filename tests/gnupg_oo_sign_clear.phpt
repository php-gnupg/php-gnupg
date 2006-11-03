--TEST--n
sign a text with sigmode SIG_MODE_CLEAR
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$gpg -> setsignmode(gnupg::SIG_MODE_CLEAR);
$gpg -> addsignkey($fingerprint, $passphrase);
$ret = $gpg -> sign($plaintext);

$gpg = NULL;

$gpg = new gnupg();
$tmp = false;
$ret = $gpg -> verify($ret, false, $tmp);

var_dump($ret);
var_dump($tmp);
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
string(8) "foo bar
"
