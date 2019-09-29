--TEST--n
sign a text with mode SIG_MODE_NORMAL and without armored output
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
gnupg_setarmor($gpg, 0);
gnupg_setsignmode($gpg, GNUPG_SIG_MODE_NORMAL);
gnupg_addsignkey($gpg, $fingerprint, $passphrase);
$ret = gnupg_sign($gpg, $plaintext);

$gpg = NULL;

$gpg = gnupg_init();
$plaintext = false;
$ret = gnupg_verify($gpg, $ret, false, $plaintext);

var_dump($ret);
var_dump($plaintext);
?>
--EXPECTF--
array(1) {
  [0]=>
  array(5) {
    ["fingerprint"]=>
    string(40) "2DF0DD02DC9B70B7F64F572E669E775E0A6284B3"
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
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>