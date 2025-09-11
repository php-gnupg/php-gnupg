--TEST--
sign a text with sigmode SIG_MODE_CLEAR
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
gnupg_setsignmode($gpg, GNUPG_SIG_MODE_CLEAR);
gnupg_addsignkey($gpg, $fingerprint, $passphrase);
$ret = gnupg_sign($gpg, $plaintext);

$gpg = gnupg_init();
$tmp = false;
$ret = gnupg_verify($gpg, $ret, false, $tmp);

var_dump($ret);
// Some distros like Arch Linux applied patch to gnupg 2.4.8 removing the new line - see GH-62
var_dump($tmp == "foo bar\n" || $tmp == "foo bar");
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
bool(true)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>