--TEST--n
sign a text with sigmode SIG_MODE_CLEAR
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$gpg->setsignmode(gnupg::SIG_MODE_CLEAR);
$gpg->addsignkey($fingerprint, $passphrase);
$ret = $gpg->sign($plaintext);

$gpg = NULL;

$gpg = new gnupg();
$tmp = false;
$ret = $gpg->verify($ret, false, $tmp);

var_dump($ret);
var_dump($tmp);
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
string(8) "foo bar
"
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>