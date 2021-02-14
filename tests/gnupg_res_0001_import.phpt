--TEST--
import a new key into the keyring
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::reset_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_import($gpg, $testkey);
var_dump($ret);
?>
--EXPECT--
array(9) {
  ["imported"]=>
  int(1)
  ["unchanged"]=>
  int(0)
  ["newuserids"]=>
  int(0)
  ["newsubkeys"]=>
  int(0)
  ["secretimported"]=>
  int(1)
  ["secretunchanged"]=>
  int(0)
  ["newsignatures"]=>
  int(0)
  ["skippedkeys"]=>
  int(0)
  ["fingerprint"]=>
  string(40) "2DF0DD02DC9B70B7F64F572E669E775E0A6284B3"
}
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>