--TEST--n
import a new key into the keyring
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
@unlink (dirname(__FILE__)."/pubring.gpg");
@unlink (dirname(__FILE__)."/secring.gpg");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg -> import($testkey);
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
  string(40) "64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E"
}
