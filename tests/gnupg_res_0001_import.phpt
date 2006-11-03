--TEST--n
import a new key into the keyring
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
@unlink (dirname(__FILE__)."/pubring.gpg");
@unlink (dirname(__FILE__)."/secring.gpg");
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
  string(40) "64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E"
}
