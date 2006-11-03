--TEST--n
delete a key from the keyring
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_deletekey($gpg, $fingerprint,true);
var_dump($ret);
?>
--EXPECT--
bool(true)
