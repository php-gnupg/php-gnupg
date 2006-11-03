--TEST--n
list signatures
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg -> listsignatures($fingerprint);
var_dump($ret);
?>
--EXPECT--
array(1) {
  ["testkey (testkey) <test@example.net>"]=>
  array(1) {
    ["2E96F141B3DD2B2E"]=>
    array(8) {
      ["uid"]=>
      string(36) "testkey (testkey) <test@example.net>"
      ["name"]=>
      string(7) "testkey"
      ["email"]=>
      string(16) "test@example.net"
      ["comment"]=>
      string(7) "testkey"
      ["expires"]=>
      int(0)
      ["revoked"]=>
      bool(false)
      ["expired"]=>
      bool(false)
      ["invalid"]=>
      bool(false)
    }
  }
}
