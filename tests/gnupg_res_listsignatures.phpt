--TEST--n
list signatures
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_listsignatures($gpg, $fingerprint);
var_dump($ret);
?>
--EXPECT--
array(1) {
  ["PHP GnuPG <gnupg@php.net>"]=>
  array(1) {
    ["976AB7A307618158"]=>
    array(8) {
      ["uid"]=>
      string(25) "PHP GnuPG <gnupg@php.net>"
      ["name"]=>
      string(9) "PHP GnuPG"
      ["email"]=>
      string(13) "gnupg@php.net"
      ["comment"]=>
      string(0) ""
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
