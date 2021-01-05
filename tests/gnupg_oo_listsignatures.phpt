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
