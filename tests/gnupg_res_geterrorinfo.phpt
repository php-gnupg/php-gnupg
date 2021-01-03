--TEST--
get error info
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
var_dump(gnupg_geterrorinfo($gpg));
?>
--EXPECT--
array(4) {
  ["generic_message"]=>
  bool(false)
  ["gpgme_code"]=>
  int(0)
  ["gpgme_source"]=>
  string(18) "Unspecified source"
  ["gpgme_message"]=>
  string(7) "Success"
}
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>