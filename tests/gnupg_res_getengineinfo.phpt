--TEST--
get keyinfo
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
$ret = gnupg_getengineinfo($gpg);
var_dump($ret);
?>
--EXPECTF--
array(3) {
  ["protocol"]=>
  int(0)
  ["file_name"]=>
  string(%d) %s
  ["home_dir"]=>
  string(0) ""
}

--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>

