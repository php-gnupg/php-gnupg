--TEST--
get engineinfo
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$ret = $gpg->getengineinfo();
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

