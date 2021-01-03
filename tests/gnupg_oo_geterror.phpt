--TEST--
get error
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
var_dump($gpg->geterror());
?>
--EXPECTF--
bool(false)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>