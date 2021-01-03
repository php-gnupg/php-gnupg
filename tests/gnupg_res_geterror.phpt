--TEST--
get error
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
var_dump(gnupg_geterror($gpg));
?>
--EXPECT--
bool(false)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>