--TEST--
init object with custom file_name
--SKIPIF--
<?php
if(!class_exists("gnupg")) {
    die("skip");
}
if (!file_exists('/usr/bin/gpg')) {
    die("skip /usr/bin/gpg does not exist");
}
?>
--FILE--
<?php
require_once "gnupgt.inc";

$gpg = new gnupg(array('file_name' => '/usr/bin/gpg'));
$engine = $gpg->getengineinfo();
var_dump($engine['file_name']);
?>
--EXPECT--
string(12) "/usr/bin/gpg"