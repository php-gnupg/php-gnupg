--TEST--
init resource with custom file_name
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

$gpg = gnupg_init(array('file_name' => '/usr/bin/gpg'));
$engine = gnupg_getengineinfo($gpg);
var_dump($engine['file_name']);
?>
--EXPECT--
string(12) "/usr/bin/gpg"