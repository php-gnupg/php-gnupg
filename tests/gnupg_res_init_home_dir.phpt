--TEST--
init resource with custom home_dir
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
$homedir = __DIR__ . '/init_res_home';
if (!is_dir($homedir)) {
    mkdir($homedir);
}

$gpg = gnupg_init(array('home_dir' => $homedir));
gnupg_seterrormode($gpg, gnupg::ERROR_WARNING);
gnupg_import($gpg, $testkey);
$imported = false;
foreach (glob("$homedir/*") as $filename) {
    $imported = true;
}
var_dump($imported);
$engine = gnupg_getengineinfo($gpg);
var_dump($engine['home_dir'] === $homedir);
?>
--EXPECT--
bool(true)
bool(true)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key(__DIR__ . '/init_res_home');
?>
