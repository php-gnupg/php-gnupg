--TEST--
init object with custom home_dir
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
$homedir = __DIR__ . '/init_oo_home';
if (!is_dir($homedir)) {
    mkdir($homedir);
}

$gpg = new gnupg(array('home_dir' => $homedir));
$gpg->seterrormode(gnupg::ERROR_WARNING);
$gpg->import($testkey);
$imported = false;
foreach (glob("$homedir/*") as $filename) {
    $imported = true;
}
var_dump($imported);
$engine = $gpg->getengineinfo();
var_dump($engine['home_dir'] === $homedir);
?>
--EXPECT--
bool(true)
bool(true)
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key(__DIR__ . '/init_oo_home');
?>
