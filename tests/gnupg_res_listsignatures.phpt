--TEST--
list signatures
--SKIPIF--
<?php if (!extension_loaded("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_listsignatures($gpg, $fingerprint);

$k1 = "PHP GnuPG <gnupg@php.net>";
$k2 = "669E775E0A6284B3";
gnupgt::check_array('PHP GnuPG <gnupg@php.net>', $ret, $k1, $k2, 'uid');
gnupgt::check_array('PHP GnuPG', $ret, $k1, $k2, 'name');
gnupgt::check_array('gnupg@php.net', $ret, $k1, $k2, 'email');
gnupgt::check_array('', $ret, $k1, $k2, 'comment');
gnupgt::check_array(0, $ret, $k1, $k2, 'expires');
gnupgt::check_array(false, $ret, $k1, $k2, 'revoked');
gnupgt::check_array(false, $ret, $k1, $k2, 'expired');
gnupgt::check_array(false, $ret, $k1, $k2, 'invalid');
gnupgt::check_array(1567958444, $ret, $k1, $k2, 'timestamp');

?>
Done
--EXPECT--
Done
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>