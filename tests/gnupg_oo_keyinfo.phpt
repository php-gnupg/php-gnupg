--TEST--
get keyinfo
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once "gnupgt.inc";
gnupgt::import_key();

$gpg = new gnupg();
$gpg->seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg->keyinfo($fingerprint);
gnupgt::check_array(false, $ret, 0, 'disabled');
gnupgt::check_array(false, $ret, 0, 'expired');
gnupgt::check_array(false, $ret, 0, 'revoked');
gnupgt::check_array(false, $ret, 0, 'is_secret');
gnupgt::check_array(true, $ret, 0, 'can_sign');
gnupgt::check_array(true, $ret, 0, 'can_encrypt');
// uid
gnupgt::check_array('testkey', $ret, 0, 'uids', 0, 'name');
gnupgt::check_array('testkey', $ret, 0, 'uids', 0, 'comment');
gnupgt::check_array('test@example.net', $ret, 0, 'uids', 0, 'email');
gnupgt::check_array('testkey (testkey) <test@example.net>', $ret, 0, 'uids', 0, 'uid');
gnupgt::check_array(false, $ret, 0, 'uids', 0, 'revoked');
gnupgt::check_array(false, $ret, 0, 'uids', 0, 'invalid');
gnupgt::check_array(false, $ret, 0, 'uids', 0, 'invalid');
// subkey 1
gnupgt::check_array("64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E", $ret, 0, 'subkeys', 0, 'fingerprint');
gnupgt::check_array("2E96F141B3DD2B2E", $ret, 0, 'subkeys', 0, 'keyid');
gnupgt::check_array(1129316524, $ret, 0, 'subkeys', 0, 'timestamp');
gnupgt::check_array(0, $ret, 0, 'subkeys', 0, 'expires');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'is_secret');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'can_encrypt');
gnupgt::check_array(true, $ret, 0, 'subkeys', 0, 'can_sign');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'disabled');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'expired');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'revoked');
gnupgt::check_array(true, $ret, 0, 'subkeys', 0, 'can_certify');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'can_authenticate');
gnupgt::check_array(false, $ret, 0, 'subkeys', 0, 'is_qualified');
gnupgt::check_array_from_version('1.9.0', false, $ret, 0, 'subkeys', 0, 'is_de_vs');
gnupgt::check_array(GNUPG_PK_DSA, $ret, 0, 'subkeys', 0, 'pubkey_algo');
gnupgt::check_array(1024, $ret, 0, 'subkeys', 0, 'length');
gnupgt::check_array_from_version('1.7.0', false, $ret, 0, 'subkeys', 0, 'is_cardkey');
// subkey 2
gnupgt::check_array("A3437D3651E27CF9864198F0BFE8D07DDACDEAC8", $ret, 0, 'subkeys', 1, 'fingerprint');
gnupgt::check_array("BFE8D07DDACDEAC8", $ret, 0, 'subkeys', 1, 'keyid');
gnupgt::check_array(1129316525, $ret, 0, 'subkeys', 1, 'timestamp');
gnupgt::check_array(0, $ret, 0, 'subkeys', 1, 'expires');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'is_secret');
gnupgt::check_array(true, $ret, 0, 'subkeys', 1, 'can_encrypt');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'can_sign');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'disabled');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'expired');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'revoked');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'can_certify');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'can_authenticate');
gnupgt::check_array(false, $ret, 0, 'subkeys', 1, 'is_qualified');
gnupgt::check_array_from_version('1.9.0', false, $ret, 0, 'subkeys', 1, 'is_de_vs');
gnupgt::check_array(GNUPG_PK_ELG_E, $ret, 0, 'subkeys', 1, 'pubkey_algo');
gnupgt::check_array(1024, $ret, 0, 'subkeys', 1, 'length');
gnupgt::check_array_from_version('1.7.0', false, $ret, 0, 'subkeys', 1, 'is_cardkey');

?>
Done
--EXPECT--
Done
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
