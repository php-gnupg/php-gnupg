--TEST--n
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

var_dump($ret);
?>
--EXPECT--
array(1) {
  [0]=>
  array(8) {
    ["disabled"]=>
    bool(false)
    ["expired"]=>
    bool(false)
    ["revoked"]=>
    bool(false)
    ["is_secret"]=>
    bool(false)
    ["can_sign"]=>
    bool(true)
    ["can_encrypt"]=>
    bool(true)
    ["uids"]=>
    array(1) {
      [0]=>
      array(6) {
        ["name"]=>
        string(7) "testkey"
        ["comment"]=>
        string(7) "testkey"
        ["email"]=>
        string(16) "test@example.net"
        ["uid"]=>
        string(36) "testkey (testkey) <test@example.net>"
        ["revoked"]=>
        bool(false)
        ["invalid"]=>
        bool(false)
      }
    }
    ["subkeys"]=>
    array(2) {
      [0]=>
      array(11) {
        ["fingerprint"]=>
        string(40) "64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E"
        ["keyid"]=>
        string(16) "2E96F141B3DD2B2E"
        ["timestamp"]=>
        int(1129316524)
        ["expires"]=>
        int(0)
        ["is_secret"]=>
        bool(false)
        ["invalid"]=>
        bool(false)
        ["can_encrypt"]=>
        bool(false)
        ["can_sign"]=>
        bool(true)
        ["disabled"]=>
        bool(false)
        ["expired"]=>
        bool(false)
        ["revoked"]=>
        bool(false)
      }
      [1]=>
      array(11) {
        ["fingerprint"]=>
        string(40) "A3437D3651E27CF9864198F0BFE8D07DDACDEAC8"
        ["keyid"]=>
        string(16) "BFE8D07DDACDEAC8"
        ["timestamp"]=>
        int(1129316525)
        ["expires"]=>
        int(0)
        ["is_secret"]=>
        bool(false)
        ["invalid"]=>
        bool(false)
        ["can_encrypt"]=>
        bool(true)
        ["can_sign"]=>
        bool(false)
        ["disabled"]=>
        bool(false)
        ["expired"]=>
        bool(false)
        ["revoked"]=>
        bool(false)
      }
    }
  }
}
--CLEAN--
<?php
require_once "gnupgt.inc";
gnupgt::delete_key();
?>
