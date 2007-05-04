--TEST--n
get keyinfo
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = gnupg_init();
gnupg_seterrormode($gpg, GNUPG_ERROR_WARNING);
$ret = gnupg_keyinfo($gpg, $fingerprint);
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
