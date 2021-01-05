--TEST--n
get keyinfo
--SKIPIF--
<?php if(!class_exists("gnupg")) die("skip"); ?>
--FILE--
<?php
require_once(dirname(__FILE__)."/vars.inc");
$gpg = new gnupg();
$gpg -> seterrormode(gnupg::ERROR_WARNING);
$ret = $gpg -> keyinfo($fingerprint);
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
        string(9) "PHP GnuPG"
        ["comment"]=>
        string(0) ""
        ["email"]=>
        string(13) "gnupg@php.net"
        ["uid"]=>
        string(25) "PHP GnuPG <gnupg@php.net>"
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
        string(40) "BA5808CEAC2F4DEB25599472976AB7A307618158"
        ["keyid"]=>
        string(16) "976AB7A307618158"
        ["timestamp"]=>
        int(1609869162)
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
        string(40) "E9E3A5171BDC5B621420E2A99A9BF4CB9BF4BF97"
        ["keyid"]=>
        string(16) "9A9BF4CB9BF4BF97"
        ["timestamp"]=>
        int(1609869162)
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
