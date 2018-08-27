<?php

require_once __DIR__ . "/vars.inc";

class gnupgt {
    /**
     * Import all keys
     */
    static public function import_key()
    {
        global $testkey;

        self::delete_key();

        $gpg = new gnupg();
        $gpg->import($testkey);
    }

    /**
     * Delete all keys.
     */
    static public function delete_key()
    {
        @unlink(__DIR__ . "/pubring.gpg");
        @unlink(__DIR__ . "/secring.gpg");
        @unlink(__DIR__ . "/pubring.kbx");
        @unlink(__DIR__ . "/random_seed");
        @unlink(__DIR__ . "/sshcontrol");
        @unlink(__DIR__ . "/trustdb.gpg");
        $privKeyDir = __DIR__ . '/private-keys-v1.d';
        if (is_dir($privKeyDir)) {
            foreach (glob($privKeyDir . '/*.key') as $key) {
                unlink($key);
            }
            rmdir($privKeyDir);
        }
    }

    /**
     * Print error message and return false.
     *
     * @param string $msg
     * @return bool
     */
    static private function error($msg)
    {
        echo "ERROR: " . $msg;
        return false;
    }

    /**
     * Check single array value.
     *
     * @param mixed $expected
     * @param array $a
     * @param string $key1
     * @return bool
     */
    static public function check_array($expected, $a, $key1)
    {
        $args = func_get_args();
        $keys = array_splice($args, 2);
        $value = $a;
        foreach ($keys as $key) {
            if (!isset($value[$key])) {
                return self::error("key $key not found in the array");
            }
            $value = $value[$key];
        }
        if ($value !== $expected) {

            return self::error(
                sprintf(
                    "key %s value %s does not match expected %s\n",
                    $key,
                    var_export($value, true),
                    var_export($expected, true)
                )
            );
        }

        return true;
    }

    /**
     * Check single array value but only for GpgME version higher than supplied.
     *
     * @param mixed $expected
     * @param array $a
     * @param string $key1
     * @return bool
     */
    static public function check_array_from_version($version, $expected, $a, $key1)
    {
        if (version_compare(GNUPG_GPGME_VERSION,  $version) > 0) {
            return true;
        }

        $args = func_get_args();
        return call_user_func_array('gnupgt::check_array', array_splice($args, 1));
    }

    /**
     * Check keyinfo for var key
     *
     * @param $ret
     * @param $secret_only
     */
    static public function check_keyinfo($ret, $secret_only) {
        self::check_array(false, $ret, 0, 'disabled');
        self::check_array(false, $ret, 0, 'expired');
        self::check_array(false, $ret, 0, 'revoked');
        self::check_array($secret_only, $ret, 0, 'is_secret');
        self::check_array(true, $ret, 0, 'can_sign');
        self::check_array(true, $ret, 0, 'can_encrypt');
        // uid
        self::check_array('testkey', $ret, 0, 'uids', 0, 'name');
        self::check_array('testkey', $ret, 0, 'uids', 0, 'comment');
        self::check_array('test@example.net', $ret, 0, 'uids', 0, 'email');
        self::check_array('testkey (testkey) <test@example.net>', $ret, 0, 'uids', 0, 'uid');
        self::check_array(false, $ret, 0, 'uids', 0, 'revoked');
        self::check_array(false, $ret, 0, 'uids', 0, 'invalid');
        self::check_array(false, $ret, 0, 'uids', 0, 'invalid');
        // subkey 1
        self::check_array("64DF06E42FCF2094590CDEEE2E96F141B3DD2B2E", $ret, 0, 'subkeys', 0, 'fingerprint');
        self::check_array("2E96F141B3DD2B2E", $ret, 0, 'subkeys', 0, 'keyid');
        self::check_array(1129316524, $ret, 0, 'subkeys', 0, 'timestamp');
        self::check_array(0, $ret, 0, 'subkeys', 0, 'expires');
        self::check_array($secret_only, $ret, 0, 'subkeys', 0, 'is_secret');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'can_encrypt');
        self::check_array(true, $ret, 0, 'subkeys', 0, 'can_sign');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'disabled');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'expired');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'revoked');
        self::check_array(true, $ret, 0, 'subkeys', 0, 'can_certify');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'can_authenticate');
        self::check_array(false, $ret, 0, 'subkeys', 0, 'is_qualified');
        self::check_array_from_version('1.9.0', false, $ret, 0, 'subkeys', 0, 'is_de_vs');
        self::check_array(GNUPG_PK_DSA, $ret, 0, 'subkeys', 0, 'pubkey_algo');
        self::check_array(1024, $ret, 0, 'subkeys', 0, 'length');
        self::check_array_from_version('1.7.0', false, $ret, 0, 'subkeys', 0, 'is_cardkey');
        // subkey 2
        self::check_array("A3437D3651E27CF9864198F0BFE8D07DDACDEAC8", $ret, 0, 'subkeys', 1, 'fingerprint');
        self::check_array("BFE8D07DDACDEAC8", $ret, 0, 'subkeys', 1, 'keyid');
        self::check_array(1129316525, $ret, 0, 'subkeys', 1, 'timestamp');
        self::check_array(0, $ret, 0, 'subkeys', 1, 'expires');
        self::check_array($secret_only, $ret, 0, 'subkeys', 1, 'is_secret');
        self::check_array(true, $ret, 0, 'subkeys', 1, 'can_encrypt');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'can_sign');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'disabled');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'expired');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'revoked');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'can_certify');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'can_authenticate');
        self::check_array(false, $ret, 0, 'subkeys', 1, 'is_qualified');
        self::check_array_from_version('1.9.0', false, $ret, 0, 'subkeys', 1, 'is_de_vs');
        self::check_array(GNUPG_PK_ELG_E, $ret, 0, 'subkeys', 1, 'pubkey_algo');
        self::check_array(1024, $ret, 0, 'subkeys', 1, 'length');
        self::check_array_from_version('1.7.0', false, $ret, 0, 'subkeys', 1, 'is_cardkey');
    }
}