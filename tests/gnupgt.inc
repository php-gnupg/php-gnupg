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
}