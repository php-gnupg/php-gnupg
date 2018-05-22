<?php

require_once __DIR__ . "/vars.inc";

class gnupgt {
    static function import_key()
    {
        global $testkey;

        self::delete_key();

        $gpg = new gnupg();
        $gpg->import($testkey);
    }

    static function delete_key()
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
}