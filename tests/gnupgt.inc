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
    }
}