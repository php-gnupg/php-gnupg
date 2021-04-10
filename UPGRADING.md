# PHP GnuPG Upgrading notes

This document lists backward incompatible change in the extension

## 1.5.0
- no backward incompatible changes

## 1.4.0
- gnupg_decryptverify $plaintext reference can no longer be passed in
  call_user_func_array which is conformant to user space code.
  See https://github.com/php-gnupg/php-gnupg/issues/4 for more details.

