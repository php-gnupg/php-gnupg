# News

List of all features for the release

## 1.5.2
- Fixed GH-37: `gnupg_decrypt()` returns false when decrypting an encrypted empty string
- Fixed GH-46: `gnupg_decrypt()` segfaults when password callback user ID hint is not supplied
- Fixed 1.5.0 regressition - the deletekey `allow_secret` made optional again

## 1.5.1
- Fixed compilation with PHP 8.1
- Fixed build with gpgme 1.4

## 1.5.0
- Support for PHP 8
- Support for GnuPG 2.1+
- Added argument info for all functions and methods (reflection support)
- Added new function `gnupg_getengineinfo`
- Added new function `gnupg_geterrorinfo`
- Added init array argument for setting home dir and gpg binary file name
- Added additional fields to `gnupg_keyinfo` returned array
- Added parameter to `gnupg_keyinfo` to use `secret_only`
- Fixed `gnupg_deletekey` to use boolean for `allow_secret` parameter
