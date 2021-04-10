# PHP GnuPG

The php-gnupg is a wrapper for GpgME library that provides access to GnuPG.


## Installation

### Linux

Before starting with installation of this extensions, the `GpgME` library has to be installed. It
has got installation packages on the most Linux distributions. The minimal version of GpgME that
is supported is 1.3.0. The extension supports GnuPG version 1 and 2.

Of course PHP has to be installed too. The minimal version that is supported is 5.3.2.

#### PECL

This extension is available on PECL. 

```
$ sudo pecl install gnupg
```

#### Manual Installation

It's important to have a git installed as it's necessary for recursive fetch of
[phpc](https://github.com/bukka/phpc).

First clone recursively the repository
```
git clone --recursive https://github.com/php-gnupg/php-gnupg.git
```

Then go to the created directory and compile the extension. The PHP development package has to be
installed (command `phpize` must be available).
```
cd php-gnupg
phpize
./configure
make
sudo make install
```

Finally the following line needs to be added to `php.ini`
```
extension=gnupg.so
```
or for PHP 8+ it's just
```
extension=gnupg
```

### Windows

The extension is not currently supported on Windows due to unavailable GpgME library builds that
would be supported by PHP.

## Documentation

The extension documentation is now available in the PHP-Manual: http://php.net/manual/en/book.gnupg.php
