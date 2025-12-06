/*
  +--------------------------------------------------------------------+
  | PECL :: gnupg                                                      |
  +--------------------------------------------------------------------+
  | Redistribution and use in source and binary forms, with or without |
  | modification, are permitted provided that the conditions mentioned |
  | in the accompanying LICENSE file are met.                          |
  +--------------------------------------------------------------------+
  | Copyright (c) 2006, Thilo Raufeisen <traufeisen@php.net>           |
  | Copyright (c) 2013, Jim Jagielski <jimjag@php.net>                 |
  | Copyright (c) 2016, Jakub Zelenka <bukka@php.net>                  |
  +--------------------------------------------------------------------+
*/

#ifndef PHP_GNUPG_KEYLISTITERATOR_H
#define PHP_GNUPG_KEYLISTITERATOR_H

#include <gpgme.h>

typedef struct _gnupg_keylistiterator_object {
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_key_t gpgkey;
	char *pattern;
	zend_object std;
} gnupg_keylistiterator_object;

int gnupg_keylistiterator_init(INIT_FUNC_ARGS);

PHP_METHOD(gnupg_keylistiterator, __construct);
PHP_METHOD(gnupg_keylistiterator, current);
PHP_METHOD(gnupg_keylistiterator, key);
PHP_METHOD(gnupg_keylistiterator, next);
PHP_METHOD(gnupg_keylistiterator, rewind);
PHP_METHOD(gnupg_keylistiterator, valid);

#endif /* PHP_GNUPG_KEYLISTITERATOR_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
