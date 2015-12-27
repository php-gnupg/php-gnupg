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
  +--------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_GNUPG_KEYLISTITERATOR_H
#define PHP_GNUPG_KEYLISTITERATOR_H

extern zend_module_entry gnupg_keyiterator_module_entry;

#ifdef PHP_WIN32
#define PHP_GNUPG_API __declspec(dllexport)
#else
#define PHP_GNUPG_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include <gpgme.h>

#define gnupg_keylistiterator_init() _gnupg_keylistiterator_init(INIT_FUNC_ARGS_PASSTHRU)
extern int  _gnupg_keylistiterator_init(INIT_FUNC_ARGS);

typedef struct _gnupg_keylistiterator_object{
	gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_key_t gpgkey;
    zval pattern;
	zend_object zo;
} gnupg_keylistiterator_object;

static zend_class_entry *gnupg_keylistiterator_class_entry;

static inline gnupg_keylistiterator_object *keylistiterator_object_from_obj(zend_object *obj) /* {{{ */ {
    return (gnupg_keylistiterator_object*)((char*)(obj) - XtOffsetOf(gnupg_keylistiterator_object, zo));
}
/* }}} */

static inline gnupg_keylistiterator_object *Z_KEYLISTITERATORO_P(zval *zv) /* {{{ */ {
	return keylistiterator_object_from_obj(Z_OBJ_P((zv)));
}
/* }}} */

PHP_METHOD(gnupg_keylistiterator, __construct);
PHP_METHOD(gnupg_keylistiterator, current);
PHP_METHOD(gnupg_keylistiterator, next);
PHP_METHOD(gnupg_keylistiterator, rewind);
PHP_METHOD(gnupg_keylistiterator, key);
PHP_METHOD(gnupg_keylistiterator, valid);


#ifdef ZTS
#define GNUPG_G(v) TSRMG(gnupg_globals_id, zend_gnupg_globals *, v)
#else
#define GNUPG_G(v) (gnupg_globals.v)
#endif

#endif	/* PHP_GNUPG_H */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
