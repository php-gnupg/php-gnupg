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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stddef.h>

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "php_gnupg.h"
#include "php_gnupg_keylistiterator.h"
#include "phpc/phpc.h"

static int le_gnupg_keylistiterator;

static zend_class_entry *gnupg_keylistiterator_class_entry;

PHPC_OBJ_DEFINE_HANDLER_VAR(gnupg_keylistiterator);

/* {{{ GNUPG_GET_ITERATOR */
#define GNUPG_GET_ITERATOR() \
	zval *this = getThis(); \
	PHPC_THIS_DECLARE(gnupg_keylistiterator) = NULL; \
	do { \
		if (this) { \
			PHPC_THIS_FETCH_FROM_ZVAL(gnupg_keylistiterator, this); \
			if (!PHPC_THIS) { \
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
				RETURN_FALSE; \
			} \
		} \
	} while (0)
/* }}} */

/* {{{ free gnupg_keylistiterator */
PHPC_OBJ_HANDLER_FREE(gnupg_keylistiterator)
{
	PHPC_OBJ_HANDLER_FREE_INIT(gnupg_keylistiterator);

	gpgme_op_keylist_end(PHPC_THIS->ctx);
	gpgme_key_release(PHPC_THIS->gpgkey);
	gpgme_release(PHPC_THIS->ctx);
	if (PHPC_THIS->pattern) {
		efree(PHPC_THIS->pattern);
	}

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}

/* {{{ create_ex gnupg_keylistiterator */
PHPC_OBJ_HANDLER_CREATE_EX(gnupg_keylistiterator)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(gnupg_keylistiterator);

	gpgme_check_version(NULL);

	gpgme_new(&PHPC_THIS->ctx);
	PHPC_THIS->err = 0;
	PHPC_THIS->gpgkey = NULL;
	PHPC_THIS->pattern = NULL;

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(gnupg_keylistiterator);
}

/* {{{ create gnupg_keylistiterator */
PHPC_OBJ_HANDLER_CREATE(gnupg_keylistiterator)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(gnupg_keylistiterator);
}

/* {{{ method list gnupg_keylistiterator */
static zend_function_entry gnupg_keylistiterator_methods[] = {
	PHP_ME(gnupg_keylistiterator, __construct, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, current, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, key, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, next, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, rewind, NULL, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, valid, NULL, ZEND_ACC_PUBLIC)
	PHPC_FE_END
};
/* }}} */

/* {{{ _gnupg_keylistiterator_init
 */
int _gnupg_keylistiterator_init(INIT_FUNC_ARGS)
{
	zend_class_entry ce;

	/* init class */
	INIT_CLASS_ENTRY(ce, "gnupg_keylistiterator", gnupg_keylistiterator_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, gnupg_keylistiterator);
	gnupg_keylistiterator_class_entry = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(gnupg_keylistiterator);
	PHPC_OBJ_SET_HANDLER_OFFSET(gnupg_keylistiterator);
	PHPC_OBJ_SET_HANDLER_FREE(gnupg_keylistiterator);

	zend_class_implements(gnupg_keylistiterator_class_entry TSRMLS_CC, 1, zend_ce_iterator);

	le_gnupg_keylistiterator = zend_register_list_destructors_ex(NULL, NULL, "ctx_keylistiterator", module_number);

	return SUCCESS;
}
/* }}} */

/* {{{ proto __contruct(string $pattern)
 * constructs keylistiterator with supplied pattern
 */
PHP_METHOD(gnupg_keylistiterator, __construct)
{
	char *pattern = NULL;
	phpc_str_size_t pattern_len;

	int args = ZEND_NUM_ARGS();

	GNUPG_GET_ITERATOR();

	if (args > 0) {
		if (zend_parse_parameters(args TSRMLS_CC, "|s", &pattern, &pattern_len) == FAILURE) {
			return;
		}
		PHPC_THIS->pattern = estrdup(pattern);
	}
}
/* }}} */

/* {{{ proto string current() */
PHP_METHOD(gnupg_keylistiterator,current)
{
	GNUPG_GET_ITERATOR();

	PHPC_CSTR_RETURN(PHPC_THIS->gpgkey->uids[0].uid);
}
/* }}} */

/* {{{ proto string key() */
PHP_METHOD(gnupg_keylistiterator,key)
{
	GNUPG_GET_ITERATOR();

	PHPC_CSTR_RETURN(PHPC_THIS->gpgkey->subkeys[0].fpr);
}
/* }}} */

/* {{{ proto bool next() */
PHP_METHOD(gnupg_keylistiterator,next)
{
	GNUPG_GET_ITERATOR();

	if (PHPC_THIS->gpgkey){
		gpgme_key_release(PHPC_THIS->gpgkey);
	}

	if ((PHPC_THIS->err = gpgme_op_keylist_next(PHPC_THIS->ctx, &PHPC_THIS->gpgkey))) {
		gpgme_key_release(PHPC_THIS->gpgkey);
		PHPC_THIS->gpgkey = NULL;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool rewind() */
PHP_METHOD(gnupg_keylistiterator,rewind)
{
	GNUPG_GET_ITERATOR();

	if ((PHPC_THIS->err = gpgme_op_keylist_start(
			 PHPC_THIS->ctx, PHPC_THIS->pattern ? PHPC_THIS->pattern : "", 0)) != GPG_ERR_NO_ERROR){
		zend_throw_exception(zend_exception_get_default(TSRMLS_C), (char *)gpg_strerror(PHPC_THIS->err), 1 TSRMLS_CC);
	}
	if ((PHPC_THIS->err = gpgme_op_keylist_next(PHPC_THIS->ctx, &PHPC_THIS->gpgkey)) != GPG_ERR_NO_ERROR){
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool valid() */
PHP_METHOD(gnupg_keylistiterator,valid)
{
	GNUPG_GET_ITERATOR();

	if (PHPC_THIS->gpgkey != NULL) {
		RETURN_TRUE;
	} else {
		RETURN_FALSE;
	}
}
/* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
