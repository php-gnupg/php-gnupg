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
#include "php_gnupg_compat.h"

static int le_gnupg_keylistiterator;

static zend_class_entry *gnupg_keylistiterator_class_entry;
static zend_object_handlers gnupg_keylistiterator_handlers;

/* Helper macro to get object from zend_object */
static inline gnupg_keylistiterator_object *gnupg_keylistiterator_from_obj(zend_object *obj)
{
	return (gnupg_keylistiterator_object *)((char *)(obj) - XtOffsetOf(gnupg_keylistiterator_object, std));
}

#define Z_GNUPG_KEYLISTITERATOR_P(zv) gnupg_keylistiterator_from_obj(Z_OBJ_P(zv))

/* {{{ GNUPG_GET_ITERATOR */
#define GNUPG_GET_ITERATOR() \
	zval *this = getThis(); \
	gnupg_keylistiterator_object *intern = NULL; \
	do { \
		if (this) { \
			intern = Z_GNUPG_KEYLISTITERATOR_P(this); \
			if (!intern) { \
				php_error_docref(NULL, E_WARNING, "Invalid or unitialized gnupg_keylistiterator object"); \
				RETURN_FALSE; \
			} \
		} \
	} while (0)
/* }}} */

/* {{{ gnupg_keylistiterator_object_free */
static void gnupg_keylistiterator_object_free(zend_object *object)
{
	gnupg_keylistiterator_object *intern = gnupg_keylistiterator_from_obj(object);

	gpgme_op_keylist_end(intern->ctx);
	gpgme_key_release(intern->gpgkey);
	gpgme_release(intern->ctx);
	if (intern->pattern) {
		efree(intern->pattern);
	}

	zend_object_std_dtor(&intern->std);
}
/* }}} */

/* {{{ gnupg_keylistiterator_object_create */
static zend_object *gnupg_keylistiterator_object_create(zend_class_entry *ce)
{
	gnupg_keylistiterator_object *intern;

	intern = ecalloc(1, sizeof(gnupg_keylistiterator_object) + zend_object_properties_size(ce));

	gpgme_check_version(NULL);
	gpgme_new(&intern->ctx);
	intern->err = 0;
	intern->gpgkey = NULL;
	intern->pattern = NULL;

	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &gnupg_keylistiterator_handlers;

	return &intern->std;
}
/* }}} */

/* {{{ arginfo for gnupg void iterator method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_void_iterator_method, 0, 0, 0)
ZEND_END_ARG_INFO()
/* }}} */

ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(arginfo_gnupg_current, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

#define arginfo_gnupg_key arginfo_gnupg_current

ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(arginfo_gnupg_valid, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(arginfo_gnupg_next, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

#define arginfo_gnupg_rewind  arginfo_gnupg_next

/* {{{ method list gnupg_keylistiterator */
static const zend_function_entry gnupg_keylistiterator_methods[] = {
	PHP_ME(gnupg_keylistiterator, __construct, arginfo_gnupg_void_iterator_method, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
	PHP_ME(gnupg_keylistiterator, current, arginfo_gnupg_current, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, key, arginfo_gnupg_key, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, next, arginfo_gnupg_next, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, rewind, arginfo_gnupg_rewind, ZEND_ACC_PUBLIC)
	PHP_ME(gnupg_keylistiterator, valid, arginfo_gnupg_valid, ZEND_ACC_PUBLIC)
	PHP_FE_END
};
/* }}} */

/* {{{ gnupg_keylistiterator_init
 */
int gnupg_keylistiterator_init(INIT_FUNC_ARGS)
{
	zend_class_entry ce;

	/* init class */
	INIT_CLASS_ENTRY(ce, "gnupg_keylistiterator", gnupg_keylistiterator_methods);
	ce.create_object = gnupg_keylistiterator_object_create;
	gnupg_keylistiterator_class_entry = zend_register_internal_class(&ce);

	memcpy(&gnupg_keylistiterator_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	gnupg_keylistiterator_handlers.offset = XtOffsetOf(gnupg_keylistiterator_object, std);
	gnupg_keylistiterator_handlers.free_obj = gnupg_keylistiterator_object_free;

	zend_class_implements(gnupg_keylistiterator_class_entry, 1, zend_ce_iterator);

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
	size_t pattern_len;

	int args = ZEND_NUM_ARGS();

	GNUPG_GET_ITERATOR();

	if (args > 0) {
		if (zend_parse_parameters(args, "|s", &pattern, &pattern_len) == FAILURE) {
			return;
		}
		intern->pattern = estrdup(pattern);
	}
}
/* }}} */

/* {{{ proto string current() */
PHP_METHOD(gnupg_keylistiterator, current)
{
	GNUPG_GET_ITERATOR();

	RETURN_STRING(intern->gpgkey->uids[0].uid);
}
/* }}} */

/* {{{ proto string key() */
PHP_METHOD(gnupg_keylistiterator, key)
{
	GNUPG_GET_ITERATOR();

	RETURN_STRING(intern->gpgkey->subkeys[0].fpr);
}
/* }}} */

/* {{{ proto bool next() */
PHP_METHOD(gnupg_keylistiterator, next)
{
	GNUPG_GET_ITERATOR();

	if (intern->gpgkey) {
		gpgme_key_release(intern->gpgkey);
	}

	if ((intern->err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey))) {
		gpgme_key_release(intern->gpgkey);
		intern->gpgkey = NULL;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool rewind() */
PHP_METHOD(gnupg_keylistiterator, rewind)
{
	GNUPG_GET_ITERATOR();

	if ((intern->err = gpgme_op_keylist_start(
			 intern->ctx, intern->pattern ? intern->pattern : "", 0)) != GPG_ERR_NO_ERROR) {
		zend_throw_exception(zend_ce_exception, (char *)gpgme_strerror(intern->err), 1);
	}
	if ((intern->err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey)) != GPG_ERR_NO_ERROR) {
		RETURN_FALSE;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool valid() */
PHP_METHOD(gnupg_keylistiterator, valid)
{
	GNUPG_GET_ITERATOR();

	if (intern->gpgkey != NULL) {
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
