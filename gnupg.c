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
#include "zend_exceptions.h"
#include "ext/standard/info.h"
#include "php_gnupg.h"
#include "php_gnupg_compat.h"

#include "php_gnupg_keylistiterator.h"

static zend_class_entry *gnupg_class_entry;

static zend_object_handlers gnupg_object_handlers;

/* Helper to get object from zend_object */
static inline gnupg_object *gnupg_object_from_zobj(zend_object *obj) {
	return (gnupg_object *)((char *)(obj) - XtOffsetOf(gnupg_object, std));
}

#define Z_GNUPG_P(zv) gnupg_object_from_zobj(Z_OBJ_P(zv))

/* {{{ GNUPG_GETOBJ */
#define GNUPG_GETOBJ() \
	zval *this = getThis(); \
	gnupg_object *intern = NULL; \
	do { \
		if (this) { \
			intern = Z_GNUPG_P(this); \
			if (!intern) { \
				php_error_docref(NULL, E_WARNING, \
					"Invalid or unitialized gnupg object"); \
				RETURN_FALSE; \
			} \
		} \
	} while (0)
/* }}} */

/* {{{ GNUPG_ERR */
#define GNUPG_ERR(error) \
	if (intern) { \
		switch (intern->errormode) { \
			case 1: \
				php_error_docref(NULL, E_WARNING, (char*)error); \
				break; \
			case 2: \
				zend_throw_exception(zend_ce_exception, (char*) error, 0); \
				break; \
			default: \
				intern->errortxt = (char*)error; \
		} \
	} else { \
		php_error_docref(NULL, E_WARNING, (char*)error); \
	} \
	do { \
		if (return_value) { \
			RETVAL_FALSE; \
		} \
	} while (0)
/* }}} */

/* {{{ php_gnupg_free_encryptkeys */
static void php_gnupg_free_encryptkeys(gnupg_object *intern)
{
	if (intern) {
		int idx;
		/* loop through all encryptkeys and unref them in the gpgme-lib */
		for (idx = 0; idx < intern->encrypt_size; idx++) {
			gpgme_key_unref(intern->encryptkeys[idx]);
		}
		if (intern->encryptkeys != NULL) {
			efree(intern->encryptkeys);
		}
		intern->encryptkeys = NULL;
		intern->encrypt_size = 0;
	}
}
/* }}} */

/* {{{ php_gnupg_free */
static void php_gnupg_free(gnupg_object *intern)
{
	if (intern) {
		if (intern->ctx) {
			/* clear all signers from the gpgme-lib and finally release it */
			gpgme_signers_clear(intern->ctx);
			gpgme_release(intern->ctx);
			intern->ctx = NULL;
		}
		/* basic cleanup */
		php_gnupg_free_encryptkeys(intern);
		zend_hash_destroy(intern->signkeys);
		FREE_HASHTABLE(intern->signkeys);
		zend_hash_destroy(intern->decryptkeys);
		FREE_HASHTABLE(intern->decryptkeys);
	}
}
/* }}} */

/* {{{ php_gnupg_init */
static void php_gnupg_init(gnupg_object *intern)
{
	/* init the gpgme-lib and set the default values */
	gpgme_ctx_t	ctx;
	gpgme_error_t err;

	err = gpgme_new(&ctx);
	intern->ctx = ctx;
	intern->encryptkeys = NULL;
	intern->encrypt_size = 0;
	intern->signmode = GPGME_SIG_MODE_CLEAR;
	intern->err = err;
	intern->errortxt = NULL;
	intern->errormode = 3;
	ALLOC_HASHTABLE(intern->signkeys);
	zend_hash_init(intern->signkeys, 0, NULL, NULL, 0);
	ALLOC_HASHTABLE(intern->decryptkeys);
	zend_hash_init(intern->decryptkeys, 0, NULL, NULL, 0);
}
/* }}} */

/* set GNUPG_PATH to NULL if not defined */
#ifndef GNUPG_PATH
#define GNUPG_PATH NULL
#endif

/* {{{ php_gnupg_make */
static void php_gnupg_make(gnupg_object *intern, zval *options)
{
	if (intern->err == GPG_ERR_NO_ERROR) {
		char *file_name = GNUPG_PATH;
		char *home_dir = NULL;
		zval *pv_file_name, *pv_home_dir;
		gpgme_ctx_t	ctx = intern->ctx;

		if (options && (pv_file_name = zend_hash_str_find(Z_ARRVAL_P(options), "file_name", sizeof("file_name")-1)) != NULL) {
			file_name = Z_STRVAL_P(pv_file_name);
		}
		if (options && (pv_home_dir = zend_hash_str_find(Z_ARRVAL_P(options), "home_dir", sizeof("home_dir")-1)) != NULL) {
			home_dir = Z_STRVAL_P(pv_home_dir);
		}

		if (file_name != NULL || home_dir != NULL) {
			if (gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, file_name, home_dir) != GPG_ERR_NO_ERROR) {
				zend_throw_exception(zend_ce_exception, (char*) "Setting engine info failed", 0);
			}
		}
		gpgme_set_armor(ctx, 1);
#if GPGME_VERSION_NUMBER >= 0x010400  /* GPGME >= 1.4.0 */
		gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);
#endif
	}
}
/* }}} */

/* {{{ free gnupg object */
static void gnupg_object_free(zend_object *object)
{
	gnupg_object *intern = gnupg_object_from_zobj(object);

	php_gnupg_free(intern);

	zend_object_std_dtor(&intern->std);
}
/* }}} */

/* {{{ create_ex gnupg object */
static zend_object *gnupg_object_create_ex(zend_class_entry *class_type, int init_props)
{
	gnupg_object *intern;

	intern = ecalloc(1, sizeof(gnupg_object) + zend_object_properties_size(class_type));

	zend_object_std_init(&intern->std, class_type);
	if (init_props) {
		object_properties_init(&intern->std, class_type);
	}

	php_gnupg_init(intern);

	intern->std.handlers = &gnupg_object_handlers;

	return &intern->std;
}
/* }}} */

/* {{{ create gnupg object */
static zend_object *gnupg_object_create(zend_class_entry *class_type)
{
	return gnupg_object_create_ex(class_type, 1);
}
/* }}} */

/* {{{ arginfo for gnupg __construct and gnupg_init */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_init, 0, 0, 0)
	ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg void methods */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_void_method, 0, 0, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg method with armor parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_armor_method, 0)
	ZEND_ARG_INFO(0, armor)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with enctext parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_enctext_method, 0)
	ZEND_ARG_INFO(0, enctext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with text parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_text_method, 0)
	ZEND_ARG_INFO(0, text)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with key parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_key_method, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with adddecryptkey parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_key_passphrase_method, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, passphrase)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with deletekey parameter */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_deletekey_method, 0, 0, 1)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, allow_secret)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with keyid parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_keyid_method, 0)
	ZEND_ARG_INFO(0, keyid)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg_keyinfo method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_keyinfo_method, 0, 0, 1)
	ZEND_ARG_INFO(0, pattern)
	ZEND_ARG_INFO(0, secret_only)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with pattern parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_pattern_method, 0)
	ZEND_ARG_INFO(0, pattern)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with errmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_errmode_method, 0)
	ZEND_ARG_INFO(0, errormode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with signmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_signmode_method, 0)
	ZEND_ARG_INFO(0, signmode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg_verify method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_verify_method, 0, 0, 2)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg_decryptverify method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_decryptverify_method, 0, 0, 2)
	ZEND_ARG_INFO(0, enctext)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

#define PHP_GNUPG_FALIAS(_name, _arginfo) \
	PHP_FALIAS(_name, gnupg_ ## _name, _arginfo)

/* {{{ methodlist gnupg */
const zend_function_entry gnupg_methods[] = {
	PHP_ME(gnupg, __construct, arginfo_gnupg_init, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_GNUPG_FALIAS(keyinfo,           arginfo_gnupg_keyinfo_method)
	PHP_GNUPG_FALIAS(verify,            arginfo_gnupg_verify_method)
	PHP_GNUPG_FALIAS(getengineinfo,     arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(geterror,          arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(geterrorinfo,      arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(clearsignkeys,     arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(clearencryptkeys,  arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(cleardecryptkeys,  arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(setarmor,          arginfo_gnupg_armor_method)
	PHP_GNUPG_FALIAS(encrypt,           arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(decrypt,           arginfo_gnupg_enctext_method)
	PHP_GNUPG_FALIAS(messagekeys,       arginfo_gnupg_enctext_method)
	PHP_GNUPG_FALIAS(export,            arginfo_gnupg_pattern_method)
	PHP_GNUPG_FALIAS(import,            arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(getprotocol,       arginfo_gnupg_void_method)
	PHP_GNUPG_FALIAS(setsignmode,       arginfo_gnupg_signmode_method)
	PHP_GNUPG_FALIAS(sign,              arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(encryptsign,       arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(decryptverify,     arginfo_gnupg_decryptverify_method)
	PHP_GNUPG_FALIAS(addsignkey,        arginfo_gnupg_key_passphrase_method)
	PHP_GNUPG_FALIAS(addencryptkey,     arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(adddecryptkey,     arginfo_gnupg_key_passphrase_method)
	PHP_GNUPG_FALIAS(deletekey,         arginfo_gnupg_deletekey_method)
#if GPGME_VERSION_NUMBER < 0x020000  /* GPGME < 2.0.0 */
	PHP_GNUPG_FALIAS(gettrustlist,      arginfo_gnupg_pattern_method)
#endif
	PHP_GNUPG_FALIAS(listsignatures,    arginfo_gnupg_keyid_method)
	PHP_GNUPG_FALIAS(seterrormode,      arginfo_gnupg_errmode_method)
	PHP_FE_END
};
/* }}} */

/* {{{ arginfo for gnupg function with gnupg parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_void_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg init */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_init_function, 0, 0, 0)
	ZEND_ARG_INFO(0, options)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg function with armor parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_armor_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, armor)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with enctext parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_enctext_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, enctext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with text parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_text_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, text)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with key parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_key_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with deletekey parameter */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_deletekey_function, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, allow_secret)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with adddecryptkey parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_key_passphrase_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, key)
	ZEND_ARG_INFO(0, passphrase)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with keyid parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_keyid_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, keyid)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg_keyinfo function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_keyinfo_function, 0, 0, 2)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, pattern)
	ZEND_ARG_INFO(0, secret_only)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with pattern parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_pattern_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, pattern)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with errmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_errmode_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, errormode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with signmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_signmode_function, 0)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, signmode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_verify_function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_verify_function, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_decryptverify_function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_decryptverify_function, 0, 0, 3)
	ZEND_ARG_OBJ_INFO(0, gnupg, gnupg, 0)
	ZEND_ARG_INFO(0, enctext)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ functionlist gnupg */
static const zend_function_entry gnupg_functions[] = {
	PHP_FE(gnupg_init,				arginfo_gnupg_init_function)
	PHP_FE(gnupg_keyinfo,			arginfo_gnupg_keyinfo_function)
	PHP_FE(gnupg_sign,				arginfo_gnupg_text_function)
	PHP_FE(gnupg_verify,			arginfo_gnupg_verify_function)
	PHP_FE(gnupg_clearsignkeys,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_clearencryptkeys,	arginfo_gnupg_void_function)
	PHP_FE(gnupg_cleardecryptkeys,	arginfo_gnupg_void_function)
	PHP_FE(gnupg_setarmor,			arginfo_gnupg_armor_function)
	PHP_FE(gnupg_encrypt,			arginfo_gnupg_text_function)
	PHP_FE(gnupg_decrypt,			arginfo_gnupg_enctext_function)
	PHP_FE(gnupg_messagekeys,		arginfo_gnupg_enctext_function)
	PHP_FE(gnupg_export,			arginfo_gnupg_pattern_function)
	PHP_FE(gnupg_import,			arginfo_gnupg_key_function)
	PHP_FE(gnupg_getengineinfo,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_getprotocol,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_setsignmode,		arginfo_gnupg_signmode_function)
	PHP_FE(gnupg_encryptsign,		arginfo_gnupg_text_function)
	PHP_FE(gnupg_decryptverify,		arginfo_gnupg_decryptverify_function)
	PHP_FE(gnupg_geterror,			arginfo_gnupg_void_function)
	PHP_FE(gnupg_geterrorinfo,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_addsignkey,		arginfo_gnupg_key_passphrase_function)
	PHP_FE(gnupg_addencryptkey,		arginfo_gnupg_key_function)
	PHP_FE(gnupg_adddecryptkey,		arginfo_gnupg_key_passphrase_function)
	PHP_FE(gnupg_deletekey,			arginfo_gnupg_deletekey_function)
#if GPGME_VERSION_NUMBER < 0x020000  /* GPGME < 2.0.0 */
	PHP_FE(gnupg_gettrustlist,		arginfo_gnupg_pattern_function)
#endif
	PHP_FE(gnupg_listsignatures,	arginfo_gnupg_keyid_function)
	PHP_FE(gnupg_seterrormode,		arginfo_gnupg_errmode_function)
	PHP_FE_END
};
/* }}} */

/* {{{ gnupg_module_entry
 */
zend_module_entry gnupg_module_entry = {
	STANDARD_MODULE_HEADER,
	"gnupg",
	gnupg_functions,
	PHP_MINIT(gnupg),
	PHP_MSHUTDOWN(gnupg),
	NULL,
	NULL,
	PHP_MINFO(gnupg),
	PHP_GNUPG_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_GNUPG
ZEND_GET_MODULE(gnupg)
#endif

#define PHP_GNUPG_DO(_action) ((intern->err = _action) == GPG_ERR_NO_ERROR)

#define PHP_GNUPG_VERSION_BUF_SIZE 64

#define PHP_GNUPG_SET_CLASS_CONST(_name, _value) \
	zend_declare_class_constant_long(gnupg_class_entry, \
		_name, sizeof(_name) - 1, _value)

#define PHP_GNUPG_REG_CONST(_name, _value) \
	REGISTER_LONG_CONSTANT(_name,  _value, CONST_CS | CONST_PERSISTENT);

#define PHP_GNUPG_REG_CONST_STR(_name, _value) \
	REGISTER_STRING_CONSTANT(_name,  _value, CONST_CS | CONST_PERSISTENT);

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(gnupg)
{
	zend_class_entry ce;
	char php_gpgme_version[PHP_GNUPG_VERSION_BUF_SIZE];

	/* init class */
	INIT_CLASS_ENTRY(ce, "gnupg", gnupg_methods);
	ce.create_object = gnupg_object_create;
	gnupg_class_entry = zend_register_internal_class(&ce);

	memcpy(&gnupg_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	gnupg_object_handlers.offset = XtOffsetOf(gnupg_object, std);
	gnupg_object_handlers.free_obj = gnupg_object_free;

	if (SUCCESS != gnupg_keylistiterator_init(type, module_number)) {
		return FAILURE;
	}

	PHP_GNUPG_SET_CLASS_CONST("SIG_MODE_NORMAL",    GPGME_SIG_MODE_NORMAL);
	PHP_GNUPG_SET_CLASS_CONST("SIG_MODE_DETACH",    GPGME_SIG_MODE_DETACH);
	PHP_GNUPG_SET_CLASS_CONST("SIG_MODE_CLEAR",     GPGME_SIG_MODE_CLEAR);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_UNKNOWN",   GPGME_VALIDITY_UNKNOWN);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_UNDEFINED", GPGME_VALIDITY_UNDEFINED);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_NEVER",     GPGME_VALIDITY_NEVER);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_MARGINAL",  GPGME_VALIDITY_MARGINAL);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_FULL",      GPGME_VALIDITY_FULL);
	PHP_GNUPG_SET_CLASS_CONST("VALIDITY_ULTIMATE",  GPGME_VALIDITY_ULTIMATE);
	PHP_GNUPG_SET_CLASS_CONST("PROTOCOL_OpenPGP",   GPGME_PROTOCOL_OpenPGP);
	PHP_GNUPG_SET_CLASS_CONST("PROTOCOL_CMS",       GPGME_PROTOCOL_CMS);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_VALID",       GPGME_SIGSUM_VALID);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_GREEN",       GPGME_SIGSUM_GREEN);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_RED",         GPGME_SIGSUM_RED);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_KEY_REVOKED", GPGME_SIGSUM_KEY_REVOKED);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_KEY_EXPIRED", GPGME_SIGSUM_KEY_EXPIRED);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_SIG_EXPIRED", GPGME_SIGSUM_SIG_EXPIRED);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_KEY_MISSING", GPGME_SIGSUM_KEY_MISSING);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_CRL_MISSING", GPGME_SIGSUM_CRL_MISSING);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_CRL_TOO_OLD", GPGME_SIGSUM_CRL_TOO_OLD);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_BAD_POLICY",  GPGME_SIGSUM_BAD_POLICY);
	PHP_GNUPG_SET_CLASS_CONST("SIGSUM_SYS_ERROR",   GPGME_SIGSUM_SYS_ERROR);
	PHP_GNUPG_SET_CLASS_CONST("ERROR_WARNING",      1);
	PHP_GNUPG_SET_CLASS_CONST("ERROR_EXCEPTION",    2);
	PHP_GNUPG_SET_CLASS_CONST("ERROR_SILENT",       3);
	PHP_GNUPG_SET_CLASS_CONST("PK_RSA",             GPGME_PK_RSA);
	PHP_GNUPG_SET_CLASS_CONST("PK_RSA_E",           GPGME_PK_RSA_E);
	PHP_GNUPG_SET_CLASS_CONST("PK_RSA_S",           GPGME_PK_RSA_S);
	PHP_GNUPG_SET_CLASS_CONST("PK_DSA",             GPGME_PK_DSA);
	PHP_GNUPG_SET_CLASS_CONST("PK_ELG",             GPGME_PK_ELG);
	PHP_GNUPG_SET_CLASS_CONST("PK_ELG_E",           GPGME_PK_ELG_E);
#if GPGME_VERSION_NUMBER >= 0x010500  /* GPGME >= 1.5.0 */
	PHP_GNUPG_SET_CLASS_CONST("PK_ECC",             GPGME_PK_ECC);
#endif /* gpgme >= 1.5.0 */
	PHP_GNUPG_SET_CLASS_CONST("PK_ECDSA",           GPGME_PK_ECDSA);
	PHP_GNUPG_SET_CLASS_CONST("PK_ECDH",            GPGME_PK_ECDH);
#if GPGME_VERSION_NUMBER >= 0x010700  /* GPGME >= 1.7.0 */
	PHP_GNUPG_SET_CLASS_CONST("PK_EDDSA",           GPGME_PK_EDDSA);
#endif /* gpgme >= 1.7.0 */

	PHP_GNUPG_REG_CONST("GNUPG_SIG_MODE_NORMAL",    GPGME_SIG_MODE_NORMAL);
	PHP_GNUPG_REG_CONST("GNUPG_SIG_MODE_DETACH",    GPGME_SIG_MODE_DETACH);
	PHP_GNUPG_REG_CONST("GNUPG_SIG_MODE_CLEAR",     GPGME_SIG_MODE_CLEAR);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_UNKNOWN",   GPGME_VALIDITY_UNKNOWN);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_UNDEFINED", GPGME_VALIDITY_UNDEFINED);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_NEVER",     GPGME_VALIDITY_NEVER);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_MARGINAL",  GPGME_VALIDITY_MARGINAL);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_FULL",      GPGME_VALIDITY_FULL);
	PHP_GNUPG_REG_CONST("GNUPG_VALIDITY_ULTIMATE",  GPGME_VALIDITY_ULTIMATE);
	PHP_GNUPG_REG_CONST("GNUPG_PROTOCOL_OpenPGP",   GPGME_PROTOCOL_OpenPGP);
	PHP_GNUPG_REG_CONST("GNUPG_PROTOCOL_CMS",       GPGME_PROTOCOL_CMS);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_VALID",       GPGME_SIGSUM_VALID);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_GREEN",       GPGME_SIGSUM_GREEN);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_RED",         GPGME_SIGSUM_RED);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_KEY_REVOKED", GPGME_SIGSUM_KEY_REVOKED);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_KEY_EXPIRED", GPGME_SIGSUM_KEY_EXPIRED);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_SIG_EXPIRED", GPGME_SIGSUM_SIG_EXPIRED);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_KEY_MISSING", GPGME_SIGSUM_KEY_MISSING);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_CRL_MISSING", GPGME_SIGSUM_CRL_MISSING);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_CRL_TOO_OLD", GPGME_SIGSUM_CRL_TOO_OLD);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_BAD_POLICY",  GPGME_SIGSUM_BAD_POLICY);
	PHP_GNUPG_REG_CONST("GNUPG_SIGSUM_SYS_ERROR",   GPGME_SIGSUM_SYS_ERROR);
	PHP_GNUPG_REG_CONST("GNUPG_ERROR_WARNING",      1);
	PHP_GNUPG_REG_CONST("GNUPG_ERROR_EXCEPTION",    2);
	PHP_GNUPG_REG_CONST("GNUPG_ERROR_SILENT",       3);
	PHP_GNUPG_REG_CONST("GNUPG_PK_RSA",             GPGME_PK_RSA);
	PHP_GNUPG_REG_CONST("GNUPG_PK_RSA_E",           GPGME_PK_RSA_E);
	PHP_GNUPG_REG_CONST("GNUPG_PK_RSA_S",           GPGME_PK_RSA_S);
	PHP_GNUPG_REG_CONST("GNUPG_PK_DSA",             GPGME_PK_DSA);
	PHP_GNUPG_REG_CONST("GNUPG_PK_ELG",             GPGME_PK_ELG);
	PHP_GNUPG_REG_CONST("GNUPG_PK_ELG_E",           GPGME_PK_ELG_E);
#if GPGME_VERSION_NUMBER >= 0x010500  /* GPGME >= 1.5.0 */
	PHP_GNUPG_REG_CONST("GNUPG_PK_ECC",             GPGME_PK_ECC);
#endif /* gpgme >= 1.5.0 */
	PHP_GNUPG_REG_CONST("GNUPG_PK_ECDSA",           GPGME_PK_ECDSA);
	PHP_GNUPG_REG_CONST("GNUPG_PK_ECDH",            GPGME_PK_ECDH);
#if GPGME_VERSION_NUMBER >= 0x010700  /* GPGME >= 1.7.0 */
	PHP_GNUPG_REG_CONST("GNUPG_PK_EDDSA",           GPGME_PK_EDDSA);
#endif /* gpgme >= 1.7.0 */

	/* init gpgme subsystems and set the returned version to the constant */
	strncpy(php_gpgme_version, gpgme_check_version(NULL), PHP_GNUPG_VERSION_BUF_SIZE);
	php_gpgme_version[PHP_GNUPG_VERSION_BUF_SIZE - 1] = '\0';
	PHP_GNUPG_REG_CONST_STR("GNUPG_GPGME_VERSION", php_gpgme_version);

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(gnupg)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(gnupg)
{
	const char *php_gpgme_version = gpgme_check_version(NULL);

	php_info_print_table_start();
	php_info_print_table_header(2, "gnupg support", "enabled");
	php_info_print_table_row(2, "GPGme Version", php_gpgme_version);
	php_info_print_table_row(2, "Extension Version", PHP_GNUPG_VERSION);
	php_info_print_table_end();
}
/* }}} */

/* {{{ passphrase_cb */
gpgme_error_t passphrase_cb(
		void *hook, const char *uid_hint, const char *passphrase_info,
		int last_was_bad, int fd)
{
	char uid[17];
	int idx;
	char *passphrase = NULL;
	zval *return_value = NULL;
	gnupg_object *intern = hook;

	if (last_was_bad) {
		GNUPG_ERR("Incorrent passphrase");
		return 1;
	}
	for (idx=0; idx < 16 && uid_hint[idx] != '\0'; idx++) {
		uid[idx] = uid_hint[idx];
	}
	uid[idx] = '\0';

	passphrase = zend_hash_str_find_ptr(intern->signkeys, (char *)uid, strlen((char *)uid));
	if (!passphrase) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}

	if (write(fd, passphrase, strlen(passphrase)) == strlen(passphrase)
			&& write(fd, "\n", 1) == 1) {
		return 0;
	}
	GNUPG_ERR("write failed");
	return 1;
}
/* }}} */

/* {{{ passphrase_decrypt_cb */
gpgme_error_t passphrase_decrypt_cb (
		void *hook,
		const char *uid_hint, const char *passphrase_info,
		int last_was_bad, int fd)
{
	char uid[17];
	int idx;
	char *passphrase = NULL;
	zval *return_value = NULL;
	gnupg_object *intern = hook;

	if (last_was_bad) {
		GNUPG_ERR("Incorrent passphrase");
		return 1;
	}
	if (uid_hint == NULL) {
		GNUPG_ERR("No user ID hint");
		return 1;
	}
	for (idx=0; idx < 16 && uid_hint[idx] != '\0'; idx++) {
		uid[idx] = uid_hint[idx];
	}
	uid[idx] = '\0';

	passphrase = zend_hash_str_find_ptr(intern->decryptkeys, (char *)uid, strlen((char *)uid));
	if (!passphrase) {
		/* If the requested key is not in decryptkeys, ignore it and return success. It then tries
		 * to call callback for the next key if the message was encrypted with more than one key. */
		write(fd, "\n", 1);
		return 0;
	}

	if (write(fd, passphrase, strlen(passphrase)) == strlen(passphrase)
			&& write(fd, "\n", 1) == 1) {
		return 0;
	}
	GNUPG_ERR("write failed");
	return 1;
}
/* }}} */

/* {{{ gnupg_fetchsignatures */
int gnupg_fetchsignatures(gpgme_signature_t gpgme_signatures, zval *main_arr)
{
	zval sig_arr;

	array_init(main_arr);
	while (gpgme_signatures) {
		array_init(&sig_arr);
		add_assoc_string(&sig_arr, "fingerprint", gpgme_signatures->fpr);
		add_assoc_long(&sig_arr, "validity", gpgme_signatures->validity);
		add_assoc_long(&sig_arr, "timestamp", gpgme_signatures->timestamp);
		add_assoc_long(&sig_arr, "status", gpgme_signatures->status);
		add_assoc_long(&sig_arr, "summary", gpgme_signatures->summary);

		add_next_index_zval(main_arr, &sig_arr);

		gpgme_signatures = gpgme_signatures->next;
	}
	return 1;
}
/* }}} */

/* {{{ proto gnupg::__construct(array options = NULL)
 * construct gnupg object
*/
PHP_METHOD(gnupg, __construct)
{
	zval *options = NULL;
	gnupg_object *intern;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|a", &options) == FAILURE) {
		return;
	}

	intern = Z_GNUPG_P(getThis());
	php_gnupg_make(intern, options);
}
/* }}} */

/* {{{ proto object gnupg_init(array options = NULL)
 * inits gnupg and returns an object
*/
PHP_FUNCTION(gnupg_init)
{
	zval *options = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|a", &options) == FAILURE) {
		return;
	}

	object_init_ex(return_value, gnupg_class_entry);
	gnupg_object *intern = Z_GNUPG_P(return_value);
	php_gnupg_make(intern, options);
}
/* }}} */

/* {{{ proto bool gnupg_setarmor(int armor)
 * turn on/off armor mode
 * 0 = off
 * >0 = on
 * */
PHP_FUNCTION(gnupg_setarmor)
{
	zval *object = NULL;
	zend_long armor;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &armor) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Ol", &object, gnupg_class_entry, &armor) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	if (armor > 1) {
		armor = 1; /*just to make sure */
	}

	gpgme_set_armor(intern->ctx, armor);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_seterrormode(int errormode) */
PHP_FUNCTION(gnupg_seterrormode)
{
	zval *object = NULL;
	zend_long errormode;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &errormode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Ol", &object, gnupg_class_entry, &errormode) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	switch (errormode) {
		case 1:		/* warning */
		case 3:		/* silent */
			intern->errormode = errormode;
			break;
		case 2:		/* exception */
			intern->errormode = errormode;
			break;
		default:
			GNUPG_ERR("invalid errormode");
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_setsignmode(int signmode)
 * sets the mode for signing operations
 */
PHP_FUNCTION(gnupg_setsignmode)
{
	zval *object = NULL;
	zend_long signmode;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &signmode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Ol", &object, gnupg_class_entry, &signmode) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	switch (signmode) {
		case GPGME_SIG_MODE_NORMAL:
		case GPGME_SIG_MODE_DETACH:
		case GPGME_SIG_MODE_CLEAR:
			intern->signmode = signmode;
			RETVAL_TRUE;
			break;
		default:
			GNUPG_ERR("invalid signmode");
			RETVAL_FALSE;
			break;
	}
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto array gnupg_getengineinfo(void)
 * returns the engine info
 */
PHP_FUNCTION(gnupg_getengineinfo)
{
	zval *object = NULL;
	gpgme_engine_info_t info;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	info = gpgme_ctx_get_engine_info(intern->ctx);

	array_init(return_value);
	add_assoc_long(return_value, "protocol", info->protocol);
	add_assoc_string(return_value, "file_name", info->file_name);
	add_assoc_string(return_value, "home_dir", info->home_dir ? info->home_dir : "");
}
/* }}} */

/* {{{ proto string gnupg_geterror(void)
 * returns the last errormessage
 */
PHP_FUNCTION(gnupg_geterror)
{
	zval *object = NULL;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!intern->errortxt) {
		RETURN_FALSE;
	} else {
		RETURN_STRING(intern->errortxt);
	}
}
/* }}} */

/* {{{ proto string gnupg_geterrorinfo(void)
 * returns the last error info array
 */
PHP_FUNCTION(gnupg_geterrorinfo)
{
	zval *object = NULL;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	array_init(return_value);
	if (intern->errortxt) {
		add_assoc_string(return_value, "generic_message", intern->errortxt);
	} else {
		add_assoc_bool(return_value, "generic_message", 0);
	}
	add_assoc_long(return_value, "gpgme_code", intern->err);
	add_assoc_string(return_value, "gpgme_source", (char *) gpgme_strsource(intern->err));
	add_assoc_string(return_value, "gpgme_message", (char *) gpgme_strerror(intern->err));
}
/* }}} */

/* {{{ proto int gnupg_getprotocol(void)
 * returns the currently used pgp-protocol.
 * atm only OpenPGP is supported
 */
PHP_FUNCTION(gnupg_getprotocol) {
	RETURN_LONG(GPGME_PROTOCOL_OpenPGP);
}
/* }}} */

/* {{{ proto array gnupg_keyinfo(string pattern, bool secret_only = false)
 * returns an array with informations about all keys, that matches
 * the given pattern
 */
PHP_FUNCTION(gnupg_keyinfo)
{
	zval *object = NULL;
	char *searchkey = NULL;
	size_t searchkey_len;
	zval subarr, userid, userids, subkey, subkeys;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;
	gpgme_user_id_t gpgme_userid;
	zend_bool secret_only = 0;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|b",
				&searchkey, &searchkey_len, &secret_only) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os|b",
				&object, gnupg_class_entry, &searchkey, &searchkey_len, &secret_only) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	intern->err = gpgme_op_keylist_start(intern->ctx, searchkey, secret_only);
	if ((intern->err) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not init keylist");
		return;
	}

	array_init(return_value);

	while (PHP_GNUPG_DO(gpgme_op_keylist_next(intern->ctx, &gpgme_key))) {
		array_init(&subarr);
		array_init(&subkeys);
		array_init(&userids);

		add_assoc_bool(&subarr, "disabled", gpgme_key->disabled);
		add_assoc_bool(&subarr, "expired", gpgme_key->expired);
		add_assoc_bool(&subarr, "revoked", gpgme_key->revoked);
		add_assoc_bool(&subarr, "is_secret", gpgme_key->secret);
		add_assoc_bool(&subarr, "can_sign", gpgme_key->can_sign);
		add_assoc_bool(&subarr, "can_encrypt", gpgme_key->can_encrypt);

		gpgme_userid = gpgme_key->uids;
		while (gpgme_userid) {
			array_init(&userid);

			add_assoc_string(&userid, "name", gpgme_userid->name);
			add_assoc_string(&userid, "comment", gpgme_userid->comment);
			add_assoc_string(&userid, "email", gpgme_userid->email);
			add_assoc_string(&userid, "uid", gpgme_userid->uid);

			add_assoc_bool(&userid, "revoked", gpgme_userid->revoked);
			add_assoc_bool(&userid, "invalid", gpgme_userid->invalid);

			add_next_index_zval(&userids, &userid);
			gpgme_userid = gpgme_userid->next;
		}

		add_assoc_zval(&subarr, "uids", &userids);

		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			array_init(&subkey);

			if (gpgme_subkey->fpr) {
				add_assoc_string(&subkey, "fingerprint", gpgme_subkey->fpr);
			}

			add_assoc_string(&subkey, "keyid", gpgme_subkey->keyid);
			add_assoc_long(&subkey, "timestamp", gpgme_subkey->timestamp);
			add_assoc_long(&subkey, "expires", gpgme_subkey->expires);
			add_assoc_bool(&subkey, "is_secret", gpgme_subkey->secret);
			add_assoc_bool(&subkey, "invalid", gpgme_subkey->invalid);
			add_assoc_bool(&subkey, "can_encrypt", gpgme_subkey->can_encrypt);
			add_assoc_bool(&subkey, "can_sign", gpgme_subkey->can_sign);
			add_assoc_bool(&subkey, "disabled", gpgme_subkey->disabled);
			add_assoc_bool(&subkey, "expired", gpgme_subkey->expired);
			add_assoc_bool(&subkey, "revoked", gpgme_subkey->revoked);
			add_assoc_bool(&subkey, "can_certify", gpgme_subkey->can_certify);
			add_assoc_bool(&subkey, "can_authenticate", gpgme_subkey->can_authenticate);
			add_assoc_bool(&subkey, "is_qualified", gpgme_subkey->is_qualified);
#if GPGME_VERSION_NUMBER >= 0x010900  /* GPGME >= 1.9.0 */
			add_assoc_bool(&subkey, "is_de_vs", gpgme_subkey->is_de_vs);
#endif /* gpgme >= 1.9.0 */
			add_assoc_long(&subkey, "pubkey_algo", gpgme_subkey->pubkey_algo);
			add_assoc_long(&subkey, "length", gpgme_subkey->length);
#if GPGME_VERSION_NUMBER >= 0x010700  /* GPGME >= 1.7.0 */
			if (gpgme_subkey->keygrip) {
				add_assoc_string(&subkey, "keygrip", gpgme_subkey->keygrip);
			}
#endif /* gpgme >= 1.7.0 */
			add_assoc_bool(&subkey, "is_cardkey", gpgme_subkey->is_cardkey);
			if (gpgme_subkey->card_number) {
				add_assoc_string(&subkey, "card_number", gpgme_subkey->card_number);
			}
#if GPGME_VERSION_NUMBER >= 0x010500  /* GPGME >= 1.5.0 */
			if (gpgme_subkey->curve) {
				add_assoc_string(&subkey, "curve", gpgme_subkey->curve);
			}
#endif

			add_next_index_zval(&subkeys, &subkey);
			gpgme_subkey = gpgme_subkey->next;
		}

		add_assoc_zval(&subarr, "subkeys", &subkeys);

		add_next_index_zval(return_value, &subarr);
		gpgme_key_unref(gpgme_key);
	}
}
/* }}} */

/* {{{ proto bool gnupg_addsignkey(string key) */
PHP_FUNCTION(gnupg_addsignkey)
{
	zval *object = NULL;
	char *key_id = NULL;
	size_t key_id_len;
	char *passphrase = NULL;
	size_t passphrase_len;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|s",
				&key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os|s",
				&object, gnupg_class_entry, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if (passphrase) {
		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			if (gpgme_subkey->can_sign == 1) {
				zend_hash_str_add_ptr(intern->signkeys, gpgme_subkey->keyid, strlen(gpgme_subkey->keyid), passphrase);
			}
			gpgme_subkey = gpgme_subkey->next;
		}
	}
	if (!PHP_GNUPG_DO(gpgme_signers_add(intern->ctx, gpgme_key))) {
		GNUPG_ERR("could not add signer");
	} else {
		RETVAL_TRUE;
	}
	gpgme_key_unref(gpgme_key);
}
/* }}} */

/* {{{ proto bool gnupg_adddecryptkey(string key) */
PHP_FUNCTION(gnupg_adddecryptkey)
{
	zval *object = NULL;
	char *key_id = NULL;
	size_t key_id_len;
	char *passphrase = NULL;
	size_t passphrase_len;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss",
				&key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Oss",
				&object, gnupg_class_entry, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!PHP_GNUPG_DO(gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	gpgme_subkey = gpgme_key->subkeys;
	while (gpgme_subkey) {
		if (gpgme_subkey->secret == 1) {
			zend_hash_str_add_ptr(intern->decryptkeys, gpgme_subkey->keyid, strlen(gpgme_subkey->keyid), passphrase);
		}
		gpgme_subkey = gpgme_subkey->next;
	}
	gpgme_key_unref(gpgme_key);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_addencryptkey(string key) */
PHP_FUNCTION(gnupg_addencryptkey)
{
	zval *object = NULL;
	char *key_id = NULL;
	size_t key_id_len;
	gpgme_key_t gpgme_key = NULL;
	size_t encrypt_keys_size;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&key_id, &key_id_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &key_id, &key_id_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(intern->ctx, key_id, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed");
		RETURN_FALSE;
	}

	encrypt_keys_size = sizeof(intern->encryptkeys) * (intern->encrypt_size + 2);
	if (intern->encryptkeys == NULL) {
		intern->encryptkeys = emalloc(encrypt_keys_size);
	} else {
		intern->encryptkeys = erealloc(intern->encryptkeys, encrypt_keys_size);
	}
	intern->encryptkeys[intern->encrypt_size] = gpgme_key;
	intern->encrypt_size++;
	intern->encryptkeys[intern->encrypt_size] = NULL;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_clearsignkeys)
{
	zval *object = NULL;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	gpgme_signers_clear(intern->ctx);
	zend_hash_clean(intern->signkeys);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearencryptkeys(void)
 * removes all keys which are set for encryption
 */
PHP_FUNCTION(gnupg_clearencryptkeys)
{
	zval *object = NULL;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	php_gnupg_free_encryptkeys(intern);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_cleardecryptkeys)
{
	zval *object = NULL;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "O", &object, gnupg_class_entry) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	zend_hash_clean(intern->decryptkeys);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string gnupg_sign(string text)
 * signs the given test with the key, which was set with setsignerkey before
 * and returns the signed text
 * the signmode depends on gnupg_setsignmode
 */
PHP_FUNCTION(gnupg_sign)
{
	zval *object = NULL;
	char *value = NULL;
	size_t value_len;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_sign_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &value, &value_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	gpgme_set_passphrase_cb(intern->ctx, passphrase_cb, intern);
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, value, value_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_sign(intern->ctx, in, out, intern->signmode))) {
		if (!intern->errortxt) {
			GNUPG_ERR("data signing failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	result = gpgme_op_sign_result(intern->ctx);
	if (result->invalid_signers) {
		GNUPG_ERR("invalid signers found");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	if (!result->signatures) {
		GNUPG_ERR("no signature in result");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	if (ret_size < 1) {
		RETVAL_FALSE;
	} else {
		RETVAL_STRINGL(userret, ret_size);
	}
	gpgme_data_release(in);
	free(userret);
}
/* }}} */

/* {{{ proto string gnupg_encrypt(string text)
 * encrypts the given text with the key, which was set with setencryptkey before
 * and returns the encrypted text
 */
PHP_FUNCTION(gnupg_encrypt)
{
	zval *object = NULL;
	char *value = NULL;
	size_t value_len;
	char *userret = NULL;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_encrypt_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &value, &value_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!intern->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, value, value_len, 0))) {
		GNUPG_ERR("could no create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(intern->err = gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_encrypt(intern->ctx, intern->encryptkeys,
			GPGME_ENCRYPT_ALWAYS_TRUST, in, out))) {
		GNUPG_ERR("encrypt failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	result = gpgme_op_encrypt_result(intern->ctx);
	if (result->invalid_recipients) {
		GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	userret	= gpgme_data_release_and_get_mem(out, &ret_size);
	gpgme_data_release(in);
	RETVAL_STRINGL(userret, ret_size);
	free(userret);
	if (ret_size < 1) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto string gnupg_encrypt_sign(string text)
 * encrypts and signs the given text with the keys, which weres set
 * with setencryptkey and setsignkey before, and returns the encrypted text
 */
PHP_FUNCTION(gnupg_encryptsign)
{
	zval *object = NULL;
	char *value = NULL;
	size_t value_len;
	char *userret = NULL;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_encrypt_result_t result;
	gpgme_sign_result_t sign_result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &value, &value_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	if (!intern->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	gpgme_set_passphrase_cb(intern->ctx, passphrase_cb, intern);
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem (&in, value, value_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_encrypt_sign(intern->ctx, intern->encryptkeys,
			GPGME_ENCRYPT_ALWAYS_TRUST, in, out))) {
		if (!intern->errortxt) {
			GNUPG_ERR("encrypt-sign failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}

	result = gpgme_op_encrypt_result (intern->ctx);
	if (result->invalid_recipients) {
		GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}

	sign_result = gpgme_op_sign_result (intern->ctx);
	if (sign_result->invalid_signers) {
		GNUPG_ERR("invalid signers found");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	if (!sign_result->signatures) {
		GNUPG_ERR("could not find a signature");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}

	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	gpgme_data_release(in);
	RETVAL_STRINGL(userret, ret_size);
	free (userret);
	if (ret_size < 1) {
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto array gnupg_verify(string text, string signature [, string &plaintext])
 * verifies the given clearsigned text and returns information about the result in an array
 */
PHP_FUNCTION(gnupg_verify)
{
	zval *object = NULL;
	gpgme_data_t gpgme_text, gpgme_sig;
	gpgme_verify_result_t gpgme_result;
	/* text without the signature, if its a detached one, or the text incl the sig */
	zval *signed_text = NULL;
	/* signature, if its a detached one */
	zval *signature = NULL;
	/* signed_text without the signature if its not a detached sig */
	zval *plain_text = NULL;
	char *gpg_plain;
	size_t gpg_plain_len;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "zz|z",
				&signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Ozz|z",
				&object, gnupg_class_entry, &signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (Z_TYPE_P(signature) == IS_STRING) { /* detached signature */
		/* setup signature-databuffer for gpgme */
		if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(
				&gpgme_sig, Z_STRVAL_P(signature), Z_STRLEN_P(signature), 0))) {
			GNUPG_ERR("could not create signature-databuffer");
			return;
		}
		/* and the text */
		if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(
				&gpgme_text, Z_STRVAL_P(signed_text), Z_STRLEN_P(signed_text), 0))) {
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
		/* now verify sig + text */
		if (!PHP_GNUPG_DO(gpgme_op_verify(intern->ctx, gpgme_sig, gpgme_text, NULL))) {
			GNUPG_ERR("verify failed");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
	} else { /* clearsign or normal signature */
		if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(
				&gpgme_sig, Z_STRVAL_P(signed_text), Z_STRLEN_P(signed_text), 0))) {
			GNUPG_ERR("could not create signature-databuffer");
			return;
		}
		/* set a NULL databuffer for gpgme */
		if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&gpgme_text, NULL, 0, 0))) {
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
		/* and verify the 'signature' */
		if (!PHP_GNUPG_DO(gpgme_op_verify(intern->ctx, gpgme_sig, NULL, gpgme_text))) {
			GNUPG_ERR("verify failed");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
	}
	/* now get the result */
	gpgme_result = gpgme_op_verify_result(intern->ctx);
	if (!gpgme_result->signatures) {
		GNUPG_ERR("no signature found");
	} else {
		/* fetch all signatures in an array */
		gnupg_fetchsignatures(gpgme_result->signatures, return_value);
		/* get a 'plain' version of the text without a signature */
		gpg_plain = gpgme_data_release_and_get_mem(gpgme_text, &gpg_plain_len);
		if (gpg_plain && gpg_plain_len > 0 && plain_text) {
			ZVAL_DEREF(plain_text);
			ZVAL_STRINGL(plain_text, gpg_plain, gpg_plain_len);
		}
		free(gpg_plain);
	}
	gpgme_data_release(gpgme_sig);
}
/* }}} */

/* {{{ proto string gnupg_decrypt(string enctext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decrypt)
{
	zval *object = NULL;
	char *enctxt;
	size_t enctxt_len;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_decrypt_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&enctxt, &enctxt_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &enctxt, &enctxt_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	gpgme_set_passphrase_cb(intern->ctx, passphrase_decrypt_cb, intern);

	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if ((intern->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_decrypt(intern->ctx, in, out))) {
		if (!intern->errortxt) {
			GNUPG_ERR("decrypt failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	result = gpgme_op_decrypt_result(intern->ctx);
	if (result->unsupported_algorithm) {
		GNUPG_ERR("unsupported algorithm");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);

	gpgme_data_release(in);
	if (userret != NULL) {
		RETVAL_STRINGL(userret, ret_size);
		free(userret);
	} else {
		RETVAL_EMPTY_STRING();
	}
}
/* }}} */

/* {{{ proto string gnupg_messagekeys(string enctext)
 * returns the recipient keyids and their status for the given enctext
 */
PHP_FUNCTION(gnupg_messagekeys)
{
	char *enctxt;
	phpc_str_size_t	enctxt_len;
	gpgme_data_t in, out;
	gpgme_decrypt_result_t result;
	gpgme_recipient_t recipient;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&enctxt, &enctxt_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &enctxt, &enctxt_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		RETURN_FALSE;
	}

	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		RETURN_FALSE;
	}

	PHP_GNUPG_DO(gpgme_op_decrypt(PHPC_THIS->ctx, in, out));

	result = gpgme_op_decrypt_result(PHPC_THIS->ctx);

	gpgme_data_release(in);
	gpgme_data_release(out);

	if (!result->recipients) {
		GNUPG_ERR("invalid enctext");
		RETURN_FALSE;
	}

	PHPC_ARRAY_INIT(return_value);

	recipient = result->recipients;

	while (recipient) {
		PHPC_ARRAY_ADD_ASSOC_BOOL(return_value, recipient->keyid, !recipient->status);

		recipient = recipient->next;
	}
}

/* }}} */

/* {{{ proto string gnupg_decryptverify(string enctext, string &plaintext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decryptverify)
{
	zval *object = NULL;
	char *enctxt;
	size_t enctxt_len;
	zval *plaintext;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_decrypt_result_t decrypt_result;
	gpgme_verify_result_t verify_result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "sz",
				&enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Osz",
				&object, gnupg_class_entry, &enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	ZVAL_DEREF(plaintext);

	gpgme_set_passphrase_cb(intern->ctx, passphrase_decrypt_cb, intern);

	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_decrypt_verify(intern->ctx, in, out))) {
		if (!intern->errortxt) {
			GNUPG_ERR("decrypt-verify failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	ZVAL_STRINGL(plaintext, userret, ret_size);
	free(userret);
	decrypt_result = gpgme_op_decrypt_result(intern->ctx);
	if (decrypt_result->unsupported_algorithm) {
		GNUPG_ERR("unsupported algorithm");
		gpgme_data_release(in);
		return;
	}
	verify_result = gpgme_op_verify_result(intern->ctx);
	if (!verify_result->signatures) {
		GNUPG_ERR("no signature found");
		gpgme_data_release(in);
		return;
	}
	gnupg_fetchsignatures(verify_result->signatures, return_value);
	gpgme_data_release(in);
}
/* }}} */

/* {{{ proto string gnupg_export(string pattern)
 * exports the first public key which matches against the given pattern
 */
PHP_FUNCTION(gnupg_export)
{
	zval *object = NULL;
	char *searchkey = NULL;
	size_t searchkey_len;
	char *userret;
	size_t ret_size;
	gpgme_data_t  out;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&searchkey, &searchkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_export(intern->ctx, searchkey, 0, out))) {
		GNUPG_ERR("export failed");
		gpgme_data_release(out);
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	if (ret_size < 1) {
		RETVAL_FALSE;
	} else {
		RETVAL_STRINGL(userret, ret_size);
	}
	free(userret);
}
/* }}} */

/* {{{ proto array gnupg_import(string key)
 * imports the given key and returns a status-array
 */
PHP_FUNCTION(gnupg_import)
{
	zval *object = NULL;
	char *importkey = NULL;
	size_t importkey_len;
	gpgme_data_t in;
	gpgme_import_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&importkey, &importkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &importkey, &importkey_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, importkey, importkey_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_import(intern->ctx, in))) {
		GNUPG_ERR("import failed");
		gpgme_data_release(in);
		return;
	}
	gpgme_data_release(in);
	result = gpgme_op_import_result(intern->ctx);

	if (!result || !result->imports || result->imports->result != GPG_ERR_NO_ERROR) {
		RETURN_FALSE;
	}
	array_init(return_value);
	add_assoc_long(return_value, "imported", result->imported);
	add_assoc_long(return_value, "unchanged", result->unchanged);
	add_assoc_long(return_value, "newuserids", result->new_user_ids);
	add_assoc_long(return_value, "newsubkeys", result->new_sub_keys);
	add_assoc_long(return_value, "secretimported", result->secret_imported);
	add_assoc_long(return_value, "secretunchanged", result->secret_unchanged);
	add_assoc_long(return_value, "newsignatures", result->new_signatures);
	add_assoc_long(return_value, "skippedkeys", result->skipped_new_keys);
	if (result->imports && result->imports->fpr) {
		add_assoc_string(return_value, "fingerprint", result->imports->fpr);
	}
}
/* }}} */

#ifndef GPGME_DELETE_ALLOW_SECRET
#define GPGME_DELETE_ALLOW_SECRET 1
#endif

/* {{{ proto book gnupg_deletekey(string key)
 *	deletes a key from the keyring
 */
PHP_FUNCTION(gnupg_deletekey)
{
	zval *object = NULL;
	char *key;
	size_t key_len;
	zend_bool allow_secret = 0;
	gpgme_key_t	gpgme_key;
	unsigned int flags = 0;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s|b",
				&key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os|b",
				&object, gnupg_class_entry, &key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(intern->ctx, key, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if (allow_secret) {
		flags = GPGME_DELETE_ALLOW_SECRET;
	}
	if (!PHP_GNUPG_DO(gpgme_op_delete(intern->ctx, gpgme_key, flags))) {
		GNUPG_ERR("delete failed");
		RETVAL_FALSE;
	} else {
		RETVAL_TRUE;
	}
	gpgme_key_unref(gpgme_key);
}
/* }}} */

#if GPGME_VERSION_NUMBER < 0x020000  /* GPGME < 2.0.0 */

/* {{{ proto array gnupg_gettrustlist(string pattern)
* searching for trust items which match PATTERN
*/
PHP_FUNCTION(gnupg_gettrustlist)
{
	zval *object = NULL;
	char *pattern;
	size_t pattern_len;
	zval sub_arr;
	gpgme_trust_item_t item;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&pattern, &pattern_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &pattern, &pattern_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!PHP_GNUPG_DO(gpgme_op_trustlist_start(intern->ctx, pattern, 0))) {
		GNUPG_ERR("could not start trustlist");
		return;
	}
	array_init(return_value);
	while (PHP_GNUPG_DO(gpgme_op_trustlist_next(intern->ctx, &item))) {
		array_init(&sub_arr);

		add_assoc_long(&sub_arr, "level", item->level);
		add_assoc_long(&sub_arr, "type", item->type);
		add_assoc_string(&sub_arr, "keyid", item->keyid);
		add_assoc_string(&sub_arr, "ownertrust", item->owner_trust);
		add_assoc_string(&sub_arr, "validity", item->validity);
		add_assoc_string(&sub_arr, "name", item->name);
		gpgme_trust_item_unref(item);
		add_next_index_zval(return_value, &sub_arr);
	}
}
/* }}} */

#endif /* GPGME < 2.0.0 */

/* {{{ proto array gnupg_listsignatures(string keyid) */
PHP_FUNCTION(gnupg_listsignatures)
{
	zval *object = NULL;
	char	*keyid;
	size_t keyid_len;

	zval sub_arr;
	zval sig_arr;

	gpgme_key_t		gpgme_key;
	gpgme_user_id_t	gpgme_userid;
	gpgme_key_sig_t	gpgme_signature;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "s",
				&keyid, &keyid_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS(), "Os",
				&object, gnupg_class_entry, &keyid, &keyid_len) == FAILURE) {
			return;
		}
		intern = Z_GNUPG_P(object);
	}
	if (!PHP_GNUPG_DO(gpgme_set_keylist_mode(intern->ctx, GPGME_KEYLIST_MODE_SIGS))) {
		GNUPG_ERR("could not switch to sigmode");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_get_key(intern->ctx, keyid, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed. given key not unique?");
		return;
	}
	if (!gpgme_key->uids) {
		GNUPG_ERR("no uids found");
		gpgme_key_unref(gpgme_key);
		return;
	}
	array_init(return_value);
	gpgme_userid = gpgme_key->uids;
	while (gpgme_userid) {
		array_init(&sub_arr);
		gpgme_signature = gpgme_userid->signatures;
		while (gpgme_signature) {
			array_init(&sig_arr);

			add_assoc_string(&sig_arr, "uid", gpgme_signature->uid);
			add_assoc_string(&sig_arr, "name", gpgme_signature->name);
			add_assoc_string(&sig_arr, "email", gpgme_signature->email);
			add_assoc_string(&sig_arr, "comment", gpgme_signature->comment);
			add_assoc_long(&sig_arr, "expires", gpgme_signature->expires);
			add_assoc_bool(&sig_arr, "revoked", gpgme_signature->revoked);
			add_assoc_bool(&sig_arr, "expired", gpgme_signature->expired);
			add_assoc_bool(&sig_arr, "invalid", gpgme_signature->invalid);
			add_assoc_long(&sig_arr, "timestamp", gpgme_signature->timestamp);
			add_assoc_zval(&sub_arr, gpgme_signature->keyid, &sig_arr);
			gpgme_signature = gpgme_signature->next;
		}
		add_assoc_zval(return_value, gpgme_userid->uid, &sub_arr);
		gpgme_userid = gpgme_userid->next;
	}
	gpgme_key_unref(gpgme_key);
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
