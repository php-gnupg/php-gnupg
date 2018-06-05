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
#include "phpc/phpc.h"

#include "php_gnupg_keylistiterator.h"

static int le_gnupg;

static zend_class_entry *gnupg_class_entry;

PHPC_OBJ_DEFINE_HANDLER_VAR(gnupg);

/* {{{ GNUPG_GETOBJ */
#define GNUPG_GETOBJ() \
	zval *this = getThis(); \
	PHPC_THIS_DECLARE(gnupg) = NULL; \
	zval *res; \
	do { \
		if (this) { \
			PHPC_THIS_FETCH_FROM_ZVAL(gnupg, this); \
			if (!PHPC_THIS) { \
				php_error_docref(NULL TSRMLS_CC, E_WARNING, \
					"Invalid or unitialized gnupg object"); \
				RETURN_FALSE; \
			} \
		} \
	} while (0)
/* }}} */

#define GNUPG_RES_FETCH() \
	PHPC_THIS = (PHPC_OBJ_STRUCT_NAME(gnupg) *) \
			PHPC_RES_FETCH(res, "ctx", le_gnupg)

/* {{{ GNUPG_ERR */
#define GNUPG_ERR(error) \
	if (PHPC_THIS) { \
		switch (PHPC_THIS->errormode) { \
			case 1: \
				php_error_docref(NULL TSRMLS_CC, E_WARNING, \
					(char*)error); \
				break; \
			case 2: \
				zend_throw_exception(\
					zend_exception_get_default(TSRMLS_C), \
					(char*) error, \
					0 TSRMLS_CC \
				); \
				break; \
			default: \
				PHPC_THIS->errortxt = (char*)error; \
		} \
	} else { \
		php_error_docref(NULL TSRMLS_CC, E_WARNING, (char*)error); \
	} \
	do { \
		if (return_value) { \
			RETVAL_FALSE; \
		} \
	} while (0)
/* }}} */

/* {{{ php_gnupg_free_encryptkeys */
static void php_gnupg_free_encryptkeys(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	if (PHPC_THIS) {
		int idx;
		/* loop through all encryptkeys and unref them in the gpgme-lib */
		for (idx = 0; idx < PHPC_THIS->encrypt_size; idx++) {
			gpgme_key_unref(PHPC_THIS->encryptkeys[idx]);
		}
		if (PHPC_THIS->encryptkeys != NULL) {
			efree(PHPC_THIS->encryptkeys);
		}
		PHPC_THIS->encryptkeys = NULL;
		PHPC_THIS->encrypt_size = 0;
	}
}
/* }}} */

/* {{{ php_gnupg_this_free */
static void php_gnupg_this_free(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	if (PHPC_THIS) {
		if (PHPC_THIS->ctx) {
			/* clear all signers from the gpgme-lib and finally release it */
			gpgme_signers_clear(PHPC_THIS->ctx);
			gpgme_release(PHPC_THIS->ctx);
			PHPC_THIS->ctx = NULL;
		}
		/* basic cleanup */
		php_gnupg_free_encryptkeys(PHPC_THIS TSRMLS_CC);
		zend_hash_destroy(PHPC_THIS->signkeys);
		FREE_HASHTABLE(PHPC_THIS->signkeys);
		zend_hash_destroy(PHPC_THIS->decryptkeys);
		FREE_HASHTABLE(PHPC_THIS->decryptkeys);
	}
}
/* }}} */

/* {{{ php_gnupg_this_init */
static void php_gnupg_this_init(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	/* init the gpgme-lib and set the default values */
	gpgme_ctx_t	ctx;
	gpgme_error_t err;

	err = gpgme_new(&ctx);
	PHPC_THIS->ctx = ctx;
	PHPC_THIS->encryptkeys = NULL;
	PHPC_THIS->encrypt_size = 0;
	PHPC_THIS->signmode = GPGME_SIG_MODE_CLEAR;
	PHPC_THIS->err = err;
	PHPC_THIS->errortxt = NULL;
	PHPC_THIS->errormode = 3;
	ALLOC_HASHTABLE(PHPC_THIS->signkeys);
	zend_hash_init(PHPC_THIS->signkeys, 0, NULL, NULL, 0);
	ALLOC_HASHTABLE(PHPC_THIS->decryptkeys);
	zend_hash_init(PHPC_THIS->decryptkeys, 0, NULL, NULL, 0);
}
/* }}} */

/* set GNUPG_PATH to NULL if not defined */
#ifndef GNUPG_PATH
#define GNUPG_PATH NULL
#endif

/* {{{ php_gnupg_this_make */
static void php_gnupg_this_make(PHPC_THIS_DECLARE(gnupg), zval *options TSRMLS_DC)
{
	if (PHPC_THIS->err == GPG_ERR_NO_ERROR) {
		char *file_name = GNUPG_PATH;
		char *home_dir = NULL;
		phpc_val *ppv_file_name, *ppv_home_dir;
		gpgme_ctx_t	ctx = PHPC_THIS->ctx;

		if (options && PHPC_HASH_CSTR_FIND_IN_COND(
				Z_ARRVAL_P(options), "file_name", ppv_file_name)) {
			file_name = PHPC_STRVAL_P(ppv_file_name);
		}
		if (options && PHPC_HASH_CSTR_FIND_IN_COND(
				Z_ARRVAL_P(options), "home_dir", ppv_home_dir)) {
			home_dir = PHPC_STRVAL_P(ppv_home_dir);
		}

		if (file_name != NULL || home_dir != NULL) {
			gpgme_ctx_set_engine_info(
					ctx, GPGME_PROTOCOL_OpenPGP, file_name, home_dir);
		}
		gpgme_set_armor(ctx, 1);
		gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);
	}
}
/* }}} */

/* {{{ php_gnupg_res_dtor */
static void php_gnupg_res_dtor(phpc_res_entry_t *rsrc TSRMLS_DC) /* {{{ */
{
	PHPC_THIS_DECLARE(gnupg) = rsrc->ptr;
	php_gnupg_this_free(PHPC_THIS TSRMLS_CC);
	efree(PHPC_THIS);
}
/* }}} */

/* {{{ free gnupg */
PHPC_OBJ_HANDLER_FREE(gnupg)
{
	PHPC_OBJ_HANDLER_FREE_INIT(gnupg);

	php_gnupg_this_free(PHPC_THIS TSRMLS_CC);

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}

/* {{{ create_ex gnupg */
PHPC_OBJ_HANDLER_CREATE_EX(gnupg)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(gnupg);

	php_gnupg_this_init(PHPC_THIS TSRMLS_CC);

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(gnupg);
}

/* {{{ create gnupg */
PHPC_OBJ_HANDLER_CREATE(gnupg)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(gnupg);
}

/* {{{ arginfo for gnupg __construct and gnupg_init */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_init, 0, 0, 0)
	ZEND_ARG_INFO(0, options)
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
	ZEND_ARG_INFO(0, kye)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with key parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_keyid_method, 0)
	ZEND_ARG_INFO(0, kyeid)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with pattern parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_pattern_method, 0)
	ZEND_ARG_INFO(0, pattern)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg methods with errmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_errmode_method, 0)
	ZEND_ARG_INFO(0, errnmode)
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
phpc_function_entry gnupg_methods[] = {
	PHP_ME(gnupg, __construct, arginfo_gnupg_init, ZEND_ACC_CTOR|ZEND_ACC_PUBLIC)
	PHP_GNUPG_FALIAS(keyinfo,           arginfo_gnupg_pattern_method)
	PHP_GNUPG_FALIAS(verify,            arginfo_gnupg_verify_method)
	PHP_GNUPG_FALIAS(getengineinfo,     NULL)
	PHP_GNUPG_FALIAS(geterror,          NULL)
	PHP_GNUPG_FALIAS(clearsignkeys,     NULL)
	PHP_GNUPG_FALIAS(clearencryptkeys,  NULL)
	PHP_GNUPG_FALIAS(cleardecryptkeys,  NULL)
	PHP_GNUPG_FALIAS(setarmor,          arginfo_gnupg_armor_method)
	PHP_GNUPG_FALIAS(encrypt,           arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(decrypt,           arginfo_gnupg_enctext_method)
	PHP_GNUPG_FALIAS(export,            arginfo_gnupg_pattern_method)
	PHP_GNUPG_FALIAS(import,            arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(getprotocol,       NULL)
	PHP_GNUPG_FALIAS(setsignmode,       arginfo_gnupg_signmode_method)
	PHP_GNUPG_FALIAS(sign,              arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(encryptsign,       arginfo_gnupg_text_method)
	PHP_GNUPG_FALIAS(decryptverify,     arginfo_gnupg_decryptverify_method)
	PHP_GNUPG_FALIAS(addsignkey,        arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(addencryptkey,     arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(adddecryptkey,     arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(deletekey,         arginfo_gnupg_key_method)
	PHP_GNUPG_FALIAS(gettrustlist,      arginfo_gnupg_pattern_method)
	PHP_GNUPG_FALIAS(listsignatures,    arginfo_gnupg_keyid_method)
	PHP_GNUPG_FALIAS(seterrormode,      arginfo_gnupg_errmode_method)
	PHPC_FE_END
};
/* }}} */

/* {{{ arginfo for gnupg function with no parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_void_function, 0)
	ZEND_ARG_INFO(0, res)
ZEND_END_ARG_INFO()
/* }}} */


/* {{{ arginfo for gnupg function with armor parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_armor_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, armor)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with enctext parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_enctext_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, enctext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with text parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_text_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, text)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with key parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_key_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, kye)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with key parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_keyid_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, kyeid)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with pattern parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_pattern_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, pattern)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with errmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_errmode_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, errnmode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo for gnupg functions with signmode parameter */
ZEND_BEGIN_ARG_INFO(arginfo_gnupg_signmode_function, 0)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, signmode)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_verify_function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_verify_function, 0, 0, 3)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_decryptverify_function */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_decryptverify_function, 0, 0, 3)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, enctext)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ functionlist gnupg */
static zend_function_entry gnupg_functions[] = {
	PHP_FE(gnupg_init,				arginfo_gnupg_void_function)
	PHP_FE(gnupg_keyinfo,			arginfo_gnupg_pattern_function)
	PHP_FE(gnupg_sign,				arginfo_gnupg_text_function)
	PHP_FE(gnupg_verify,			arginfo_gnupg_verify_function)
	PHP_FE(gnupg_clearsignkeys,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_clearencryptkeys,	arginfo_gnupg_void_function)
	PHP_FE(gnupg_cleardecryptkeys,	arginfo_gnupg_void_function)
	PHP_FE(gnupg_setarmor,			arginfo_gnupg_armor_function)
	PHP_FE(gnupg_encrypt,			arginfo_gnupg_text_function)
	PHP_FE(gnupg_decrypt,			arginfo_gnupg_enctext_function)
	PHP_FE(gnupg_export,			arginfo_gnupg_pattern_function)
	PHP_FE(gnupg_import,			arginfo_gnupg_key_function)
	PHP_FE(gnupg_getengineinfo,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_getprotocol,		arginfo_gnupg_void_function)
	PHP_FE(gnupg_setsignmode,		arginfo_gnupg_signmode_function)
	PHP_FE(gnupg_encryptsign,		arginfo_gnupg_text_function)
	PHP_FE(gnupg_decryptverify,		arginfo_gnupg_decryptverify_function)
	PHP_FE(gnupg_geterror,			arginfo_gnupg_void_function)
	PHP_FE(gnupg_addsignkey,		arginfo_gnupg_key_function)
	PHP_FE(gnupg_addencryptkey,		arginfo_gnupg_key_function)
	PHP_FE(gnupg_adddecryptkey,		arginfo_gnupg_key_function)
	PHP_FE(gnupg_deletekey,			arginfo_gnupg_key_function)
	PHP_FE(gnupg_gettrustlist,		arginfo_gnupg_pattern_function)
	PHP_FE(gnupg_listsignatures,	arginfo_gnupg_keyid_function)
	PHP_FE(gnupg_seterrormode,		arginfo_gnupg_errmode_function)
	PHPC_FE_END
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

#define PHP_GNUPG_DO(_action) ((PHPC_THIS->err = _action) == GPG_ERR_NO_ERROR)

#define PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL_EX(_g_arr, _g_name, _g_struct, _g_key) \
	PHPC_ARRAY_ADD_ASSOC_BOOL(\
		PHPC_VAL_CAST_TO_PZVAL(_g_arr), #_g_name, _g_struct->_g_key)
#define PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(_g_arr, _g_name, _g_struct) \
	PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL_EX(_g_arr, _g_name, _g_struct, _g_name)

#define PHP_GNUPG_ARRAY_ADD_ASSOC_LONG_EX(_g_arr, _g_name, _g_struct, _g_key) \
	PHPC_ARRAY_ADD_ASSOC_LONG(\
		PHPC_VAL_CAST_TO_PZVAL(_g_arr), #_g_name, _g_struct->_g_key)
#define PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(_g_arr, _g_name, _g_struct) \
	PHP_GNUPG_ARRAY_ADD_ASSOC_LONG_EX(_g_arr, _g_name, _g_struct, _g_name)

#define PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR_EX(_g_arr, _g_name, _g_struct, _g_key) \
	PHPC_ARRAY_ADD_ASSOC_CSTR(\
		PHPC_VAL_CAST_TO_PZVAL(_g_arr), #_g_name, _g_struct->_g_key)
#define PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(_g_arr, _g_name, _g_struct) \
	PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR_EX(_g_arr, _g_name, _g_struct, _g_name)

#define PHP_GNUPG_SET_CLASS_CONST(_name, _value) \
	zend_declare_class_constant_long(gnupg_class_entry, \
		_name, sizeof(_name) - 1, _value TSRMLS_CC)

#define PHP_GNUPG_REG_CONST(_name, _value) \
	REGISTER_LONG_CONSTANT(_name,  _value, CONST_CS | CONST_PERSISTENT);

#define PHP_GNUPG_REG_CONST_STR(_name, _value) \
	REGISTER_STRING_CONSTANT(_name,  _value, CONST_CS | CONST_PERSISTENT);

#define PHP_GNUPG_VERSION_BUF_SIZE 64

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(gnupg)
{
	zend_class_entry ce;
	char php_gpgme_version[PHP_GNUPG_VERSION_BUF_SIZE];

	/* init class */
	INIT_CLASS_ENTRY(ce, "gnupg", gnupg_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, gnupg);
	gnupg_class_entry = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(gnupg);
	PHPC_OBJ_SET_HANDLER_OFFSET(gnupg);
	PHPC_OBJ_SET_HANDLER_FREE(gnupg);

	/* register resource */
	le_gnupg = zend_register_list_destructors_ex(
				php_gnupg_res_dtor, NULL, "ctx", module_number);

	if (SUCCESS != gnupg_keylistiterator_init()) {
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
#if GPGME_VERSION_NUMBER >= 0x010300  /* GPGME >= 1.3.0 */
	PHP_GNUPG_SET_CLASS_CONST("PK_ECDSA",           GPGME_PK_ECDSA);
	PHP_GNUPG_SET_CLASS_CONST("PK_ECDH",            GPGME_PK_ECDH);
#endif /* gpgme >= 1.3.0 */	
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
#if GPGME_VERSION_NUMBER >= 0x010300  /* GPGME >= 1.3.0 */
	PHP_GNUPG_REG_CONST("GNUPG_PK_ECDSA",           GPGME_PK_ECDSA);
	PHP_GNUPG_REG_CONST("GNUPG_PK_ECDH",            GPGME_PK_ECDH);
#endif /* gpgme >= 1.3.0 */	
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
	PHPC_THIS_DECLARE(gnupg) = hook;
	TSRMLS_FETCH();

	if (last_was_bad) {
		GNUPG_ERR("Incorrent passphrase");
		return 1;
	}
	for (idx=0; idx < 16; idx++) {
		uid[idx] = uid_hint[idx];
	}
	uid[16] = '\0';
	if (!PHPC_HASH_CSTR_FIND_PTR_IN_COND(
				PHPC_THIS->signkeys, (char *)uid, passphrase)) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}
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
	PHPC_THIS_DECLARE(gnupg) = hook;
	TSRMLS_FETCH();

	if (last_was_bad) {
		GNUPG_ERR("Incorrent passphrase");
		return 1;
	}
	for (idx=0; idx < 16; idx++) {
		uid[idx] = uid_hint[idx];
	}
	uid[16] = '\0';
	if (!PHPC_HASH_CSTR_FIND_PTR_IN_COND(
				PHPC_THIS->decryptkeys, (char *)uid, passphrase)) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}
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

/* {{{ gnupg_fetchsignatures */
int gnupg_fetchsignatures(gpgme_signature_t gpgme_signatures, zval *main_arr)
{
	phpc_val sig_arr;

	PHPC_ARRAY_INIT(main_arr);
	while (gpgme_signatures) {
		PHPC_VAL_MAKE(sig_arr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(sig_arr));
		PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR_EX(sig_arr, fingerprint, gpgme_signatures, fpr);
		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, validity, gpgme_signatures);
		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, timestamp, gpgme_signatures);
		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, status, gpgme_signatures);
		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, summary, gpgme_signatures);

		PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(
			main_arr,
			PHPC_VAL_CAST_TO_PZVAL(sig_arr)
		);

		gpgme_signatures = gpgme_signatures->next;
	}
	return 1;
}
/* }}} */

/* {{{ proto gnupg::__construct(array options = NULL)
 * inits gnupg and returns a resource
*/
PHP_METHOD(gnupg, __construct)
{
	zval *options = NULL;
	PHPC_THIS_DECLARE(gnupg);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|a",
			&options) == FAILURE) {
		return;
	}

	PHPC_THIS_FETCH(gnupg);
	php_gnupg_this_make(PHPC_THIS, options TSRMLS_CC);
}
/* }}} */

/* {{{ proto resource gnupg_init(array options = NULL)
 * inits gnupg and returns a resource
*/
PHP_FUNCTION(gnupg_init)
{
	zval *options = NULL;
	PHPC_THIS_DECLARE(gnupg);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|a",
			&options) == FAILURE) {
		return;
	}

	PHPC_THIS = emalloc(sizeof(PHPC_OBJ_STRUCT_NAME(gnupg)));
	php_gnupg_this_init(PHPC_THIS TSRMLS_CC);
	php_gnupg_this_make(PHPC_THIS, options TSRMLS_CC);
	PHPC_RES_RETURN(PHPC_RES_REGISTER(PHPC_THIS, le_gnupg));
}
/* }}} */

/* {{{ proto bool gnupg_setarmor(int armor)
 * turn on/off armor mode
 * 0 = off
 * >0 = on
 * */
PHP_FUNCTION(gnupg_setarmor)
{
	phpc_long_t armor;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
				&armor) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl",
				&res, &armor) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (armor > 1) {
		armor = 1; /*just to make sure */
	}

	gpgme_set_armor(PHPC_THIS->ctx, armor);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_seterrormode(int errormde) */
PHP_FUNCTION(gnupg_seterrormode)
{
	phpc_long_t errormode;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
				&errormode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl",
				 &res, &errormode) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	switch (errormode) {
		case 1:		/* warning */
		case 3:		/* silent */
			PHPC_THIS->errormode = errormode;
			break;
		case 2:		/* exception */
			PHPC_THIS->errormode = errormode;
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
	phpc_long_t signmode;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
				&signmode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl",
				&res, &signmode) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	switch (signmode) {
		case GPGME_SIG_MODE_NORMAL:
		case GPGME_SIG_MODE_DETACH:
		case GPGME_SIG_MODE_CLEAR:
			PHPC_THIS->signmode = signmode;
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
	gpgme_engine_info_t info;
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	info = gpgme_ctx_get_engine_info(PHPC_THIS->ctx);

	PHPC_ARRAY_INIT(return_value);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "protocol", info->protocol);
	PHPC_ARRAY_ADD_ASSOC_CSTR(return_value, "file_name", info->file_name);
	PHPC_ARRAY_ADD_ASSOC_CSTR(return_value, "home_dir", info->home_dir ? info->home_dir : "");
}
/* }}} */

/* {{{ proto string gnupg_geterror(void)
 * returns the last errormessage
 */
PHP_FUNCTION(gnupg_geterror)
{
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHPC_THIS->errortxt) {
		RETURN_FALSE;
	} else {
		PHPC_CSTR_RETURN(PHPC_THIS->errortxt);
	}
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

/* {{{ proto array gnupg_keyinfo(string pattern)
 * returns an array with informations about all keys, that matches
 * the given pattern
 */
PHP_FUNCTION(gnupg_keyinfo)
{
	char *searchkey = NULL;
	phpc_str_size_t searchkey_len;
	phpc_val subarr, userid, userids, subkey, subkeys;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;
	gpgme_user_id_t gpgme_userid;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&searchkey, &searchkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	PHPC_THIS->err = gpgme_op_keylist_start(PHPC_THIS->ctx, searchkey, 0);
	if ((PHPC_THIS->err) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not init keylist");
		return;
	}

	PHPC_ARRAY_INIT(return_value);

	while (PHP_GNUPG_DO(gpgme_op_keylist_next(PHPC_THIS->ctx, &gpgme_key))) {
		PHPC_VAL_MAKE(subarr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subarr));

		PHPC_VAL_MAKE(subkeys);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subkeys));

		PHPC_VAL_MAKE(userids);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(userids));

		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subarr, disabled, gpgme_key);
		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subarr, expired, gpgme_key);
		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subarr, revoked, gpgme_key);
		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL_EX(subarr, is_secret, gpgme_key, secret);
		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subarr, can_sign, gpgme_key);
		PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subarr, can_encrypt, gpgme_key);

		gpgme_userid = gpgme_key->uids;
		while (gpgme_userid) {
			PHPC_VAL_MAKE(userid);
			PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(userid));

			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(userid, name, gpgme_userid);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(userid, comment, gpgme_userid);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(userid, email, gpgme_userid);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(userid, uid, gpgme_userid);

			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(userid, revoked, gpgme_userid);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(userid, invalid, gpgme_userid);

			PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(
					PHPC_VAL_CAST_TO_PZVAL(userids),
					PHPC_VAL_CAST_TO_PZVAL(userid));
			gpgme_userid = gpgme_userid->next;
		}

		PHPC_ARRAY_ADD_ASSOC_ZVAL(
				PHPC_VAL_CAST_TO_PZVAL(subarr),
				"uids",
				PHPC_VAL_CAST_TO_PZVAL(userids));

		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			PHPC_VAL_MAKE(subkey);
			PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subkey));

			if (gpgme_subkey->fpr) {
				PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR_EX(subkey, fingerprint, gpgme_subkey, fpr);
			}

			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(subkey, keyid, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(subkey, timestamp, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(subkey, expires, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL_EX(subkey, is_secret, gpgme_subkey, secret);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, invalid, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, can_encrypt, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, can_sign, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, disabled, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, expired, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, revoked, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, can_certify, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, can_authenticate, gpgme_subkey);
#if GPGME_VERSION_NUMBER >= 0x010100  /* GPGME >= 1.1.0 */
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, is_qualified, gpgme_subkey);
#endif /* gpgme >= 1.1.0 */
#if GPGME_VERSION_NUMBER >= 0x010900  /* GPGME >= 1.9.0 */
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, is_de_vs, gpgme_subkey);
#endif /* gpgme >= 1.9.0 */
			/*
				https://github.com/gpg/gpgme/blob/f7700a016926f0d8e9cb3c0337837deb7fe01079/src/gpgme.h.in#L258
				https://github.com/gpg/gpgme/blob/f7700a016926f0d8e9cb3c0337837deb7fe01079/src/gpgme.c#L1196
				printf '0x%02x%02x%02x\n' 1 2 0
			*/
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(subkey, pubkey_algo, gpgme_subkey);
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(subkey, length, gpgme_subkey);
#if GPGME_VERSION_NUMBER >= 0x010700  /* GPGME >= 1.7.0 */
			if (gpgme_subkey->keygrip) {
				PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(subkey, keygrip, gpgme_subkey);
			}
#endif /* gpgme >= 1.7.0 */
#if GPGME_VERSION_NUMBER >= 0x010200  /* GPGME >= 1.2.0 */
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(subkey, is_cardkey, gpgme_subkey);
			if (gpgme_subkey->card_number) {
				PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(subkey, card_number, gpgme_subkey);
			}
#endif /* gpgme >= 1.2.0 */
			if (gpgme_subkey->curve) {
				PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(subkey, curve, gpgme_subkey);
			}

			PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(
					PHPC_VAL_CAST_TO_PZVAL(subkeys),
					PHPC_VAL_CAST_TO_PZVAL(subkey));
			gpgme_subkey = gpgme_subkey->next;
		}

		PHPC_ARRAY_ADD_ASSOC_ZVAL(
				PHPC_VAL_CAST_TO_PZVAL(subarr),
				"subkeys",
				PHPC_VAL_CAST_TO_PZVAL(subkeys));

		PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(
				return_value, PHPC_VAL_CAST_TO_PZVAL(subarr));
		gpgme_key_unref(gpgme_key);
	}
}
/* }}} */

/* {{{ proto bool gnupg_addsignkey(string key) */
PHP_FUNCTION(gnupg_addsignkey)
{
	char *key_id = NULL;
	phpc_str_size_t  key_id_len;
	char *passphrase = NULL;
	phpc_str_size_t	passphrase_len;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s",
				&key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|s",
				&res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 1))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if (passphrase) {
		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			if (gpgme_subkey->can_sign == 1) {
				PHPC_HASH_CSTR_ADD_PTR(PHPC_THIS->signkeys,
						gpgme_subkey->keyid, passphrase, passphrase_len + 1);
			}
			gpgme_subkey = gpgme_subkey->next;
		}
	}
	if (!PHP_GNUPG_DO(gpgme_signers_add(PHPC_THIS->ctx, gpgme_key))) {
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
	char *key_id = NULL;
	phpc_str_size_t key_id_len;
	char *passphrase = NULL;
	phpc_str_size_t passphrase_len;
	gpgme_key_t gpgme_key;
	gpgme_subkey_t gpgme_subkey;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
				&key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss",
				&res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHP_GNUPG_DO(gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 1))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	gpgme_subkey = gpgme_key->subkeys;
	while (gpgme_subkey) {
		if (gpgme_subkey->secret == 1) {
			PHPC_HASH_CSTR_ADD_PTR(
					PHPC_THIS->decryptkeys, gpgme_subkey->keyid,
					passphrase, passphrase_len + 1);
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
	char *key_id = NULL;
	phpc_str_size_t  key_id_len;
	gpgme_key_t gpgme_key = NULL;
	size_t encrypt_keys_size;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&key_id, &key_id_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &key_id, &key_id_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed");
		RETURN_FALSE;
	}

	encrypt_keys_size = sizeof(PHPC_THIS->encryptkeys) * (PHPC_THIS->encrypt_size + 2);
	if (PHPC_THIS->encryptkeys == NULL) {
		PHPC_THIS->encryptkeys = emalloc(encrypt_keys_size);
	} else {
		PHPC_THIS->encryptkeys = erealloc(PHPC_THIS->encryptkeys, encrypt_keys_size);
	}
	PHPC_THIS->encryptkeys[PHPC_THIS->encrypt_size] = gpgme_key;
	PHPC_THIS->encrypt_size++;
	PHPC_THIS->encryptkeys[PHPC_THIS->encrypt_size] = NULL;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_clearsignkeys)
{
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	gpgme_signers_clear(PHPC_THIS->ctx);
	zend_hash_clean(PHPC_THIS->signkeys);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearencryptkeys(void)
 * removes all keys which are set for encryption
 */
PHP_FUNCTION(gnupg_clearencryptkeys)
{
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	php_gnupg_free_encryptkeys(PHPC_THIS TSRMLS_CC);

	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_cleardecryptkeys)
{
	GNUPG_GETOBJ();

	if (!this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	zend_hash_clean(PHPC_THIS->decryptkeys);
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
	char *value = NULL;
	phpc_str_size_t value_len;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_sign_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_cb, PHPC_THIS);
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, value, value_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_sign(PHPC_THIS->ctx, in, out, PHPC_THIS->signmode))) {
		if (!PHPC_THIS->errortxt) {
			GNUPG_ERR("data signing failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	result = gpgme_op_sign_result(PHPC_THIS->ctx);
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
		PHPC_CSTRL_RETVAL(userret, ret_size);
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
	char *value = NULL;
	phpc_str_size_t value_len;
	char *userret = NULL;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_encrypt_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHPC_THIS->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, value, value_len, 0))) {
		GNUPG_ERR("could no create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(PHPC_THIS->err = gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_encrypt(PHPC_THIS->ctx, PHPC_THIS->encryptkeys,
			GPGME_ENCRYPT_ALWAYS_TRUST, in, out))) {
		GNUPG_ERR("encrypt failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	result = gpgme_op_encrypt_result(PHPC_THIS->ctx);
	if (result->invalid_recipients) {
		GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	userret	= gpgme_data_release_and_get_mem(out, &ret_size);
	gpgme_data_release(in);
	PHPC_CSTRL_RETVAL(userret, ret_size);
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
	char *value = NULL;
	phpc_str_size_t value_len;
	char *userret = NULL;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_encrypt_result_t result;
	gpgme_sign_result_t sign_result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHPC_THIS->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_cb, PHPC_THIS);
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem (&in, value, value_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_encrypt_sign(PHPC_THIS->ctx, PHPC_THIS->encryptkeys,
			GPGME_ENCRYPT_ALWAYS_TRUST, in, out))) {
		if (!PHPC_THIS->errortxt) {
			GNUPG_ERR("encrypt-sign failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}

	result = gpgme_op_encrypt_result (PHPC_THIS->ctx);
	if (result->invalid_recipients) {
		GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}

	sign_result = gpgme_op_sign_result (PHPC_THIS->ctx);
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
	PHPC_CSTRL_RETVAL(userret, ret_size);
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|z",
				&signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzz|z",
				&res, &signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
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
		if (!PHP_GNUPG_DO(gpgme_op_verify(PHPC_THIS->ctx, gpgme_sig, gpgme_text, NULL))) {
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
		if (!PHP_GNUPG_DO(gpgme_op_verify(PHPC_THIS->ctx, gpgme_sig, NULL, gpgme_text))) {
			GNUPG_ERR("verify failed");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
	}
	/* now get the result */
	gpgme_result = gpgme_op_verify_result(PHPC_THIS->ctx);
	if (!gpgme_result->signatures) {
		GNUPG_ERR("no signature found");
	} else {
		/* fetch all signatures in an array */
		gnupg_fetchsignatures(gpgme_result->signatures, return_value);
		/* get a 'plain' version of the text without a signature */
		gpg_plain = gpgme_data_release_and_get_mem(gpgme_text, &gpg_plain_len);
		if (gpg_plain && gpg_plain_len > 0 && plain_text) {
			PHPC_PZVAL_DEREF(plain_text);
			PHPC_PZVAL_CSTRL(plain_text, gpg_plain, gpg_plain_len);
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
	char *enctxt;
	phpc_str_size_t	enctxt_len;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_decrypt_result_t result;

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

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_decrypt_cb, PHPC_THIS);

	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_decrypt(PHPC_THIS->ctx, in, out))) {
		if (!PHPC_THIS->errortxt) {
			GNUPG_ERR("decrypt failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	result = gpgme_op_decrypt_result(PHPC_THIS->ctx);
	if (result->unsupported_algorithm) {
		GNUPG_ERR("unsupported algorithm");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	gpgme_data_release(in);
	PHPC_CSTRL_RETVAL(userret, ret_size);
	free(userret);
	if (ret_size < 1) {
		RETVAL_FALSE;
	}
}
/* }}} */

/* {{{ proto string gnupg_decryptverify(string enctext, string &plaintext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decryptverify)
{
	char *enctxt;
	phpc_str_size_t enctxt_len;
	zval *plaintext;
	char *userret;
	size_t ret_size;
	gpgme_data_t in, out;
	gpgme_decrypt_result_t decrypt_result;
	gpgme_verify_result_t verify_result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz",
				&enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz",
				&res, &enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	PHPC_PZVAL_DEREF(plaintext);

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_decrypt_cb, PHPC_THIS);

	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_decrypt_verify(PHPC_THIS->ctx, in, out))) {
		if (!PHPC_THIS->errortxt) {
			GNUPG_ERR("decrypt-verify failed");
		}
		gpgme_data_release(in);
		gpgme_data_release(out);
		RETVAL_FALSE;
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	PHPC_PZVAL_CSTRL(plaintext, userret, ret_size);
	free(userret);
	decrypt_result = gpgme_op_decrypt_result(PHPC_THIS->ctx);
	if (decrypt_result->unsupported_algorithm) {
		GNUPG_ERR("unsupported algorithm");
		gpgme_data_release(in);
		return;
	}
	verify_result = gpgme_op_verify_result(PHPC_THIS->ctx);
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
	char *searchkey = NULL;
	phpc_str_size_t searchkey_len;
	char *userret;
	size_t	ret_size;
	gpgme_data_t  out;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&searchkey, &searchkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHP_GNUPG_DO(gpgme_data_new(&out))) {
		GNUPG_ERR("could not create data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_export(PHPC_THIS->ctx, searchkey, 0, out))) {
		GNUPG_ERR("export failed");
		gpgme_data_release(out);
		return;
	}
	userret = gpgme_data_release_and_get_mem(out, &ret_size);
	if (ret_size < 1) {
		RETVAL_FALSE;
	} else {
		PHPC_CSTRL_RETVAL(userret, ret_size);
	}
	free(userret);
}
/* }}} */

/* {{{ proto array gnupg_import(string key)
 * imports the given key and returns a status-array
 */
PHP_FUNCTION(gnupg_import)
{
	char *importkey = NULL;
	phpc_str_size_t importkey_len;
	gpgme_data_t in;
	gpgme_import_result_t result;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&importkey, &importkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &importkey, &importkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHP_GNUPG_DO(gpgme_data_new_from_mem(&in, importkey, importkey_len, 0))) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_import(PHPC_THIS->ctx, in))) {
		GNUPG_ERR("import failed");
		gpgme_data_release(in);
		return;
	}
	gpgme_data_release(in);
	result = gpgme_op_import_result(PHPC_THIS->ctx);

	if (!result || !result->imports || result->imports->result != GPG_ERR_NO_ERROR) {
		RETURN_FALSE;
	}
	PHPC_ARRAY_INIT(return_value);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "imported", result->imported);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "unchanged", result->unchanged);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "newuserids", result->new_user_ids);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "newsubkeys", result->new_sub_keys);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "secretimported", result->secret_imported);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "secretunchanged", result->secret_unchanged);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "newsignatures", result->new_signatures);
	PHPC_ARRAY_ADD_ASSOC_LONG(return_value, "skippedkeys", result->skipped_new_keys);
	if (result->imports && result->imports->fpr) {
		PHPC_ARRAY_ADD_ASSOC_CSTR(return_value,	"fingerprint", result->imports->fpr);
	}
}
/* }}} */

/* {{{ proto book gnupg_deletekey(string key)
 *	deletes a key from the keyring
 */
PHP_FUNCTION(gnupg_deletekey)
{
	char *key;
	phpc_str_size_t key_len;
	phpc_long_t allow_secret = 0;
	gpgme_key_t	gpgme_key;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l",
				&key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|l",
				&res, &key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHP_GNUPG_DO(gpgme_get_key(PHPC_THIS->ctx, key, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_op_delete(PHPC_THIS->ctx, gpgme_key, allow_secret))) {
		GNUPG_ERR("delete failed");
		RETVAL_FALSE;
	} else {
		RETVAL_TRUE;
	}
	gpgme_key_unref(gpgme_key);
}
/* }}} */

/* {{{ proto array gnupg_gettrustlist(string pattern)
* searching for trust items which match PATTERN
*/
PHP_FUNCTION(gnupg_gettrustlist)
{
	char *pattern;
	phpc_str_size_t	pattern_len;
	phpc_val sub_arr;
	gpgme_trust_item_t item;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&pattern, &pattern_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &pattern, &pattern_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHP_GNUPG_DO(gpgme_op_trustlist_start(PHPC_THIS->ctx, pattern, 0))) {
		GNUPG_ERR("could not start trustlist");
		return;
	}
	PHPC_ARRAY_INIT(return_value);
	while (PHP_GNUPG_DO(gpgme_op_trustlist_next(PHPC_THIS->ctx, &item))) {
		PHPC_VAL_MAKE(sub_arr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(sub_arr));

		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sub_arr, level, item);
		PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sub_arr, type, item);
		PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sub_arr, keyid, item);
		PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR_EX(sub_arr, ownertrust, item, owner_trust);
		PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sub_arr, validity, item);
		PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sub_arr, name, item);
		gpgme_trust_item_unref(item);
		PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(return_value, PHPC_VAL_CAST_TO_PZVAL(sub_arr));
	}
}
/* }}} */

/* {{{ proto array gnupg_listsignatures(string keyid) */
PHP_FUNCTION(gnupg_listsignatures)
{
	char	*keyid;
	phpc_str_size_t	keyid_len;

	phpc_val sub_arr;
	phpc_val sig_arr;

	gpgme_key_t		gpgme_key;
	gpgme_user_id_t	gpgme_userid;
	gpgme_key_sig_t	gpgme_signature;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
				&keyid, &keyid_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs",
				&res, &keyid, &keyid_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHP_GNUPG_DO(gpgme_set_keylist_mode(PHPC_THIS->ctx, GPGME_KEYLIST_MODE_SIGS))) {
		GNUPG_ERR("could not switch to sigmode");
		return;
	}
	if (!PHP_GNUPG_DO(gpgme_get_key(PHPC_THIS->ctx, keyid, &gpgme_key, 0))) {
		GNUPG_ERR("get_key failed. given key not unique?");
		return;
	}
	if (!gpgme_key->uids) {
		GNUPG_ERR("no uids found");
		gpgme_key_unref(gpgme_key);
		return;
	}
	PHPC_ARRAY_INIT(return_value);
	gpgme_userid = gpgme_key->uids;
	while (gpgme_userid) {
		PHPC_VAL_MAKE(sub_arr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(sub_arr));
		gpgme_signature = gpgme_userid->signatures;
		while (gpgme_signature) {
			PHPC_VAL_MAKE(sig_arr);
			PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(sig_arr));

			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sig_arr, uid, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sig_arr, name, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sig_arr, email, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_CSTR(sig_arr, comment, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, expires, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(sig_arr, revoked, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(sig_arr, expired, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_BOOL(sig_arr, invalid, gpgme_signature);
			PHP_GNUPG_ARRAY_ADD_ASSOC_LONG(sig_arr, timestamp, gpgme_signature);
			PHPC_ARRAY_ADD_ASSOC_ZVAL(
				PHPC_VAL_CAST_TO_PZVAL(sub_arr),
				gpgme_signature->keyid,
				PHPC_VAL_CAST_TO_PZVAL(sig_arr)
			);
			gpgme_signature = gpgme_signature->next;
		}
		PHPC_ARRAY_ADD_ASSOC_ZVAL(
				return_value, gpgme_userid->uid, PHPC_VAL_CAST_TO_PZVAL(sub_arr));
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
