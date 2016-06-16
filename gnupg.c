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
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
				RETURN_FALSE; \
			} \
		} \
	} while (0)
/* }}} */

#define GNUPG_RES_FETCH() \
	PHPC_THIS = (PHPC_OBJ_STRUCT_NAME(gnupg) *) PHPC_RES_FETCH(res, "ctx", le_gnupg)

/* {{{ GNUPG_ERR */
#define GNUPG_ERR(error) \
	if (PHPC_THIS) { \
		switch (PHPC_THIS->errormode) { \
			case 1: \
				php_error_docref(NULL TSRMLS_CC, E_WARNING, (char*)error); \
				break; \
			case 2: \
				zend_throw_exception(zend_exception_get_default(TSRMLS_C), (char*) error, 0 TSRMLS_CC); \
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

/* {{{ gnupg_free_encryptkeys */
static void gnupg_free_encryptkeys(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	if (PHPC_THIS) {
		int idx;
		/* loop through all encryptkeys and unref them in the gpgme-lib */
		for (idx=0; idx < PHPC_THIS->encrypt_size; idx++) {
			gpgme_key_unref(PHPC_THIS->encryptkeys[idx]);
		}
		/* it's an odd-thing, but other solutions makes problems :
		*  erealloc(x,0) gives a segfault with PHP 4 and debug enabled
		*  efree(x) alone ends in a segfault
		*/
		efree(erealloc(PHPC_THIS->encryptkeys, 0));
		PHPC_THIS->encryptkeys = NULL;
		PHPC_THIS->encrypt_size = 0;
	}
}
/* }}} */

/* {{{ gnupg_free_resource_ptre */
static void gnupg_free_resource_ptr(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	if (PHPC_THIS) {
		if (PHPC_THIS->ctx) {
			/* clear all signers from the gpgme-lib and finally release it */
			gpgme_signers_clear(PHPC_THIS->ctx);
			gpgme_release(PHPC_THIS->ctx);
			PHPC_THIS->ctx = NULL;
		}
		/* basic cleanup */
		gnupg_free_encryptkeys(PHPC_THIS TSRMLS_CC);
		zend_hash_destroy(PHPC_THIS->signkeys);
		FREE_HASHTABLE(PHPC_THIS->signkeys);
		zend_hash_destroy(PHPC_THIS->decryptkeys);
		FREE_HASHTABLE(PHPC_THIS->decryptkeys);
	}
}
/* }}} */

/* {{{ gnupg_res_dtor */
static void gnupg_res_dtor(phpc_res_entry_t *rsrc TSRMLS_DC) /* {{{ */
{
	PHPC_THIS_DECLARE(gnupg) = rsrc->ptr;
	gnupg_free_resource_ptr(PHPC_THIS TSRMLS_CC);
	efree(PHPC_THIS);
}
/* }}} */

/* {{{ gnupg_res_init */
static void gnupg_res_init(PHPC_THIS_DECLARE(gnupg) TSRMLS_DC)
{
	/* init the gpgme-lib and set the default values */
	gpgme_ctx_t	ctx;
	gpgme_error_t err;
	gpgme_check_version(NULL);

	err = gpgme_new(&ctx);
	if (err == GPG_ERR_NO_ERROR) {
#ifdef GNUPG_PATH
		gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, GNUPG_PATH, NULL);
#endif
		gpgme_set_armor(ctx,1);
	}
	PHPC_THIS->ctx = ctx;
	PHPC_THIS->encryptkeys = NULL;
	PHPC_THIS->encrypt_size = 0;
	PHPC_THIS->signmode = GPGME_SIG_MODE_CLEAR;
	PHPC_THIS->errortxt = NULL;
	PHPC_THIS->errormode = 3;
	ALLOC_HASHTABLE(PHPC_THIS->signkeys);
	zend_hash_init(PHPC_THIS->signkeys, 0, NULL, NULL, 0);
	ALLOC_HASHTABLE(PHPC_THIS->decryptkeys);
	zend_hash_init(PHPC_THIS->decryptkeys, 0, NULL, NULL, 0);
}
/* }}} */

/* {{{ free gnupg */
PHPC_OBJ_HANDLER_FREE(gnupg)
{
	PHPC_OBJ_HANDLER_FREE_INIT(gnupg);

	gnupg_free_resource_ptr(PHPC_THIS TSRMLS_CC);

	PHPC_OBJ_HANDLER_FREE_DESTROY();
}

/* {{{ create_ex gnupg */
PHPC_OBJ_HANDLER_CREATE_EX(gnupg)
{
	PHPC_OBJ_HANDLER_CREATE_EX_INIT(gnupg);

	gnupg_res_init(PHPC_THIS TSRMLS_CC);

	PHPC_OBJ_HANDLER_CREATE_EX_RETURN(gnupg);
}

/* {{{ create gnupg */
PHPC_OBJ_HANDLER_CREATE(gnupg)
{
	PHPC_OBJ_HANDLER_CREATE_RETURN(gnupg);
}

/* {{{ arginfo gnupg_verify_method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_verify_method, 0, 0, 2)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_decryptverify_method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_decryptverify_method, 0, 0, 2)
	ZEND_ARG_INFO(0, enctext)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ methodlist gnupg */
phpc_function_entry gnupg_methods[] = {
	PHP_FALIAS(keyinfo,             gnupg_keyinfo,          NULL)
	PHP_FALIAS(verify,              gnupg_verify,           arginfo_gnupg_verify_method)
	PHP_FALIAS(geterror,            gnupg_geterror,         NULL)
	PHP_FALIAS(clearsignkeys,       gnupg_clearsignkeys,    NULL)
	PHP_FALIAS(clearencryptkeys,    gnupg_clearencryptkeys, NULL)
	PHP_FALIAS(cleardecryptkeys,    gnupg_cleardecryptkeys, NULL)
	PHP_FALIAS(setarmor,            gnupg_setarmor,         NULL)
	PHP_FALIAS(encrypt,             gnupg_encrypt,          NULL)
	PHP_FALIAS(decrypt,             gnupg_decrypt,          NULL)
	PHP_FALIAS(export,              gnupg_export,           NULL)
	PHP_FALIAS(import,              gnupg_import,           NULL)
	PHP_FALIAS(getprotocol,         gnupg_getprotocol,      NULL)
	PHP_FALIAS(setsignmode,         gnupg_setsignmode,      NULL)
	PHP_FALIAS(sign,                gnupg_sign,             NULL)
	PHP_FALIAS(encryptsign,         gnupg_encryptsign,      NULL)
	PHP_FALIAS(decryptverify,       gnupg_decryptverify,    arginfo_gnupg_decryptverify_method)
	PHP_FALIAS(addsignkey,          gnupg_addsignkey,       NULL)
	PHP_FALIAS(addencryptkey,       gnupg_addencryptkey,    NULL)
	PHP_FALIAS(adddecryptkey,       gnupg_adddecryptkey,    NULL)
	PHP_FALIAS(deletekey,           gnupg_deletekey,        NULL)
	PHP_FALIAS(gettrustlist,        gnupg_gettrustlist,     NULL)
	PHP_FALIAS(listsignatures,      gnupg_listsignatures,   NULL)
	PHP_FALIAS(seterrormode,        gnupg_seterrormode,     NULL)
	PHPC_FE_END
};
/* }}} */

/* {{{ arginfo gnupg_verify_method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_verify_function, 0, 0, 3)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, text)
	ZEND_ARG_INFO(0, signature)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ arginfo gnupg_decryptverify_method */
ZEND_BEGIN_ARG_INFO_EX(arginfo_gnupg_decryptverify_function, 0, 0, 3)
	ZEND_ARG_INFO(0, res)
	ZEND_ARG_INFO(0, enctext)
	ZEND_ARG_INFO(1, plaintext)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ functionlist gnupg */
static zend_function_entry gnupg_functions[] = {
	PHP_FE(gnupg_init,				NULL)
	PHP_FE(gnupg_keyinfo,			NULL)
	PHP_FE(gnupg_sign,				NULL)
	PHP_FE(gnupg_verify,			arginfo_gnupg_verify_function)
	PHP_FE(gnupg_clearsignkeys,		NULL)
	PHP_FE(gnupg_clearencryptkeys,	NULL)
	PHP_FE(gnupg_cleardecryptkeys,	NULL)
	PHP_FE(gnupg_setarmor,			NULL)
	PHP_FE(gnupg_encrypt,			NULL)
	PHP_FE(gnupg_decrypt,			NULL)
	PHP_FE(gnupg_export,			NULL)
	PHP_FE(gnupg_import,			NULL)
	PHP_FE(gnupg_getprotocol,		NULL)
	PHP_FE(gnupg_setsignmode,		NULL)
	PHP_FE(gnupg_encryptsign,		NULL)
	PHP_FE(gnupg_decryptverify,		arginfo_gnupg_decryptverify_function)
	PHP_FE(gnupg_geterror,			NULL)
	PHP_FE(gnupg_addsignkey,		NULL)
	PHP_FE(gnupg_addencryptkey,		NULL)
	PHP_FE(gnupg_adddecryptkey,		NULL)
	PHP_FE(gnupg_deletekey,			NULL)
	PHP_FE(gnupg_gettrustlist,		NULL)
	PHP_FE(gnupg_listsignatures,	NULL)
	PHP_FE(gnupg_seterrormode,		NULL)
	{NULL, NULL, NULL}
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

/* {{{ class constants */
static inline void gnupg_declare_long_constant(const char *const_name, long value TSRMLS_DC)
{
	zend_declare_class_constant_long(gnupg_class_entry, (char*)const_name, strlen(const_name), value TSRMLS_CC);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(gnupg)
{
	zend_class_entry ce;

	/* init class */
	INIT_CLASS_ENTRY(ce, "gnupg", gnupg_methods);
	PHPC_CLASS_SET_HANDLER_CREATE(ce, gnupg);
	gnupg_class_entry = PHPC_CLASS_REGISTER(ce);
	PHPC_OBJ_INIT_HANDLERS(gnupg);
	PHPC_OBJ_SET_HANDLER_OFFSET(gnupg);
	PHPC_OBJ_SET_HANDLER_FREE(gnupg);

	/* register resource */
	le_gnupg = zend_register_list_destructors_ex(gnupg_res_dtor, NULL, "ctx", module_number);

	if (SUCCESS != gnupg_keylistiterator_init()) {
		return FAILURE;
	}
	gnupg_declare_long_constant("SIG_MODE_NORMAL",            GPGME_SIG_MODE_NORMAL TSRMLS_CC);
	gnupg_declare_long_constant("SIG_MODE_DETACH",            GPGME_SIG_MODE_DETACH TSRMLS_CC);
	gnupg_declare_long_constant("SIG_MODE_CLEAR",             GPGME_SIG_MODE_CLEAR TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_UNKNOWN",           GPGME_VALIDITY_UNKNOWN TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_UNDEFINED",         GPGME_VALIDITY_UNDEFINED TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_NEVER",             GPGME_VALIDITY_NEVER TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_MARGINAL",          GPGME_VALIDITY_MARGINAL TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_FULL",              GPGME_VALIDITY_FULL TSRMLS_CC);
	gnupg_declare_long_constant("VALIDITY_ULTIMATE",          GPGME_VALIDITY_ULTIMATE TSRMLS_CC);
	gnupg_declare_long_constant("PROTOCOL_OpenPGP",           GPGME_PROTOCOL_OpenPGP TSRMLS_CC);
	gnupg_declare_long_constant("PROTOCOL_CMS",               GPGME_PROTOCOL_CMS TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_VALID",               GPGME_SIGSUM_VALID TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_GREEN",               GPGME_SIGSUM_GREEN TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_RED",                 GPGME_SIGSUM_RED TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_KEY_REVOKED",         GPGME_SIGSUM_KEY_REVOKED TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_KEY_EXPIRED",         GPGME_SIGSUM_KEY_EXPIRED TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_SIG_EXPIRED",         GPGME_SIGSUM_SIG_EXPIRED TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_KEY_MISSING",         GPGME_SIGSUM_KEY_MISSING TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_CRL_MISSING",         GPGME_SIGSUM_CRL_MISSING TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_CRL_TOO_OLD",         GPGME_SIGSUM_CRL_TOO_OLD TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_BAD_POLICY",          GPGME_SIGSUM_BAD_POLICY TSRMLS_CC);
	gnupg_declare_long_constant("SIGSUM_SYS_ERROR",           GPGME_SIGSUM_SYS_ERROR TSRMLS_CC);
	gnupg_declare_long_constant("ERROR_WARNING",              1 TSRMLS_CC);
	gnupg_declare_long_constant("ERROR_EXCEPTION",            2 TSRMLS_CC);
	gnupg_declare_long_constant("ERROR_SILENT",            	  3 TSRMLS_CC);
	REGISTER_LONG_CONSTANT("GNUPG_SIG_MODE_NORMAL",            GPGME_SIG_MODE_NORMAL, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIG_MODE_DETACH",            GPGME_SIG_MODE_DETACH, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIG_MODE_CLEAR",             GPGME_SIG_MODE_CLEAR, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_UNKNOWN",           GPGME_VALIDITY_UNKNOWN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_UNDEFINED",         GPGME_VALIDITY_UNDEFINED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_NEVER",             GPGME_VALIDITY_NEVER, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_MARGINAL",          GPGME_VALIDITY_MARGINAL, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_FULL",              GPGME_VALIDITY_FULL, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_VALIDITY_ULTIMATE",          GPGME_VALIDITY_ULTIMATE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_PROTOCOL_OpenPGP",           GPGME_PROTOCOL_OpenPGP, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_PROTOCOL_CMS",               GPGME_PROTOCOL_CMS, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_VALID",               GPGME_SIGSUM_VALID, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_GREEN",               GPGME_SIGSUM_GREEN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_RED",                 GPGME_SIGSUM_RED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_KEY_REVOKED",         GPGME_SIGSUM_KEY_REVOKED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_KEY_EXPIRED",         GPGME_SIGSUM_KEY_EXPIRED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_SIG_EXPIRED",         GPGME_SIGSUM_SIG_EXPIRED, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_KEY_MISSING",         GPGME_SIGSUM_KEY_MISSING, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_CRL_MISSING",         GPGME_SIGSUM_CRL_MISSING, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_CRL_TOO_OLD",         GPGME_SIGSUM_CRL_TOO_OLD, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_BAD_POLICY",          GPGME_SIGSUM_BAD_POLICY, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_SIGSUM_SYS_ERROR",           GPGME_SIGSUM_SYS_ERROR, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_ERROR_WARNING",              1, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_ERROR_EXCEPTION",            2, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("GNUPG_ERROR_SILENT",               3, CONST_CS | CONST_PERSISTENT);

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
	if (!PHPC_HASH_CSTR_FIND_PTR_IN_COND(PHPC_THIS->signkeys, (char *)uid, passphrase)) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}
	if (!passphrase) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}

	if (write(fd, passphrase, strlen(passphrase)) == strlen(passphrase) && write(fd, "\n", 1) == 1) {
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
	if (!PHPC_HASH_CSTR_FIND_PTR_IN_COND(PHPC_THIS->decryptkeys, (char *)uid, passphrase)) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}
	if (!passphrase) {
		GNUPG_ERR("no passphrase set");
		return 1;
	}
	if (write(fd, passphrase, strlen(passphrase)) == strlen(passphrase) && write(fd, "\n", 1) == 1) {
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
		PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "fingerprint", gpgme_signatures->fpr);
		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "validity", gpgme_signatures->validity);
		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "timestamp", gpgme_signatures->timestamp);
		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "status", gpgme_signatures->status);
		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "summary", gpgme_signatures->summary);
		PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(main_arr, PHPC_VAL_CAST_TO_PZVAL(sig_arr));

		gpgme_signatures = gpgme_signatures->next;
	}
	return 1;
}
/* }}} */

/* {{{ proto resource gnupg_init()
 * inits gnupg and returns a resource
*/
PHP_FUNCTION(gnupg_init)
{
	PHPC_THIS_DECLARE(gnupg);
	PHPC_THIS = emalloc(sizeof(PHPC_OBJ_STRUCT_NAME(gnupg)));
	gnupg_res_init(PHPC_THIS TSRMLS_CC);
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &armor) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &armor) == FAILURE) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &errormode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &errormode) == FAILURE) {
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
	phpc_long_t			 signmode;

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &signmode) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &signmode) == FAILURE) {
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
 * returns an array with informations about all keys, that matches the given pattern
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_op_keylist_start(PHPC_THIS->ctx, searchkey, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not init keylist");
		return;
	}

	PHPC_ARRAY_INIT(return_value);

	while (!(PHPC_THIS->err = gpgme_op_keylist_next(PHPC_THIS->ctx, &gpgme_key))) {
		PHPC_VAL_MAKE(subarr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subarr));

		PHPC_VAL_MAKE(subkeys);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subkeys));

		PHPC_VAL_MAKE(userids);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(userids));

		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "disabled", gpgme_key->disabled);
		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "expired", gpgme_key->expired);
		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "revoked", gpgme_key->revoked);
		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "is_secret", gpgme_key->secret);
		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "can_sign", gpgme_key->can_sign);
		PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subarr), "can_encrypt", gpgme_key->can_encrypt);

		gpgme_userid = gpgme_key->uids;
		while (gpgme_userid) {
			PHPC_VAL_MAKE(userid);
			PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(userid));

			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(userid), "name", gpgme_userid->name);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(userid), "comment", gpgme_userid->comment);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(userid), "email", gpgme_userid->email);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(userid), "uid", gpgme_userid->uid);

			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(userid), "revoked", gpgme_userid->revoked);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(userid), "invalid", gpgme_userid->invalid);

			PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(PHPC_VAL_CAST_TO_PZVAL(userids), PHPC_VAL_CAST_TO_PZVAL(userid));
			gpgme_userid = gpgme_userid->next;
		}

		PHPC_ARRAY_ADD_ASSOC_ZVAL(PHPC_VAL_CAST_TO_PZVAL(subarr), "uids", PHPC_VAL_CAST_TO_PZVAL(userids));

		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			PHPC_VAL_MAKE(subkey);
			PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(subkey));

			if (gpgme_subkey->fpr) {
				PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(subkey), "fingerprint", gpgme_subkey->fpr);
			}

			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(subkey), "keyid", gpgme_subkey->keyid);

			PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(subkey), "timestamp", gpgme_subkey->timestamp);
			PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(subkey), "expires", gpgme_subkey->expires);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "is_secret", gpgme_subkey->secret);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "invalid", gpgme_subkey->invalid);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "can_encrypt", gpgme_subkey->can_encrypt);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "can_sign", gpgme_subkey->can_sign);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "disabled", gpgme_subkey->disabled);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "expired", gpgme_subkey->expired);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(subkey), "revoked", gpgme_subkey->revoked);

			PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(PHPC_VAL_CAST_TO_PZVAL(subkeys), PHPC_VAL_CAST_TO_PZVAL(subkey));
			gpgme_subkey = gpgme_subkey->next;
		}

		PHPC_ARRAY_ADD_ASSOC_ZVAL(PHPC_VAL_CAST_TO_PZVAL(subarr), "subkeys", PHPC_VAL_CAST_TO_PZVAL(subkeys));

		PHPC_ARRAY_ADD_NEXT_INDEX_ZVAL(return_value, PHPC_VAL_CAST_TO_PZVAL(subarr));
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|s", &res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if (passphrase) {
		gpgme_subkey = gpgme_key->subkeys;
		while (gpgme_subkey) {
			if (gpgme_subkey->can_sign == 1) {
				PHPC_HASH_CSTR_ADD_PTR(PHPC_THIS->signkeys, gpgme_subkey->keyid, passphrase, passphrase_len + 1);
			}
			gpgme_subkey = gpgme_subkey->next;
		}
	}
	if ((PHPC_THIS->err = gpgme_signers_add(PHPC_THIS->ctx, gpgme_key)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss", &res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("get_key failed");
		return;
	}
	gpgme_subkey = gpgme_key->subkeys;
	while (gpgme_subkey) {
		if (gpgme_subkey->secret == 1) {
			PHPC_HASH_CSTR_ADD_PTR(PHPC_THIS->decryptkeys, gpgme_subkey->keyid, passphrase, passphrase_len + 1);
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

	GNUPG_GETOBJ();

	if (this) {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key_id, &key_id_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &key_id, &key_id_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if ((PHPC_THIS->err = gpgme_get_key(PHPC_THIS->ctx, key_id, &gpgme_key, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("get_key failed");
		return;
	}
	PHPC_THIS->encryptkeys = erealloc(PHPC_THIS->encryptkeys, sizeof(PHPC_THIS->encryptkeys) * (PHPC_THIS->encrypt_size + 2));
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
	gnupg_free_encryptkeys(PHPC_THIS TSRMLS_CC);

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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_cb, PHPC_THIS);
	if ((PHPC_THIS->err = gpgme_data_new_from_mem(&in, value, value_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_sign(PHPC_THIS->ctx, in, out, PHPC_THIS->signmode)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (!PHPC_THIS->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	if ((PHPC_THIS->err = gpgme_data_new_from_mem(&in, value, value_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could no create in-data buffer");
		return;
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_encrypt(PHPC_THIS->ctx, PHPC_THIS->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out)) != GPG_ERR_NO_ERROR) {
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
 * encrypts and signs the given text with the keys, which weres set with setencryptkey and setsignkey before
 * and returns the encrypted text
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if (!PHPC_THIS->encryptkeys) {
		GNUPG_ERR("no key for encryption set");
		return;
	}
	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_cb, PHPC_THIS);
	if ((PHPC_THIS->err = gpgme_data_new_from_mem (&in, value, value_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_encrypt_sign(PHPC_THIS->ctx, PHPC_THIS->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|z", &signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rzz|z", &res, &signed_text, &signature, &plain_text) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if (Z_TYPE_P(signature) == IS_STRING) { /* detached signature */
		/* setup signature-databuffer for gpgme */
		if ((PHPC_THIS->err = gpgme_data_new_from_mem(&gpgme_sig, Z_STRVAL_P(signature), Z_STRLEN_P(signature), 0)) != GPG_ERR_NO_ERROR) {
			GNUPG_ERR("could not create signature-databuffer");
			return;
		}
		/* and the text */
		if ((PHPC_THIS->err = gpgme_data_new_from_mem(&gpgme_text, Z_STRVAL_P(signed_text), Z_STRLEN_P(signed_text), 0)) != GPG_ERR_NO_ERROR) {
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
		/* now verify sig + text */
		if ((PHPC_THIS->err = gpgme_op_verify (PHPC_THIS->ctx, gpgme_sig, gpgme_text, NULL)) != GPG_ERR_NO_ERROR) {
			GNUPG_ERR("verify failed");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
	} else { /* clearsign or normal signature */
		if ((PHPC_THIS->err = gpgme_data_new_from_mem(&gpgme_sig, Z_STRVAL_P(signed_text), Z_STRLEN_P(signed_text), 0)) != GPG_ERR_NO_ERROR) {
			GNUPG_ERR("could not create signature-databuffer");
			return;
		}
		/* set a NULL databuffer for gpgme */
		if ((PHPC_THIS->err = gpgme_data_new_from_mem(&gpgme_text, NULL, 0, 0)) != GPG_ERR_NO_ERROR) {
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
		/* and verify the 'signature' */
		if ((PHPC_THIS->err = gpgme_op_verify(PHPC_THIS->ctx, gpgme_sig, NULL, gpgme_text)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &enctxt, &enctxt_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &enctxt, &enctxt_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_decrypt_cb, PHPC_THIS);

	if ((PHPC_THIS->err = gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_decrypt(PHPC_THIS->ctx, in, out)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz", &res, &enctxt, &enctxt_len, &plaintext) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	PHPC_PZVAL_DEREF(plaintext);

	gpgme_set_passphrase_cb(PHPC_THIS->ctx, passphrase_decrypt_cb, PHPC_THIS);

	if ((PHPC_THIS->err = gpgme_data_new_from_mem(&in, enctxt, enctxt_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create in-data buffer");
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_decrypt_verify(PHPC_THIS->ctx, in, out)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &searchkey, &searchkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_data_new(&out)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create data buffer");
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_export(PHPC_THIS->ctx, searchkey, 0, out)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &importkey, &importkey_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &importkey, &importkey_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_data_new_from_mem(&in, importkey, importkey_len, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_import(PHPC_THIS->ctx,in)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|l", &res, &key, &key_len, &allow_secret) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}

	if ((PHPC_THIS->err = gpgme_get_key(PHPC_THIS->ctx, key, &gpgme_key, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("get_key failed");
		return;
	}
	if ((PHPC_THIS->err = gpgme_op_delete(PHPC_THIS->ctx,gpgme_key,allow_secret)) != GPG_ERR_NO_ERROR) {
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pattern, &pattern_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &pattern, &pattern_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_op_trustlist_start (PHPC_THIS->ctx, pattern, 0)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not start trustlist");
		return;
	}
	PHPC_ARRAY_INIT(return_value);
	while (!(PHPC_THIS->err = gpgme_op_trustlist_next (PHPC_THIS->ctx, &item))) {
		PHPC_VAL_MAKE(sub_arr);
		PHPC_ARRAY_INIT(PHPC_VAL_CAST_TO_PZVAL(sub_arr));

		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "level", item->level);
		PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "type", item->type);
		PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "keyid", item->keyid);
		PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "ownertrust", item->owner_trust);
		PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "validity", item->validity);
		PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sub_arr), "name", item->name);
		gpgme_trust_item_unref	(item);
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
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &keyid, &keyid_len) == FAILURE) {
			return;
		}
	} else {
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &keyid, &keyid_len) == FAILURE) {
			return;
		}
		GNUPG_RES_FETCH();
	}
	if ((PHPC_THIS->err = gpgme_set_keylist_mode(PHPC_THIS->ctx, GPGME_KEYLIST_MODE_SIGS)) != GPG_ERR_NO_ERROR) {
		GNUPG_ERR("could not switch to sigmode");
		return;
	}
	if ((PHPC_THIS->err = gpgme_get_key(PHPC_THIS->ctx, keyid, &gpgme_key, 0)) != GPG_ERR_NO_ERROR) {
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

			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "uid", gpgme_signature->uid);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "name", gpgme_signature->name);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "email", gpgme_signature->email);
			PHPC_ARRAY_ADD_ASSOC_CSTR(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "comment", gpgme_signature->comment);
			PHPC_ARRAY_ADD_ASSOC_LONG(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "expires", gpgme_signature->expires);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "revoked", gpgme_signature->revoked);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "expired", gpgme_signature->expired);
			PHPC_ARRAY_ADD_ASSOC_BOOL(PHPC_VAL_CAST_TO_PZVAL(sig_arr), "invalid", gpgme_signature->invalid);
			PHPC_ARRAY_ADD_ASSOC_ZVAL(
				PHPC_VAL_CAST_TO_PZVAL(sub_arr),
				gpgme_signature->keyid,
				PHPC_VAL_CAST_TO_PZVAL(sig_arr)
			);
			gpgme_signature = gpgme_signature->next;
		}
		PHPC_ARRAY_ADD_ASSOC_ZVAL(return_value, gpgme_userid->uid, PHPC_VAL_CAST_TO_PZVAL(sub_arr));
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
