
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

#ifndef PHP_GNUPG_H
#define PHP_GNUPG_H

extern zend_module_entry gnupg_module_entry;
#define phpext_gnupg_ptr &gnupg_module_entry

#define PHP_GNUPG_VERSION "1.5.4"

#ifdef PHP_WIN32
#define PHP_GNUPG_API __declspec(dllexport)
#else
#define PHP_GNUPG_API
#endif

#include <gpgme.h>

#ifdef ZTS
#include "TSRM.h"
#endif

/* Object structure */
typedef struct _gnupg_object {
	gpgme_ctx_t ctx;
	gpgme_key_t *encryptkeys;
	int encrypt_size;
	gpgme_sig_mode_t signmode;
	HashTable *signkeys;
	HashTable *decryptkeys;
	gpgme_error_t err;
	char *errortxt;
	int errormode;
	zend_object std;
} gnupg_object;

/* The actual structure is defined in gnupg.c to keep it encapsulated */

PHP_MINIT_FUNCTION(gnupg);
PHP_MSHUTDOWN_FUNCTION(gnupg);
PHP_MINFO_FUNCTION(gnupg);

PHP_METHOD(gnupg, __construct);
PHP_FUNCTION(gnupg_keyinfo);
PHP_FUNCTION(gnupg_verify);
PHP_FUNCTION(gnupg_getengineinfo);
PHP_FUNCTION(gnupg_geterror);
PHP_FUNCTION(gnupg_geterrorinfo);
PHP_FUNCTION(gnupg_setsignmode);
PHP_FUNCTION(gnupg_setarmor);
PHP_FUNCTION(gnupg_sign);
PHP_FUNCTION(gnupg_clearsignkeys);
PHP_FUNCTION(gnupg_clearencryptkeys);
PHP_FUNCTION(gnupg_cleardecryptkeys);
PHP_FUNCTION(gnupg_getprotocol);
PHP_FUNCTION(gnupg_encrypt);
PHP_FUNCTION(gnupg_encryptsign);
PHP_FUNCTION(gnupg_decrypt);
PHP_FUNCTION(gnupg_messagekeys);
PHP_FUNCTION(gnupg_decryptverify);
PHP_FUNCTION(gnupg_export);
PHP_FUNCTION(gnupg_import);
PHP_FUNCTION(gnupg_init);
PHP_FUNCTION(gnupg_addsignkey);
PHP_FUNCTION(gnupg_addencryptkey);
PHP_FUNCTION(gnupg_adddecryptkey);
PHP_FUNCTION(gnupg_deletekey);
#if GPGME_VERSION_NUMBER < 0x020000  /* GPGME < 2.0.0 */
PHP_FUNCTION(gnupg_gettrustlist);
#endif
PHP_FUNCTION(gnupg_listsignatures);
PHP_FUNCTION(gnupg_seterrormode);

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