/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2004 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.0 of the PHP license,       |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_0.txt.                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Thilo Raufeisen                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifndef PHP_GNUPG_H
#define PHP_GNUPG_H

extern zend_module_entry gnupg_module_entry;
#define phpext_gnupg_ptr &gnupg_module_entry

#ifdef PHP_WIN32
#define PHP_GNUPG_API __declspec(dllexport)
#else
#define PHP_GNUPG_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

#include <gpgme.h>

typedef struct _gnupg_object{
	gpgme_ctx_t ctx;
	zval passphrase;
	gpgme_key_t encryptkey;
	gpgme_error_t err;
	int signmode;
} gnupg_object;

typedef struct _ze_gnupg_object{
	zend_object zo;
	gnupg_object *gnupg_ptr;
} ze_gnupg_object;

zend_class_entry *gnupg_class_entry;

PHP_MINIT_FUNCTION(gnupg);
PHP_MSHUTDOWN_FUNCTION(gnupg);
PHP_MINFO_FUNCTION(gnupg);

PHP_FUNCTION(gnupg_construct);
PHP_FUNCTION(gnupg_keyinfo);
PHP_FUNCTION(gnupg_verify);
PHP_FUNCTION(gnupg_geterror);
PHP_FUNCTION(gnupg_setpassphrase);
PHP_FUNCTION(gnupg_setsignerkey);
PHP_FUNCTION(gnupg_setencryptkey);
PHP_FUNCTION(gnupg_setsignmode);
PHP_FUNCTION(gnupg_setarmor);
PHP_FUNCTION(gnupg_sign);
PHP_FUNCTION(gnupg_clearsignerkey);
PHP_FUNCTION(gnupg_getprotocol);
PHP_FUNCTION(gnupg_encrypt);
PHP_FUNCTION(gnupg_encryptsign);
PHP_FUNCTION(gnupg_decrypt);
PHP_FUNCTION(gnupg_decryptverify);
PHP_FUNCTION(gnupg_export);
PHP_FUNCTION(gnupg_import);

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
