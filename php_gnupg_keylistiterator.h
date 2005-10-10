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
} gnupg_keylistiterator_object;

typedef struct _ze_gnupg_keylistiterator_object{
	zend_object zo;
	gnupg_keylistiterator_object *gnupg_keylistiterator_ptr;
} ze_gnupg_keylistiterator_object;

zend_class_entry *gnupg_keylistiterator_class_entry;

PHP_FUNCTION(gnupg_keylistiterator___construct);
PHP_FUNCTION(gnupg_keylistiterator_current);
PHP_FUNCTION(gnupg_keylistiterator_next);
PHP_FUNCTION(gnupg_keylistiterator_rewind);
PHP_FUNCTION(gnupg_keylistiterator_key);
PHP_FUNCTION(gnupg_keylistiterator_valid);

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
