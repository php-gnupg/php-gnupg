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
  | Author: Thilo Raufeisen <traufeisen@php.net>                         |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_gnupg.h"

#ifdef ZEND_ENGINE_2
#include "php_gnupg_keylistiterator.h"
#endif

static int le_gnupg;

#define PHP_GNUPG_VERSION "0.6beta"

#ifdef ZEND_ENGINE_2
static zend_object_handlers gnupg_object_handlers;
#endif

/* {{{ defs */
#define GNUPG_GETOBJ() \
	zval *this = getThis(); \
	gnupg_object *intern; \
	zval *res; \
	if(this){ \
		intern	=	(gnupg_object*) zend_object_store_get_object(getThis() TSRMLS_CC); \
		if(!intern){ \
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
			RETURN_FALSE; \
		} \
	}

#define GNUPG_ERR(error) \
    if(intern){ \
		switch (intern->errormode) { \
			case 1: \
				php_error_docref(NULL TSRMLS_CC, E_WARNING, (char*)error); \
				break; \
			case 2: \
				zend_throw_exception(zend_exception_get_default(), (char*) error, 0 TSRMLS_CC); \
				break; \
			default: \
				intern->errortxt = (char*)error; \
		} \
    }else{ \
        php_error_docref(NULL TSRMLS_CC, E_WARNING, (char*)error); \
    } \
    RETVAL_FALSE;
/* }}} */

/* {{{ free encryptkeys */
static void gnupg_free_encryptkeys(gnupg_object *intern TSRMLS_DC){
	if(intern){
		int idx;
		for(idx=0;idx<intern->encrypt_size;idx++){
			gpgme_key_unref (intern->encryptkeys[idx]);
		}
		efree(erealloc(intern->encryptkeys,0));	
        intern->encryptkeys = NULL;
        intern->encrypt_size = 0;
	}
}
/* }}} */

/* {{{ free_resource */
static void gnupg_free_resource_ptr(gnupg_object *intern TSRMLS_DC){
    if(intern){
        if(intern->ctx){
            gpgme_signers_clear (intern->ctx);
            gpgme_release       (intern->ctx);
            intern->ctx = NULL;
        }
        gnupg_free_encryptkeys(intern);
		zend_hash_destroy(intern->signkeys);
		FREE_HASHTABLE(intern->signkeys);
		zend_hash_destroy(intern->decryptkeys);
        FREE_HASHTABLE(intern->decryptkeys);
    }
}
/* }}} */

/* {{{ gnupg_res_dtor */
static void gnupg_res_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
    gnupg_object *intern;
    intern = (gnupg_object *) rsrc->ptr;
    gnupg_free_resource_ptr(intern TSRMLS_CC);
	efree(intern);
}
/* }}} */

/* {{{ gnupg_res_init */
static void gnupg_res_init(gnupg_object *intern TSRMLS_DC){
	gpgme_ctx_t	ctx;
	gpgme_new					(&ctx);
	gpgme_set_armor				(ctx,1);
	intern->ctx				=	ctx;
	intern->encryptkeys		=	NULL;
	intern->encrypt_size	=	0;
	intern->signmode		=	GPGME_SIG_MODE_CLEAR;
	intern->errortxt		=	NULL;
	intern->errormode		=	3;
	ALLOC_HASHTABLE				(intern->signkeys);
    zend_hash_init				(intern->signkeys, 0, NULL, NULL, 0);
    ALLOC_HASHTABLE				(intern->decryptkeys);
    zend_hash_init				(intern->decryptkeys, 0, NULL, NULL, 0);
	return;
}
/* }}} */

#ifdef ZEND_ENGINE_2
/* {{{ free_storage */
static void gnupg_obj_dtor(gnupg_object *intern TSRMLS_DC){
	if(!intern){
		return;
	}
	gnupg_free_resource_ptr(intern TSRMLS_CC);
	if(intern->zo.properties){
		zend_hash_destroy(intern->zo.properties);
		FREE_HASHTABLE(intern->zo.properties);
	}
	efree(intern);
}
/* }}} */


/* {{{ objects_new */
zend_object_value gnupg_obj_new(zend_class_entry *class_type TSRMLS_DC){
	gnupg_object *intern;
	zval *tmp;
	zend_object_value retval;
	
	intern					=	emalloc(sizeof(gnupg_object));
	intern->zo.ce			=	class_type;
	intern->zo.in_get		=	0;
	intern->zo.in_set		=	0;
	intern->zo.properties	=	NULL;
	
	ALLOC_HASHTABLE	(intern->zo.properties);
	zend_hash_init	(intern->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);
	zend_hash_copy	(intern->zo.properties, &class_type->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
	
	retval.handle		=	zend_objects_store_put(intern,NULL,(zend_objects_free_object_storage_t) gnupg_obj_dtor,NULL TSRMLS_CC);
	retval.handlers		=	(zend_object_handlers *) & gnupg_object_handlers;
	gnupg_res_init	(intern TSRMLS_CC);
	
	return retval;
}
/* }}} */

/* {{{ methodlist gnupg */
static zend_function_entry gnupg_methods[] = {
	ZEND_ME(gnupg,	keyinfo,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	verify,				NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	geterror,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	clearsignkeys,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	clearencryptkeys,	NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	cleardecryptkeys,	NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	setarmor,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	encrypt,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	decrypt,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	export,				NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	import,				NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	getprotocol,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	setsignmode,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	sign,				NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	encryptsign,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	decryptverify,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	addsignkey,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	addencryptkey,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	adddecryptkey,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	deletekey,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	gettrustlist,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	listsignatures,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	seterrormode,		NULL,	ZEND_ACC_PUBLIC)
	{NULL, NULL, NULL}
};
#endif  /* ZEND_ENGINE_2 */
static zend_function_entry gnupg_functions[] = {
	PHP_FE(gnupg_init,				NULL)
	PHP_FE(gnupg_keyinfo,			NULL)
	PHP_FE(gnupg_sign,				NULL)
	PHP_FE(gnupg_verify,			NULL)
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
	PHP_FE(gnupg_decryptverify,		NULL)
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

/* {{{ class constants */
static void gnupg_declare_long_constant(const char *const_name, long value TSRMLS_DC){
#if PHP_MAJOR_VERSION > 5 || PHP_MINOR_VERSION >= 1
    zend_declare_class_constant_long(gnupg_class_entry, (char*)const_name, strlen(const_name), value TSRMLS_CC);
#else
    zval *constant = malloc(sizeof(*constant));
    ZVAL_LONG(constant,value);
    INIT_PZVAL(constant);
    zend_hash_update(&gnupg_class_entry->constants_table, (char*)const_name, strlen(const_name)+1, &constant, sizeof(zval*), NULL);
#endif

}
/* }}} */

/* {{{ gnupg_module_entry
 */
zend_module_entry gnupg_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"gnupg",
	gnupg_functions,
	PHP_MINIT(gnupg),
	PHP_MSHUTDOWN(gnupg),
	NULL,		
	NULL,	
	PHP_MINFO(gnupg),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_GNUPG_VERSION,
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_GNUPG
ZEND_GET_MODULE(gnupg)
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(gnupg)
{
	le_gnupg			=	zend_register_list_destructors_ex(gnupg_res_dtor, NULL, "ctx", module_number);
#ifdef ZEND_ENGINE_2
	zend_class_entry ce;
    INIT_CLASS_ENTRY(ce, "gnupg", gnupg_methods);
    ce.create_object    =   gnupg_obj_new;
    gnupg_class_entry   =   zend_register_internal_class(&ce TSRMLS_CC);
    memcpy(&gnupg_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	if (SUCCESS != gnupg_keylistiterator_init()){
		return FAILURE;
	}
    gnupg_declare_long_constant("SIG_MODE_NORMAL",            GPGME_SIG_MODE_NORMAL TSRMLS_DC);
    gnupg_declare_long_constant("SIG_MODE_DETACH",            GPGME_SIG_MODE_DETACH TSRMLS_DC);
    gnupg_declare_long_constant("SIG_MODE_CLEAR",             GPGME_SIG_MODE_CLEAR TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_UNKNOWN",           GPGME_VALIDITY_UNKNOWN TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_UNDEFINED",         GPGME_VALIDITY_UNDEFINED TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_NEVER",             GPGME_VALIDITY_NEVER TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_MARGINAL",          GPGME_VALIDITY_MARGINAL TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_FULL",              GPGME_VALIDITY_FULL TSRMLS_DC);
    gnupg_declare_long_constant("VALIDITY_ULTIMATE",          GPGME_VALIDITY_ULTIMATE TSRMLS_DC);
    gnupg_declare_long_constant("PROTOCOL_OpenPGP",           GPGME_PROTOCOL_OpenPGP TSRMLS_DC);
    gnupg_declare_long_constant("PROTOCOL_CMS",               GPGME_PROTOCOL_CMS TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_VALID",               GPGME_SIGSUM_VALID TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_GREEN",               GPGME_SIGSUM_GREEN TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_RED",                 GPGME_SIGSUM_RED TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_KEY_REVOKED",         GPGME_SIGSUM_KEY_REVOKED TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_KEY_EXPIRED",         GPGME_SIGSUM_KEY_EXPIRED TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_SIG_EXPIRED",         GPGME_SIGSUM_SIG_EXPIRED TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_KEY_MISSING",         GPGME_SIGSUM_KEY_MISSING TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_CRL_MISSING",         GPGME_SIGSUM_CRL_MISSING TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_CRL_TOO_OLD",         GPGME_SIGSUM_CRL_TOO_OLD TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_BAD_POLICY",          GPGME_SIGSUM_BAD_POLICY TSRMLS_DC);
    gnupg_declare_long_constant("SIGSUM_SYS_ERROR",           GPGME_SIGSUM_SYS_ERROR TSRMLS_DC);
	gnupg_declare_long_constant("ERROR_WARNING",              1);
	gnupg_declare_long_constant("ERROR_EXCEPTION",            2);
	gnupg_declare_long_constant("ERROR_SILENT",            	  3);
#endif
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
	php_info_print_table_start();
	php_info_print_table_header(2, "gnupg support", "enabled");
	php_info_print_table_row(2,"GPGme Version",gpgme_check_version(NULL));
	php_info_print_table_row(2,"Extension Version",PHP_GNUPG_VERSION);
	php_info_print_table_end();
}
/* }}} */

/* {{{ callback func for setting the passphrase */

gpgme_error_t passphrase_cb (gnupg_object *intern, const char *uid_hint, const char *passphrase_info,int last_was_bad, int fd){
	char uid[16];
	int idx;
	char *passphrase = NULL;

	if(last_was_bad){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Incorrent passphrase");
		return 1;
	}
	for(idx=0;idx<16;idx++){
		uid[idx] = uid_hint[idx];
	}
	uid[16] = '\0';
	if(zend_hash_find(intern->signkeys,(char *) uid,17,(void **) &passphrase)==FAILURE){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "no passphrase set");
		return 1;
	}
	if(!passphrase){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "no passphrase set");
        return 1;
	}
	
	write (fd, passphrase, strlen(passphrase));
	write (fd, "\n", 1);
	return 0;
}

gpgme_error_t passphrase_decrypt_cb (gnupg_object *intern, const char *uid_hint, const char *passphrase_info,int last_was_bad, int fd){
    char uid[16];
    int idx;
    char *passphrase = NULL;

    if(last_was_bad){
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Incorrent passphrase");
        return 1;
    }
    for(idx=0;idx<16;idx++){
        uid[idx] = uid_hint[idx];
    }
    uid[16] = '\0';
    if(zend_hash_find(intern->decryptkeys,(char *) uid,17,(void **) &passphrase)==FAILURE){
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no passphrase set");
        return 1;
    }
    if(!passphrase){
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "no passphrase set");
        return 1;
    }
    write (fd, passphrase, strlen(passphrase));
    write (fd, "\n", 1);
    return 0;
}

/* }}} */

/* {{{ gnupg_fetchsignatures */
int gnupg_fetchsignatures(gpgme_signature_t gpgme_signatures, zval *sig_arr, zval *main_arr){
	array_init              (main_arr);
    while(gpgme_signatures){
        ALLOC_INIT_ZVAL     (sig_arr);
        array_init          (sig_arr);
        add_assoc_string    (sig_arr,  "fingerprint",  gpgme_signatures->fpr,        1);
        add_assoc_long      (sig_arr,  "validity",     gpgme_signatures->validity    );
        add_assoc_long      (sig_arr,  "timestamp",    gpgme_signatures->timestamp   );
        add_assoc_long      (sig_arr,  "status",       gpgme_signatures->status      );

        add_next_index_zval (main_arr, sig_arr);

        gpgme_signatures    =   gpgme_signatures->next;
    }
	return 1;
}
/* }}} */

/* {{{ proto resource gnupg_init()
 * inits gnupg and returns a resource
*/
PHP_FUNCTION(gnupg_init){
	gnupg_object *intern;
	intern =  emalloc(sizeof(gnupg_object));
	gnupg_res_init(intern);
	ZEND_REGISTER_RESOURCE(return_value,intern,le_gnupg);
}
/* }}} */

/* {{{ proto bool gnupg_setarmor(int armor)
 * turn on/off armor mode
 * 0 = off
 * >0 = on
 * */
PHP_FUNCTION(gnupg_setarmor){
	int		armor;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &armor) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &armor) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

	if(armor > 1){
		armor = 1; /*just to make sure */
	}

	gpgme_set_armor (intern->ctx,armor);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_seterrormode(int errormde) */
PHP_FUNCTION(gnupg_seterrormode){
	int errormode;

	GNUPG_GETOBJ();

	if(this){
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &errormode) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &errormode) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

	switch(errormode){
		case 1:		/* warning */
		case 3:		/* silent */
			intern->errormode = errormode;
			break;
#ifdef ZEND_ENGINE_2
		case 2:		/* exception */
			intern->errormode = errormode;
			break;
#endif
		default:
			GNUPG_ERROR("invalid errormode");
	}
}
/* }}} */

/* {{{ proto bool gnupg_setsignmode(int signmode)
 * sets the mode for signing operations
 */
PHP_FUNCTION(gnupg_setsignmode){
	int			 signmode;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &signmode) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rl", &res, &signmode) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	switch(signmode){
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
}
/* }}} */

/* {{{ proto string gnupg_geterror(void)
 * returns the last errormessage
 */
PHP_FUNCTION(gnupg_geterror){
	GNUPG_GETOBJ();
	
	if(!this){
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
	}
	if(!intern->errortxt){
		RETURN_FALSE;
	}else{
		RETURN_STRINGL(intern->errortxt, strlen(intern->errortxt), 1);
	}
}
/* }}} */

/* {{{ proto int gnupg_getprotocol(void)
 * returns the currently used pgp-protocol.
 * atm only OpenPGP is supported
 */
PHP_FUNCTION(gnupg_getprotocol){
	RETURN_LONG(GPGME_PROTOCOL_OpenPGP);
}

/* }}} */

/* {{{ proto array gnupg_keyinfo(string pattern)
 * returns an array with informations about all keys, that matches the given pattern
 */
PHP_FUNCTION(gnupg_keyinfo)
{
	char		*searchkey = NULL;
	int			*searchkey_len;
	zval		*subarr;
	zval		*userid;
	zval		*userids;
	zval		*subkey;
	zval		*subkeys;
	
	gpgme_key_t		gpgme_key;
	gpgme_subkey_t	gpgme_subkey;
	gpgme_user_id_t gpgme_userid;

	GNUPG_GETOBJ();

	if(this){	
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE){
			return;
		}
	}else{
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &searchkey, &searchkey_len) == FAILURE){
			return;
		}
		ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
	}
	if((intern->err = gpgme_op_keylist_start(intern->ctx, searchkey, 0)) != GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not init keylist");
		return;
	}
	
	array_init(return_value);
	
	while(!(intern->err = gpgme_op_keylist_next(intern->ctx, &gpgme_key))){
		ALLOC_INIT_ZVAL		(subarr);
		array_init			(subarr);
		
		ALLOC_INIT_ZVAL		(subkeys);
		array_init			(subkeys);
		
		ALLOC_INIT_ZVAL		(userids);
		array_init			(userids);

		add_assoc_bool      (subarr,	"disabled",		gpgme_key->disabled		);
		add_assoc_bool      (subarr,	"expired",		gpgme_key->expired		);
		add_assoc_bool      (subarr,	"revoked",		gpgme_key->revoked		);
		add_assoc_bool      (subarr,	"is_secret",	gpgme_key->secret		);
		add_assoc_bool      (subarr,	"can_sign",		gpgme_key->can_sign		);
		add_assoc_bool      (subarr,	"can_encrypt",	gpgme_key->can_encrypt	);

		gpgme_userid	=	gpgme_key->uids;
		while(gpgme_userid){
			ALLOC_INIT_ZVAL		(userid);
			array_init			(userid);
			
			add_assoc_string    (userid,	"name",		gpgme_userid->name,		1);
			add_assoc_string	(userid,	"comment",	gpgme_userid->comment,	1);
			add_assoc_string    (userid,	"email",	gpgme_userid->email,	1);
			add_assoc_string    (userid,	"uid",		gpgme_userid->uid,		1);
			
			add_assoc_bool      (userid,	"revoked",	gpgme_userid->revoked	);
			add_assoc_bool      (userid,	"invalid",	gpgme_userid->invalid	);
			
			add_next_index_zval	(userids, userid);
			gpgme_userid	=	gpgme_userid->next;
		}
		
		add_assoc_zval			(subarr,	"uids",	userids);
		
		gpgme_subkey		=	gpgme_key->subkeys;
		while(gpgme_subkey){
			ALLOC_INIT_ZVAL		(subkey);
			array_init			(subkey);
			
			if(gpgme_subkey->fpr){
				add_assoc_string    (subkey,	"fingerprint",	gpgme_subkey->fpr,		1);
			}
			
			add_assoc_string    (subkey,	"keyid",		gpgme_subkey->keyid,		1);
			
			add_assoc_long	    (subkey,	"timestamp",	gpgme_subkey->timestamp		);
			add_assoc_long	    (subkey,	"expires",		gpgme_subkey->expires		);
			add_assoc_bool	    (subkey,	"is_secret",	gpgme_subkey->secret		);
			add_assoc_bool	    (subkey,	"invalid",		gpgme_subkey->invalid		);
			add_assoc_bool	    (subkey,	"can_encrypt",	gpgme_subkey->can_encrypt	);
			add_assoc_bool	    (subkey,	"can_sign",		gpgme_subkey->can_sign		);
			add_assoc_bool	    (subkey,	"disabled",		gpgme_subkey->disabled		);
			add_assoc_bool	    (subkey,	"expired",		gpgme_subkey->expired		);
			add_assoc_bool	    (subkey,	"revoked",		gpgme_subkey->revoked		);

			add_next_index_zval	(subkeys, subkey);
			gpgme_subkey	=	gpgme_subkey->next;
		}
		
		add_assoc_zval		(subarr,	"subkeys",	subkeys);

		add_next_index_zval	(return_value, subarr);
		gpgme_key_unref		(gpgme_key);
	}
	return;
}
/* }}} */

/* {{{ proto bool gnupg_addsignkey(string key) */
PHP_FUNCTION(gnupg_addsignkey){
    char    *key_id = NULL;
    int     key_id_len;
	char	*passphrase = NULL;
	int		passphrase_len;

    gpgme_key_t         gpgme_key;
	gpgme_subkey_t		gpgme_subkey;

    GNUPG_GETOBJ();

    if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|s", &res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
    if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed");
		return;
    }
	if(passphrase){
		gpgme_subkey	=	gpgme_key->subkeys;
		while(gpgme_subkey){
			if(gpgme_subkey->can_sign == 1){
				zend_hash_add(intern->signkeys, (char *) gpgme_subkey->keyid, (uint) strlen(gpgme_subkey->keyid)+1, passphrase, (uint) passphrase_len+1, NULL);
			}	
			gpgme_subkey	=	gpgme_subkey->next;
		}
	}
    if((intern->err = gpgme_signers_add(intern->ctx, gpgme_key))!=GPG_ERR_NO_ERROR){
        GNUPG_ERR("could not add signer");
    }else{
		RETVAL_TRUE;
	}
	gpgme_key_unref(gpgme_key);
}
/* }}} */

/* {{{ proto bool gnupg_adddecryptkey(string key) */
PHP_FUNCTION(gnupg_adddecryptkey){
    char    *key_id = NULL;
    int     key_id_len;
    char    *passphrase = NULL;
    int     passphrase_len;

    gpgme_key_t         gpgme_key;
    gpgme_subkey_t      gpgme_subkey;

    GNUPG_GETOBJ();

    if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rss", &res, &key_id, &key_id_len, &passphrase, &passphrase_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
    if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed");
		return;
    }
    gpgme_subkey    =   gpgme_key->subkeys;
    while(gpgme_subkey){
    	if(gpgme_subkey->secret == 1){
        	zend_hash_add(intern->decryptkeys, (char *) gpgme_subkey->keyid, (uint) strlen(gpgme_subkey->keyid)+1, passphrase, (uint) passphrase_len+1, NULL);
		}
        gpgme_subkey    =   gpgme_subkey->next;
	}
	gpgme_key_unref(gpgme_key);
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_addencryptkey(string key) */
PHP_FUNCTION(gnupg_addencryptkey){
    char    *key_id = NULL;
    int     key_id_len;

    gpgme_key_t gpgme_key = NULL;

    GNUPG_GETOBJ();

    if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key_id, &key_id_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &key_id, &key_id_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

    if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 0)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed");
		return;
    }
    intern->encryptkeys = erealloc(intern->encryptkeys, sizeof(intern->encryptkeys) * (intern->encrypt_size + 1));
	intern->encryptkeys[intern->encrypt_size] = gpgme_key;
	intern->encrypt_size++;
	intern->encryptkeys[intern->encrypt_size] = NULL;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_clearsignkeys){
	GNUPG_GETOBJ();	

	if(!this){
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
	}

	gpgme_signers_clear	(intern->ctx);
	zend_hash_clean(intern->signkeys);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearencryptkeys(void)
 * removes all keys which are set for encryption
 */
PHP_FUNCTION(gnupg_clearencryptkeys){
	GNUPG_GETOBJ();

	if(!this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	gnupg_free_encryptkeys(intern);	

    RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkeys(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_cleardecryptkeys){
    GNUPG_GETOBJ();

    if(!this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
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
PHP_FUNCTION(gnupg_sign){
    char    *value = NULL;
    int     value_len;

    char    *userret;
    size_t  ret_size;

    gpgme_data_t in, out;
	gpgme_sign_result_t result;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

    gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
    if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
		return;
    }
    if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
    }
    if((intern->err = gpgme_op_sign(intern->ctx, in, out, intern->signmode))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("data signing failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
    }
	result		=	gpgme_op_sign_result (intern->ctx);
	if(result->invalid_signers){
		GNUPG_ERR("invalid signers found");
		gpgme_data_release(in);
        gpgme_data_release(out);
		return;
	}
	if(!result->signatures){
		GNUPG_ERR("no signature in result");
		gpgme_data_release(in);
        gpgme_data_release(out);
        return;
	}
    userret     =   gpgme_data_release_and_get_mem(out,&ret_size);
    if(ret_size < 1){
		RETVAL_FALSE;
    }else{
		RETVAL_STRINGL	(userret,ret_size,1);
	}
    gpgme_data_release  (in);
    free                (out);
	free				(userret);
}

/* }}} */

/* {{{ proto string gnupg_encrypt(string text)
 * encrypts the given text with the key, which was set with setencryptkey before
 * and returns the encrypted text
 */
PHP_FUNCTION(gnupg_encrypt){
	char *value = NULL;
	int value_len;
	char *userret = NULL;
	size_t ret_size;

	gpgme_data_t in, out;
	gpgme_encrypt_result_t result;

	GNUPG_GETOBJ();	
	
	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if(!intern->encryptkeys){
		GNUPG_ERR("no key for encryption set");
		return;
	}
	if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could no create in-data buffer");
		return;
	}
	if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if((intern->err = gpgme_op_encrypt(intern->ctx, intern->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out))!=GPG_ERR_NO_ERROR){
        GNUPG_ERR("encrypt failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
    }
	result		=	gpgme_op_encrypt_result (intern->ctx);
	if (result->invalid_recipients){
		GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
        gpgme_data_release(out);
		return;
	}
	userret		=	gpgme_data_release_and_get_mem(out,&ret_size);
	gpgme_data_release	(in);
    free                (out);
	RETVAL_STRINGL		(userret,ret_size,1);
	free				(userret);
	if(ret_size < 1){
		RETURN_FALSE;
	}
}
/* }}} */

/* {{{ proto string gnupg_encrypt_sign(string text)
 * encrypts and signs the given text with the keys, which weres set with setencryptkey and setsignkey before
 * and returns the encrypted text
 */
PHP_FUNCTION(gnupg_encryptsign){
    char *value = NULL;
    int value_len;
    char *userret = NULL;
    size_t ret_size;

    gpgme_data_t in, out;
	gpgme_encrypt_result_t result;
	gpgme_sign_result_t sign_result;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &value, &value_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

    if(!intern->encryptkeys){
		GNUPG_ERR("no key for encryption set");
		return;
    }
	gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
    if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
		return;
    }
    if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
    }
	if((intern->err = gpgme_op_encrypt_sign(intern->ctx, intern->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("encrypt-sign failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}

	result      =   gpgme_op_encrypt_result (intern->ctx);
    if (result->invalid_recipients){
        GNUPG_ERR("Invalid recipient encountered");
		gpgme_data_release(in);
        gpgme_data_release(out);
		return;
    }

	sign_result =	gpgme_op_sign_result (intern->ctx);
	if(sign_result->invalid_signers){
        GNUPG_ERR("invalid signers found");
		gpgme_data_release(in);
        gpgme_data_release(out);
		return;
    }
    if(!sign_result->signatures){
        GNUPG_ERR("could not find a signature");
		gpgme_data_release(in);
        gpgme_data_release(out);
        return;
    }
	
    userret     =   gpgme_data_release_and_get_mem(out,&ret_size);
    gpgme_data_release  (in);
    free (out);
	RETVAL_STRINGL		(userret,ret_size,1);
	free (userret);
	if(ret_size < 1){
        RETURN_FALSE;
    }
}
/* }}} */

/* {{{ proto array gnupg_verify(string text, string signature [, string &plaintext])
 * verifies the given clearsigned text and returns information about the result in an array
 */
PHP_FUNCTION(gnupg_verify){
	char	*text;
	int		text_len;
	zval	*signature = NULL;	/* use zval here because the signature can be binary */
	zval	*plaintext = NULL;
	zval	*sig_arr;

	char	*gpg_plain;
	size_t	gpg_plain_len;

	gpgme_data_t			gpgme_text, gpgme_sig;
	gpgme_verify_result_t	gpgme_result;
	gpgme_signature_t		gpgme_signatures;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|z", &text, &text_len, &signature, &plaintext) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz|z", &res, &text, &text_len, &signature, &plaintext) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if(Z_STRVAL_P(signature)){
		if((intern->err = gpgme_data_new_from_mem (&gpgme_sig, Z_STRVAL_P(signature), Z_STRLEN_P(signature), 0))!=GPG_ERR_NO_ERROR){
			GNUPG_ERR("could not create signature-databuffer");
			return;
		}
		if((intern->err = gpgme_data_new (&gpgme_text))!=GPG_ERR_NO_ERROR){
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			return;
		}
	}else{
		/*	no separate signature was passed
		*	so we assume that it is a clearsigned message
		*	text no becomes the signature
		*	creating the text-databuffer is still needed
		*/
		if((intern->err = gpgme_data_new_from_mem (&gpgme_sig, text, text_len, 0))!=GPG_ERR_NO_ERROR){
    	    GNUPG_ERR("could not create signature-databuffer");
			return;
	    }
		if((intern->err = gpgme_data_new_from_mem (&gpgme_text, NULL, 0, 0))!=GPG_ERR_NO_ERROR){
			GNUPG_ERR("could not create text-databuffer");
			gpgme_data_release(gpgme_sig);
			gpgme_data_release(gpgme_text);
			return;
		}
	}
	if((intern->err = gpgme_op_verify (intern->ctx, gpgme_sig, NULL, gpgme_text))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("verify failed");
		gpgme_data_release(gpgme_sig);
		gpgme_data_release(gpgme_text);
		return;
	}
	gpgme_result			=   gpgme_op_verify_result (intern->ctx);
    if(!gpgme_result->signatures){
        GNUPG_ERR           ("no signature found");
    }else{
		gnupg_fetchsignatures	(gpgme_result->signatures,sig_arr,return_value);
    	gpg_plain			=	gpgme_data_release_and_get_mem(gpgme_text,&gpg_plain_len);
	    if(plaintext){
    	    ZVAL_STRINGL        (plaintext,gpg_plain,gpg_plain_len,1);
	    }
	}
    gpgme_data_release      (gpgme_sig);
	free					(gpgme_text);
	free					(gpg_plain);
}
/* }}} */

/* {{{ proto string gnupg_decrypt(string enctext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decrypt){
	char	*enctxt;
	int		enctxt_len;

	char    *userret;
    size_t  ret_size;

	gpgme_data_t			in, out;
	gpgme_decrypt_result_t	result;
	
	GNUPG_GETOBJ();  

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &enctxt, &enctxt_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &enctxt, &enctxt_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

	gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_decrypt_cb, intern);
	
	if((intern->err = gpgme_data_new_from_mem (&in, enctxt, enctxt_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
	}
	if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
	}
	if((intern->err = gpgme_op_decrypt (intern->ctx, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("decrypt failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}
	result = gpgme_op_decrypt_result (intern->ctx);
	if (result->unsupported_algorithm){
		GNUPG_ERR("unsupported algorithm");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
	}	
	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	gpgme_data_release		(in);
	free					(out);
	RETVAL_STRINGL			(userret,ret_size,1);
	free					(userret);
	if(ret_size < 1){
		RETVAL_FALSE;
	}
}
/* }}} */

/* {{{ proto string gnupg_decryptverify(string enctext, string &plaintext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decryptverify){
    char    *enctxt;
    int     enctxt_len;
	zval	*plaintext;
	zval    *sig_arr;

    char    *userret;
    size_t  ret_size;

    gpgme_data_t            in, out;
	gpgme_decrypt_result_t	decrypt_result;
	gpgme_verify_result_t	verify_result;
	gpgme_signature_t       gpg_signatures;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &enctxt, &enctxt_len, &plaintext) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rsz", &res, &enctxt, &enctxt_len, &plaintext) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

    gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_decrypt_cb, intern);

    if((intern->err = gpgme_data_new_from_mem (&in, enctxt, enctxt_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
    }
    if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
		gpgme_data_release(in);
		return;
    }
    if((intern->err = gpgme_op_decrypt_verify (intern->ctx, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("decrypt-verify failed");
		gpgme_data_release(in);
		gpgme_data_release(out);
		return;
    }
    userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	ZVAL_STRINGL			(plaintext,userret,ret_size,1);
	free					(userret);
	decrypt_result		=	gpgme_op_decrypt_result (intern->ctx);
	if (decrypt_result->unsupported_algorithm){
		GNUPG_ERR			("unsupported algorithm");
		gpgme_data_release(in);
		free(out);
        return;
	}
	verify_result       =   gpgme_op_verify_result (intern->ctx);
	if(!verify_result->signatures){
        GNUPG_ERR           ("no signature found");
		gpgme_data_release(in);
		free(out);
        return;
    }
	gnupg_fetchsignatures   (verify_result->signatures,sig_arr,return_value);
    gpgme_data_release      (in);
    free                    (out);
}
/* }}} */

/* {{{ proto string gnupg_export(string pattern)
 * exports the first public key which matches against the given pattern
 */
PHP_FUNCTION(gnupg_export){
	char	*searchkey = NULL;
    int     *searchkey_len;
	char	*userret;
    size_t	ret_size;

	gpgme_data_t  out;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &searchkey, &searchkey_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create data buffer");
		return;
	}
	if((intern->err = gpgme_op_export (intern->ctx, searchkey, 0, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("export failed");
		gpgme_data_release(out);
		return;
	}
	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	RETVAL_STRINGL          (userret,ret_size,1);
	if(ret_size < 1){
		RETVAL_FALSE;
	}
	free(userret);
	free(out);
}
/* }}} */

/* {{{ proto array gnupg_import(string key)
 * imports the given key and returns a status-array
*/
PHP_FUNCTION(gnupg_import){
	char			*importkey = NULL;
	int				importkey_len;

	gpgme_data_t	in;
	gpgme_import_result_t result;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &importkey, &importkey_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &importkey, &importkey_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if((intern->err = gpgme_data_new_from_mem (&in, importkey, importkey_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
		return;
	}
	if((intern->err = gpgme_op_import(intern->ctx,in))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("import failed");
		gpgme_data_release(in);
		return;
	}
	gpgme_data_release(in);
	result = gpgme_op_import_result (intern->ctx);

	array_init				(return_value);
    add_assoc_long          (return_value,  "imported",     	result->imported);
	add_assoc_long			(return_value,	"unchanged",		result->unchanged);
	add_assoc_long			(return_value,	"newuserids",		result->new_user_ids);
	add_assoc_long			(return_value,	"newsubkeys",		result->new_sub_keys);
	add_assoc_long			(return_value,	"secretimported",	result->secret_imported);
	add_assoc_long			(return_value,	"secretunchanged",	result->secret_unchanged);
	add_assoc_long			(return_value,	"newsignatures",	result->new_signatures);
	add_assoc_long			(return_value,	"skippedkeys",		result->skipped_new_keys);
	add_assoc_string		(return_value,	"fingerprint",		result->imports->fpr,	1);
}
/* }}} */

/* {{{ proto book gnupg_deletekey(string key)
*	deletes a key from the keyring
*/
PHP_FUNCTION(gnupg_deletekey){
	char	*key;
	int		key_len;
	int		allow_secret = 0;

	gpgme_key_t	gpgme_key;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &key, &key_len, &allow_secret) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &key, &key_len, &allow_secret) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

	if((intern->err = gpgme_get_key(intern->ctx, key, &gpgme_key, 0)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed");
		return;
    }
	if((intern->err = gpgme_op_delete(intern->ctx,gpgme_key,allow_secret))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("delete failed");
		RETVAL_FALSE;
	}else{
		RETVAL_TRUE;
	}
	gpgme_key_unref(gpgme_key);
}
/* }}} */

/* {{{ proto array gnupg_gettrustlist(string pattern)
* searching for trust items which match PATTERN
*/
PHP_FUNCTION(gnupg_gettrustlist){
	char *pattern;
	int	pattern_len;
	zval *sub_arr;

	gpgme_trust_item_t item;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &pattern, &pattern_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &pattern, &pattern_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if((intern->err = gpgme_op_trustlist_start (intern->ctx, pattern, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not start trustlist");
		return;
	}
	array_init(return_value);
	while (!(intern->err = gpgme_op_trustlist_next (intern->ctx, &item))){
		ALLOC_INIT_ZVAL 	    (sub_arr);
        array_init          	(sub_arr);

		add_assoc_long			(sub_arr,	"level",		item->level			);
		add_assoc_long      	(sub_arr,	"type",			item->type			);
		add_assoc_string		(sub_arr,	"keyid",		item->keyid,		1);
		add_assoc_string    	(sub_arr,   "ownertrust",	item->owner_trust,	1);
		add_assoc_string    	(sub_arr,   "validity",		item->validity,		1);
		add_assoc_string    	(sub_arr,   "name",			item->name,			1);
		gpgme_trust_item_unref	(item);
		add_next_index_zval		(return_value, sub_arr);		
	}
}
/* }}} */

/* {{{ proto array gnupg_listsignatures(string keyid) */
PHP_FUNCTION(gnupg_listsignatures){
	char	*keyid;
	char	keyid_len;

	zval	*sub_arr;
	zval	*sig_arr;

	gpgme_key_t		gpgme_key;
	gpgme_subkey_t	gpgme_subkey;
	gpgme_user_id_t	gpgme_userid;
	gpgme_key_sig_t	gpgme_signature;

	GNUPG_GETOBJ();

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &keyid, &keyid_len) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs", &res, &keyid, &keyid_len) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if((intern->err = gpgme_set_keylist_mode(intern->ctx,GPGME_KEYLIST_MODE_SIGS))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not switch to sigmode");
		return;
	}
	if((intern->err = gpgme_get_key(intern->ctx, keyid, &gpgme_key, 0)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed. given key not unique?");
		return;
    }
	if(!gpgme_key->uids){
		GNUPG_ERR("no uids found");
		gpgme_key_unref(gpgme_key);
		return;
	}
	array_init(return_value);
	gpgme_userid	=	gpgme_key->uids;
	while(gpgme_userid){
		ALLOC_INIT_ZVAL         (sub_arr);
        array_init              (sub_arr);
		gpgme_signature = gpgme_userid->signatures;
		while(gpgme_signature){
			ALLOC_INIT_ZVAL		(sig_arr);
	        array_init			(sig_arr);

			add_assoc_string	(sig_arr,	"uid",		gpgme_signature->uid,		1);				
			add_assoc_string    (sig_arr,   "name",     gpgme_signature->name,      1);
			add_assoc_string    (sig_arr,   "email",    gpgme_signature->email,     1);
			add_assoc_string    (sig_arr,   "comment",  gpgme_signature->comment,   1);
			add_assoc_long		(sig_arr,	"expires",	gpgme_signature->expires	);
			add_assoc_bool		(sig_arr,	"revoked",	gpgme_signature->revoked	);
			add_assoc_bool      (sig_arr,   "expired",	gpgme_signature->expired	);
			add_assoc_bool      (sig_arr,   "invalid",	gpgme_signature->invalid	);
			add_assoc_zval		(sub_arr,gpgme_signature->keyid,sig_arr);
			gpgme_signature	=	gpgme_signature->next;
		}
		add_assoc_zval		(return_value,gpgme_userid->uid,sub_arr);
		gpgme_userid	=	gpgme_userid->next;
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
