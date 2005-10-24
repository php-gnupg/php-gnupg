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

#ifdef ZEND_ENGINE_2
static zend_object_handlers gnupg_object_handlers;
#endif

/* {{{ defs */
#define GNUPG_GETOBJ() \
	zval *this = getThis(); \
    gnupg_object *intern; \
	if(this){ \
		ze_gnupg_object *obj    =   (ze_gnupg_object*) zend_object_store_get_object(this TSRMLS_CC); \
		intern = obj->gnupg_ptr; \
	    if(!intern){ \
    	    php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
        	RETURN_FALSE; \
	    } \
	}
#define GNUPG_ERR(error) \
    if(intern){ \
		intern->errortxt = (char*)error; \
    }else{ \
        php_error_docref(NULL TSRMLS_CC, E_WARNING, (char*)error); \
    } \
    RETURN_FALSE;
/* }}} */

/* {{{ free encryptkeys */
static void gnupg_free_encryptkeys(gnupg_object *intern TSRMLS_DC){
	if(intern){
		if(intern->encrypt_size > 0){
			gpgme_key_release   (*intern->encryptkeys);
            erealloc(intern->encryptkeys,0);
        }
        intern->encryptkeys = NULL;
        intern->encrypt_size = 0;
	}
}
/* }}} */
/* {{{ free_resource */
static void gnupg_free_resource_ptr(gnupg_object *intern TSRMLS_DC){
    int idx;
    if(intern){
        if(intern->ctx){
            gpgme_signers_clear (intern->ctx);
            gpgme_release       (intern->ctx);
            intern->ctx = NULL;
        }
        zval_dtor(&intern->passphrase);
        gnupg_free_encryptkeys(intern);
        efree(intern);
    }
}
/* }}} */

/* {{{ gnupg_res_dtor */
static void gnupg_res_dtor(zend_rsrc_list_entry *rsrc TSRMLS_DC) {
    gnupg_object *intern;
    intern = (gnupg_object *) rsrc->ptr;
    gnupg_free_resource_ptr(intern TSRMLS_CC);
}
/* }}} */

#ifdef ZEND_ENGINE_2
/* {{{ free_storage */
static void gnupg_object_free_storage(void *object TSRMLS_DC){
	ze_gnupg_object * intern = (ze_gnupg_object *) object;
	if(!intern){
		return;
	}
	if(intern->gnupg_ptr){
		gnupg_free_resource_ptr(intern->gnupg_ptr TSRMLS_CC);
	}
	intern->gnupg_ptr = NULL;
	if(intern->zo.properties){
		zend_hash_destroy(intern->zo.properties);
		FREE_HASHTABLE(intern->zo.properties);
	}
	efree(intern);
}
/* }}} */


/* {{{ objects_new */
zend_object_value gnupg_objects_new(zend_class_entry *class_type TSRMLS_DC){
	ze_gnupg_object *intern;
	zval *tmp;
	zend_object_value retval;
	gnupg_object *gnupg_ptr;
	ze_gnupg_object *ze_obj;
	gpgme_ctx_t ctx;
	
	intern	=	emalloc(sizeof(ze_gnupg_object));
	intern->zo.ce = class_type;
	intern->zo.in_get = 0;
	intern->zo.in_set = 0;
	intern->zo.properties = NULL;
	
	ALLOC_HASHTABLE(intern->zo.properties);
	zend_hash_init(intern->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);
	zend_hash_copy(intern->zo.properties, &class_type->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
	
	retval.handle	=	zend_objects_store_put(intern,NULL,(zend_objects_free_object_storage_t) gnupg_object_free_storage,NULL TSRMLS_CC);
	retval.handlers	=	(zend_object_handlers *) & gnupg_object_handlers;

    gpgme_new(&ctx);
    gpgme_set_armor (ctx,1);
    gnupg_ptr  =   emalloc(sizeof(gnupg_object));
    gnupg_ptr->ctx         = ctx;
    gnupg_ptr->encryptkeys = NULL;
	gnupg_ptr->encrypt_size= 0;
    gnupg_ptr->signmode    = GPGME_SIG_MODE_CLEAR;
    intern->gnupg_ptr	   = gnupg_ptr;
	
	return retval;
}
/* }}} */

/* {{{ methodlist gnupg */
static zend_function_entry gnupg_methods[] = {
	ZEND_ME(gnupg,	keyinfo,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	verify,				NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	geterror,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	setpassphrase,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	clearsignkeys,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg,	clearencryptkeys,	NULL,	ZEND_ACC_PUBLIC)
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
	{NULL, NULL, NULL}
};
#endif  /* ZEND_ENGINE_2 */
static zend_function_entry gnupg_functions[] = {
	PHP_FE(gnupg_init,				NULL)
	PHP_FE(gnupg_keyinfo,			NULL)
	PHP_FE(gnupg_setpassphrase,		NULL)
	PHP_FE(gnupg_sign,				NULL)
	PHP_FE(gnupg_verify,			NULL)
	PHP_FE(gnupg_clearsignkeys,		NULL)
	PHP_FE(gnupg_clearencryptkeys,	NULL)
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
	"0.5", 
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

    ce.create_object    =   gnupg_objects_new;
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
	php_info_print_table_end();
}
/* }}} */

/* {{{ callback func for setting the passphrase
 */
gpgme_error_t passphrase_cb (gnupg_object *intern, const char *uid_hint, const char *passphrase_info,int last_was_bad, int fd){
	if(last_was_bad){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Incorrent passphrase");
		return 1;
	}
	if(Z_STRLEN(intern->passphrase) < 1){
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "no passphrase set");
		return 1;
	}
	write (fd, Z_STRVAL(intern->passphrase), Z_STRLEN(intern->passphrase));
	write (fd, "\n", 1);
	return 0;
	
}
/* }}} */


/* {{{ proto resource gnupg_init()
 * inits gnupg and returns a resource
*/
PHP_FUNCTION(gnupg_init){
	gnupg_object *intern;

	intern	=	emalloc(sizeof(gnupg_object));
	gpgme_new	(&intern->ctx);	
	intern->signmode = GPGME_SIG_MODE_CLEAR;
	intern->encryptkeys = NULL;
	gpgme_set_armor	(intern->ctx,1);
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
	zval	*res;

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

/* {{{ proto bool gnupg_setsignmode(int signmode)
 * sets the mode for signing operations
 */
PHP_FUNCTION(gnupg_setsignmode){
	int			 signmode;
	zval		*res;

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
			RETURN_TRUE;
			break;
		default:
			GNUPG_ERR("invalid signmode");
			break;
	}
}
/* }}} */

/* {{{ proto bool gnupg_setpassphrase(string passphrase)
 * sets the passphrase for all next operations
 */
PHP_FUNCTION(gnupg_setpassphrase){
	zval *tmp;
	zval *res;

	GNUPG_GETOBJ();	

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &tmp) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rz", &res, &tmp) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }

	intern->passphrase = *tmp;
	zval_copy_ctor(&intern->passphrase);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto string gnupg_geterror(void)
 * returns the last errormessage
 */
PHP_FUNCTION(gnupg_geterror){
	zval	*res;

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
	int			idx;
	zval		*subarr;
	zval		*userid;
	zval		*userids;
	zval		*subkey;
	zval		*subkeys;
	zval		*res;
	
	gpgme_key_t		gpgkey;
	gpgme_subkey_t	gpgsubkey;
	gpgme_user_id_t gpguserid;

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
	}
	
	array_init(return_value);
	
	while(!(intern->err = gpgme_op_keylist_next(intern->ctx, &gpgkey))){
		ALLOC_INIT_ZVAL		(subarr);
		array_init			(subarr);
		
		ALLOC_INIT_ZVAL		(subkeys);
		array_init			(subkeys);
		
		ALLOC_INIT_ZVAL		(userids);
		array_init			(userids);

		add_assoc_bool      (subarr,	"disabled",		gpgkey->disabled	);
		add_assoc_bool      (subarr,	"expired",		gpgkey->expired		);
		add_assoc_bool      (subarr,	"revoked",		gpgkey->revoked		);
		add_assoc_bool      (subarr,	"is_secret",	gpgkey->secret		);
		add_assoc_bool      (subarr,	"can_sign",		gpgkey->can_sign	);
		add_assoc_bool      (subarr,	"can_encrypt",	gpgkey->can_encrypt	);
		
		for(idx = 1, gpguserid = gpgkey->uids; gpguserid; idx++, gpguserid = gpguserid->next){
			ALLOC_INIT_ZVAL		(userid);
			array_init			(userid);
			
			add_assoc_string    (userid,	"name",		gpguserid->name,	1);
			add_assoc_string	(userid,	"comment",	gpguserid->comment,	1);
			add_assoc_string    (userid,	"email",	gpguserid->email,	1);
			add_assoc_string    (userid,	"uid",		gpguserid->uid,		1);
			
			add_assoc_bool      (userid,	"revoked",	gpguserid->revoked	);
			add_assoc_bool      (userid,	"invalid",	gpguserid->invalid	);
			
			add_next_index_zval	(userids, userid);
		}
		
		add_assoc_zval			(subarr,	"uids",	userids);

		for(idx = 1, gpgsubkey = gpgkey->subkeys; gpgsubkey; idx++, gpgsubkey = gpgsubkey->next){
			ALLOC_INIT_ZVAL		(subkey);
			array_init			(subkey);
			
			if(gpgsubkey->fpr){
				add_assoc_string    (subkey,	"fingerprint",	gpgsubkey->fpr,		1);
			}
			
			add_assoc_string    (subkey,	"keyid",		gpgsubkey->keyid,		1);
			
			add_assoc_long	    (subkey,	"timestamp",	gpgsubkey->timestamp	);
			add_assoc_long	    (subkey,	"expires",		gpgsubkey->expires		);
			add_assoc_bool	    (subkey,	"is_secret",	gpgsubkey->secret		);
			add_assoc_bool	    (subkey,	"invalid",		gpgsubkey->invalid		);
			add_assoc_bool	    (subkey,	"can_encrypt",	gpgsubkey->can_encrypt	);
			add_assoc_bool	    (subkey,	"can_sign",		gpgsubkey->can_sign		);
			add_assoc_bool	    (subkey,	"disabled",		gpgsubkey->disabled		);
			add_assoc_bool	    (subkey,	"expired",		gpgsubkey->expired		);
			add_assoc_bool	    (subkey,	"revoked",		gpgsubkey->revoked		);

			add_next_index_zval	(subkeys, subkey);
		}
		
		add_assoc_zval		(subarr,	"subkeys",	subkeys);

		add_next_index_zval	(return_value, subarr);
	}
	return;
}
/* }}} */

/* {{{ proto bool gnupg_addsignkey(string key) */
PHP_FUNCTION(gnupg_addsignkey){
    char    *key_id = NULL;
    int     key_id_len;
    zval    *res;

    gpgme_sign_result_t result;
    gpgme_key_t         gpgme_key;

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
    if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR){
        GNUPG_ERR("get_key failed");
    }
    if((intern->err = gpgme_signers_add(intern->ctx, gpgme_key))!=GPG_ERR_NO_ERROR){
        GNUPG_ERR("could not add signer");
    }
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_addencryptkey(string key) */
PHP_FUNCTION(gnupg_addencryptkey){
    char    *key_id = NULL;
    int     key_id_len;
    zval    *res;

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
    }
    intern->encryptkeys = erealloc(intern->encryptkeys, sizeof(intern->encryptkeys) * (intern->encrypt_size + 1));
	intern->encryptkeys[intern->encrypt_size] = gpgme_key;
	intern->encrypt_size++;
	intern->encryptkeys[intern->encrypt_size] = NULL;
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkey(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_clearsignkeys){
	zval	*res;

	GNUPG_GETOBJ();	

	if(!this){
		if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &res) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
	}

	gpgme_signers_clear	(intern->ctx);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearencryptkey(void)
 * removes all keys which are set for encryption
 */
PHP_FUNCTION(gnupg_clearencryptkeys){
	zval	*res;

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

/* {{{ proto string gnupg_sign(string text)
 * signs the given test with the key, which was set with setsignerkey before
 * and returns the signed text
 * the signmode depends on gnupg_setsignmode
 */
PHP_FUNCTION(gnupg_sign){
    char    *value = NULL;
    int     value_len;

    char    *userret;
    int     ret_size;

	zval	*res;

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
    }
    if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
    }
    if((intern->err = gpgme_op_sign(intern->ctx, in, out, intern->signmode))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("data signing failed");
    }
	result		=	gpgme_op_sign_result (intern->ctx);
	if(result->invalid_signers){
		GNUPG_ERR("invalid signers found");
	}
	if(!result->signatures){
		GNUPG_ERR("no signature in result");
	}
    userret     =   gpgme_data_release_and_get_mem(out,&ret_size);
    if(ret_size < 1){
        RETURN_FALSE;
    }
    gpgme_data_release  (in);
    free                (out);
    RETURN_STRINGL      (userret,ret_size,1);
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
	int ret_size;
	zval *res;

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
	}
	if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could no create in-data buffer");
	}
	if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
	}
	if((intern->err = gpgme_op_encrypt(intern->ctx, intern->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out))!=GPG_ERR_NO_ERROR){
        GNUPG_ERR("encrypt failed");
    }
	result		=	gpgme_op_encrypt_result (intern->ctx);
	if (result->invalid_recipients){
		GNUPG_ERR("Invalid recipient encountered");
	}
	userret		=	gpgme_data_release_and_get_mem(out,&ret_size);
	gpgme_data_release	(in);
    free                (out);
	if(ret_size < 1){
		RETURN_FALSE;
	}
	RETURN_STRINGL      (userret,ret_size,1);
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
    int ret_size;
	zval *res;

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
    }
	gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
    if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
    }
    if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
    }
	if((intern->err = gpgme_op_encrypt_sign(intern->ctx, intern->encryptkeys, GPGME_ENCRYPT_ALWAYS_TRUST, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("encrypt-sign failed");
	}

	result      =   gpgme_op_encrypt_result (intern->ctx);
    if (result->invalid_recipients){
        GNUPG_ERR("Invalid recipient encountered");
    }

	sign_result =	gpgme_op_sign_result (intern->ctx);
	if(sign_result->invalid_signers){
        GNUPG_ERR("invalid signers found");
    }
    if(!sign_result->signatures || sign_result->signatures->next){
        GNUPG_ERR("unexpected numbers of signatures created");
    }
	
    userret     =   gpgme_data_release_and_get_mem(out,&ret_size);
    gpgme_data_release  (in);
    free (out);
	if(ret_size < 1){
        RETURN_FALSE;
    }
    RETURN_STRINGL      (userret,ret_size,1);
}
/* }}} */

/* {{{ proto array gnupg_verify(string text [, string &plaintext])
 * verifies the given clearsigned text and returns information about the result in an array
 */
PHP_FUNCTION(gnupg_verify){
	char			*value = NULL;
	char			*sigtext = NULL;
	int 			value_len;
	int 			tmp;
	zval			*plaintext = NULL;
	zval			*res;
	zval			*sig;
	
	char	*userret;
	int		ret_size;

	gpgme_data_t			in, out;
	gpgme_verify_result_t	result;
	gpgme_signature_t		signature;

	GNUPG_GETOBJ();	

	if(this){
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|z", &value, &value_len, &plaintext) == FAILURE){
            return;
        }
    }else{
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "rs|z", &res, &value, &value_len, &plaintext) == FAILURE){
            return;
        }
        ZEND_FETCH_RESOURCE(intern,gnupg_object *, &res, -1, "ctx", le_gnupg);
    }
	if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
	}
	if((intern->err = gpgme_data_new_from_mem (&out, sigtext, 0, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
	}
	if((intern->err = gpgme_op_verify (intern->ctx, in, NULL, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("verify failed");
	}
	result				=	gpgme_op_verify_result (intern->ctx);
	if(!result->signatures){
		GNUPG_ERR			("no signature found");
	}
	array_init              (return_value);
	signature			=	result->signatures;
	while(signature){
		ALLOC_INIT_ZVAL		(sig);
		array_init			(sig);
		add_assoc_string    (sig,  "fingerprint",  signature->fpr,        1);
	    add_assoc_long      (sig,  "validity",     signature->validity    );
    	add_assoc_long      (sig,  "timestamp",    signature->timestamp   );
	    add_assoc_long      (sig,  "status",       signature->status      );

		add_next_index_zval (return_value, sig);
		
		signature		=	signature->next;
	}
    userret         	=   gpgme_data_release_and_get_mem(out,&ret_size);
	if(plaintext){
		ZVAL_STRINGL		(plaintext,userret,ret_size,1);
	}
	gpgme_data_release  	(in);
	free					(out);
}
/* }}} */

/* {{{ proto string gnupg_decrypt(string enctext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decrypt){
	char			*enctxt;
	int				enctxt_len;

	char    *userret;
    int     ret_size;

	zval	*res;
	
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

	gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
	
	if((intern->err = gpgme_data_new_from_mem (&in, enctxt, enctxt_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
	}
	if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
	}
	if((intern->err = gpgme_op_decrypt (intern->ctx, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("decrypt failed");
	}
	result = gpgme_op_decrypt_result (intern->ctx);
	if (result->unsupported_algorithm){
		GNUPG_ERR			("unsupported algorithm");
	}
	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	gpgme_data_release		(in);
	free					(out);
	if(ret_size < 1){
		RETURN_FALSE;
	}
	RETURN_STRINGL			(userret,ret_size,1);
}
/* }}} */

/* {{{ proto string gnupg_decryptverify(string enctext, string &plaintext)
 * decrypts the given enctext
 */
PHP_FUNCTION(gnupg_decryptverify){
    char            *enctxt;
    int             enctxt_len;
	zval			*plaintext;

    char    *userret;
    int     ret_size;

	zval	*res;

    gpgme_data_t            in, out;
	gpgme_decrypt_result_t	decrypt_result;
	gpgme_verify_result_t	verify_result;

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

    gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);

    if((intern->err = gpgme_data_new_from_mem (&in, enctxt, enctxt_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create in-data buffer");
    }
    if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("could not create out-data buffer");
    }
    if((intern->err = gpgme_op_decrypt_verify (intern->ctx, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("decrypt-verify failed");
    }
    userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	ZVAL_STRINGL			(plaintext,userret,ret_size,1);
	decrypt_result		=	gpgme_op_decrypt_result (intern->ctx);
	if (decrypt_result->unsupported_algorithm){
		GNUPG_ERR			("unsupported algorithm");
	}
	verify_result       =   gpgme_op_verify_result (intern->ctx);
	if(!verify_result->signatures){
        GNUPG_ERR           ("no signature found");
    }
    if(verify_result->signatures->next){
        GNUPG_ERR           ("multiple signatures found");
    }	

    array_init              (return_value);

    add_assoc_string        (return_value,  "fingerprint",  verify_result->signatures->fpr,        1);
    add_assoc_long          (return_value,  "validity",     verify_result->signatures->validity    );
    add_assoc_long          (return_value,  "timestamp",    verify_result->signatures->timestamp   );
    add_assoc_long          (return_value,  "status",       verify_result->signatures->status      );

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
    int		ret_size;

	zval	*res;

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
	}
	if((intern->err = gpgme_op_export (intern->ctx, searchkey, 0, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("export failed");
	}
	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	if(ret_size < 1){
		RETURN_FALSE;
	}
	RETURN_STRINGL          (userret,ret_size,1);
	free					(out);
}
/* }}} */

/* {{{ proto array gnupg_import(string key)
 * imports the given key and returns a status-array
*/
PHP_FUNCTION(gnupg_import){
	char			*importkey = NULL;
	int				importkey_len;
	zval			*res;

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
	}
	if((intern->err = gpgme_op_import(intern->ctx,in))!=GPG_ERR_NO_ERROR){
		GNUPG_ERR("import failed");
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
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
