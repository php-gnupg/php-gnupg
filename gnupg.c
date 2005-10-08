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
  | Author: Thilo Raufeisen                                                             |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_interfaces.h"
#include "php_gnupg.h"

static int le_gnupg;
static int le_gnupg_keylistiterator;

static zend_object_handlers gnupg_object_handlers;
static zend_object_handlers gnupg_keylistiterator_object_handlers;

/* {{{ macros */
#define GNUPG_FROM_OBJECT(intern, object){			\
	ze_gnupg_object *obj	=	(ze_gnupg_object*) zend_object_store_get_object(object TSRMLS_CC); \
	intern = obj->gnupg_ptr; \
	if(!intern){ \
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
		RETURN_FALSE; \
	} \
}
#define GNUPG_GET_ITERATOR(intern, object){ \
	ze_gnupg_keylistiterator_object *obj = (ze_gnupg_keylistiterator_object*) zend_object_store_get_object(object TSRMLS_CC); \
	intern = obj->gnupg_keylistiterator_ptr; \
	if(!intern){ \
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg iterator object"); \
		RETURN_FALSE; \
	}\
}
#define GNUPG_ERROR(intern, this){ \
	zend_update_property_string(Z_OBJCE_P(this), this, "error", 5, (char*)gpg_strerror(intern->err) TSRMLS_DC); \
	RETURN_FALSE; \
}
/* }}} */

/* {{{ free_resource */
static void gnupg_free_resource_ptr(gnupg_object *intern TSRMLS_DC){
	if(intern){
		
		if(intern->ctx){
			gpgme_signers_clear (intern->ctx);
			gpgme_release(intern->ctx);
			intern->ctx = NULL;
		}
		zval_dtor(&intern->passphrase);
		efree(intern);
	}
}
/* }}} */

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

/* {{{ free_iterator_storage */
static void gnupg_keylistiterator_object_free_storage(void *object TSRMLS_DC){
	ze_gnupg_keylistiterator_object *intern = (ze_gnupg_keylistiterator_object *) object;
	if(!intern){
		return;
	}
	if(intern->gnupg_keylistiterator_ptr){
		gpgme_op_keylist_end(intern->gnupg_keylistiterator_ptr->ctx);
		gpgme_key_release(intern->gnupg_keylistiterator_ptr->gpgkey);
		gpgme_release(intern->gnupg_keylistiterator_ptr->ctx);
		zval_dtor(&intern->gnupg_keylistiterator_ptr->pattern);
		efree(intern->gnupg_keylistiterator_ptr);
	}
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
	
	return retval;
}
/* }}} */

/* {{{ keylistiterator_objects_new */
zend_object_value gnupg_keylistiterator_objects_new(zend_class_entry *class_type TSRMLS_DC){
	ze_gnupg_keylistiterator_object *intern;
	zval *tmp;
	zend_object_value retval;
	intern =	emalloc(sizeof(ze_gnupg_keylistiterator_object));
	intern->zo.ce = class_type;
	intern->zo.in_get = 0;
	intern->zo.in_set = 0;
	intern->zo.properties = NULL;

	ALLOC_HASHTABLE(intern->zo.properties);
	zend_hash_init(intern->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);
	zend_hash_copy(intern->zo.properties, &class_type->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
	retval.handle   =   zend_objects_store_put(intern,NULL,(zend_objects_free_object_storage_t) gnupg_keylistiterator_object_free_storage,NULL TSRMLS_CC);
	retval.handlers	=	(zend_object_handlers *) & gnupg_keylistiterator_object_handlers;
	return retval;
}
/* }}} */

/* {{{ resource_destructor */
void gnupg_resource_destructor(zend_rsrc_list_entry *rsrc TSRMLS_DC){
	/*
	if(rsrc->ptr){
		printf("debug");
	}
	*/
}
/* }}} */

void gnupg_keylistiterator_resource_destructor(zend_rsrc_list_entry *rsrc TSRMLS_DC){

}

/* {{{ functionlist */
function_entry gnupg_functions[] = {
	{NULL, NULL, NULL}	/* Must be the last line in gnupg_functions[] */
};
/* }}} */

/* {{{ methodlist gnupg */
static zend_function_entry gnupg_methods[] = {
	PHP_ME_MAPPING(__construct,		gnupg_construct,		NULL)
	PHP_ME_MAPPING(keyinfo,			gnupg_keyinfo,			NULL)
	PHP_ME_MAPPING(verify,			gnupg_verify,			NULL)
	PHP_ME_MAPPING(getError,		gnupg_geterror,			NULL)
	PHP_ME_MAPPING(setpassphrase,	gnupg_setpassphrase,	NULL)
	PHP_ME_MAPPING(setsignerkey,	gnupg_setsignerkey,		NULL)
	PHP_ME_MAPPING(clearsignerkey,	gnupg_clearsignerkey,	NULL)
	PHP_ME_MAPPING(setencryptkey,	gnupg_setencryptkey,	NULL)
	PHP_ME_MAPPING(setarmor,		gnupg_setarmor,			NULL)
	PHP_ME_MAPPING(encrypt,			gnupg_encrypt,			NULL)
	PHP_ME_MAPPING(decrypt,			gnupg_decrypt,			NULL)
	PHP_ME_MAPPING(export,			gnupg_export,			NULL)
	PHP_ME_MAPPING(getprotocol,		gnupg_getprotocol,		NULL)
	PHP_ME_MAPPING(setsignmode,		gnupg_setsignmode,		NULL)
	PHP_ME_MAPPING(sign,			gnupg_sign,				NULL)
	{NULL, NULL, NULL}
};
/* }}} */

/* {{{ methodlist gnupg_keylistiterator */
static zend_function_entry gnupg_keylistiterator_methods[] = {
    PHP_ME_MAPPING(__construct,     gnupg_keylistiterator_construct,        NULL)
    PHP_ME_MAPPING(current,         gnupg_keylistiterator_current,          NULL)
    PHP_ME_MAPPING(key,             gnupg_keylistiterator_key,              NULL)
    PHP_ME_MAPPING(next,            gnupg_keylistiterator_next,             NULL)
    PHP_ME_MAPPING(rewind,          gnupg_keylistiterator_rewind,           NULL)
    PHP_ME_MAPPING(valid,           gnupg_keylistiterator_valid,            NULL)
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

/* {{{ properties */
void register_gnupgProperties(TSRMLS_D){
	zend_declare_property_long		(gnupg_class_entry, "protocol", 8, GPGME_PROTOCOL_OpenPGP, ZEND_ACC_PROTECTED TSRMLS_DC);
	zend_declare_property_string	(gnupg_class_entry, "error", 5, "", ZEND_ACC_PROTECTED TSRMLS_DC);
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
	NULL,		/* Replace with NULL if there's nothing to do at request start */
	NULL,	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(gnupg),
#if ZEND_MODULE_API_NO >= 20010901
	"0.1", /* Replace with version number for your extension */
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
	zend_class_entry ce; 
	
	INIT_CLASS_ENTRY(ce, "gnupg", gnupg_methods);
	
	ce.create_object	=	gnupg_objects_new;
	gnupg_class_entry   =   zend_register_internal_class(&ce TSRMLS_CC);
	memcpy(&gnupg_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	le_gnupg			=	zend_register_list_destructors_ex(gnupg_resource_destructor, NULL, "ctx", module_number);
/*
	zend_class_entry itce;
*/
	INIT_CLASS_ENTRY(ce, "gnupg_keylistiterator", gnupg_keylistiterator_methods);
	
	ce.create_object 	=	gnupg_keylistiterator_objects_new;
	gnupg_keylistiterator_class_entry = zend_register_internal_class(&ce TSRMLS_CC);
	memcpy(&gnupg_keylistiterator_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	le_gnupg_keylistiterator = zend_register_list_destructors_ex(gnupg_keylistiterator_resource_destructor, NULL, "ctx_keylistiterator", module_number);
	
	zend_class_implements   (gnupg_keylistiterator_class_entry TSRMLS_DC, 1, zend_ce_iterator);
	
	
	register_gnupgProperties(TSRMLS_CC);
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
	gnupg_declare_long_constant("SIGSUM_RED",         		  GPGME_SIGSUM_RED TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_KEY_REVOKED",         GPGME_SIGSUM_KEY_REVOKED TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_KEY_EXPIRED",         GPGME_SIGSUM_KEY_EXPIRED TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_SIG_EXPIRED",         GPGME_SIGSUM_SIG_EXPIRED TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_KEY_MISSING",         GPGME_SIGSUM_KEY_MISSING TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_CRL_MISSING",         GPGME_SIGSUM_CRL_MISSING TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_CRL_TOO_OLD",         GPGME_SIGSUM_CRL_TOO_OLD TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_BAD_POLICY",          GPGME_SIGSUM_BAD_POLICY TSRMLS_DC);
	gnupg_declare_long_constant("SIGSUM_SYS_ERROR",           GPGME_SIGSUM_SYS_ERROR TSRMLS_DC);
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

/* {{{proto object gnupg_construct([PROTOCOL])
 * constructor.
 * if passed, only GPGME_PROTOCOL_OpenPGP is currently valid
 */
PHP_FUNCTION(gnupg_construct){
	gnupg_object *intern;
	zval *this = getThis();
	ze_gnupg_object *ze_obj;
	
	int protocol = GPGME_PROTOCOL_OpenPGP;
	gpgme_ctx_t ctx;
	gpgme_error_t err;
		
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &protocol) == FAILURE){
		return;
	}
	if(protocol != GPGME_PROTOCOL_OpenPGP){
		zend_throw_exception(zend_exception_get_default(),"only OpenPGP is currently supported",1 TSRMLS_CC);
	}
	if((err = gpgme_new(&ctx))!=GPG_ERR_NO_ERROR){
		zend_throw_exception(zend_exception_get_default(),gpg_strerror(err),1 TSRMLS_CC);
	}
	gpgme_set_armor	(ctx,1);
	
	ze_obj	=	(ze_gnupg_object*) zend_object_store_get_object(this TSRMLS_CC); 
	intern	=	emalloc(sizeof(gnupg_object));
	intern->ctx			= ctx;
	intern->encryptkey	= NULL;
	intern->signmode	= GPGME_SIG_MODE_CLEAR;
	ze_obj->gnupg_ptr	= intern;
}
/* }}} */

/* {{{ proto bool gnupg_setarmor(int armor)
 * turn on/off armor mode
 * 0 = off
 * >0 = on
 * */
PHP_FUNCTION(gnupg_setarmor){
	int	   		 armor;
	zval	     *this = getThis();
	gnupg_object *intern;

	GNUPG_FROM_OBJECT(intern, this);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &armor) == FAILURE){
		return;
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
	zval		 *this = getThis();
	gnupg_object *intern;

	GNUPG_FROM_OBJECT(intern, this);

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"l", &signmode) == FAILURE){
		return;
	}
	switch(signmode){
		case GPGME_SIG_MODE_NORMAL:
		case GPGME_SIG_MODE_DETACH:
		case GPGME_SIG_MODE_CLEAR:
			intern->signmode = signmode;
			RETURN_TRUE;
			break;
		default:
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid signmode: %i",signmode);
			RETURN_FALSE; /* not really needed */
			break;
	}
}
/* }}} */

/* {{{ proto bool gnupg_setpassphrase(string passphrase)
 * sets the passphrase for all next operations
 */
PHP_FUNCTION(gnupg_setpassphrase){
	zval *tmp;
	zval *this = getThis();
	gnupg_object *intern;
	
	GNUPG_FROM_OBJECT(intern, this);

	if(zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"z", &tmp) == FAILURE){
		return;
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
	zval *error;
	zval *this = getThis();
	
	error	= zend_read_property(Z_OBJCE_P(this), this, "error", 5, 1 TSRMLS_CC);
	RETURN_STRINGL(Z_STRVAL_P(error), Z_STRLEN_P(error), 1);
}
/* }}} */

/* {{{ proto int gnupg_getprotocol(void)
 * returns the currently used pgp-protocol.
 * atm only OpenPGP is supported
 */
PHP_FUNCTION(gnupg_getprotocol){
	zval *this = getThis();
	zval *protocol;
	gnupg_object *intern;
	GNUPG_FROM_OBJECT(intern, this);
	protocol	=	zend_read_property(Z_OBJCE_P(this), this, "protocol", 8, 1 TSRMLS_CC);
	RETURN_LONG(Z_LVAL_P(protocol));
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
	zval		*this = getThis();
	zval		*subarr;
	zval		*userid;
	zval		*userids;
	zval		*subkey;
	zval		*subkeys;
	gnupg_object *intern;
	
	gpgme_key_t		gpgkey;
	gpgme_subkey_t	gpgsubkey;
	gpgme_user_id_t gpguserid;
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE){
		return;
	}
	
	GNUPG_FROM_OBJECT(intern, this);
	
	if((intern->err = gpgme_op_keylist_start(intern->ctx, searchkey, 0)) != GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
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

/* {{{ proto bool gnupg_setsignerkey(string key)
 * sets the private key for the next sign operation.
 * please note, that the given key must return only 1 result from the keyring
 * it should be the best to provide a fingerprint here
 */
PHP_FUNCTION(gnupg_setsignerkey){
    char	*key_id = NULL;
    int		key_id_len;
	
	zval			*this = getThis();
	gnupg_object	*intern;

    gpgme_sign_result_t	result;
	gpgme_key_t			gpgme_key;
	
	GNUPG_FROM_OBJECT(intern, this);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key_id, &key_id_len) == FAILURE){
        return;
    }
	if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 1)) != GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
    }

	gpgme_signers_clear	(intern->ctx);

	if((intern->err = gpgme_signers_add(intern->ctx, gpgme_key))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	RETURN_TRUE;	
}
/* }}} */

/* {{{ proto bool gnupg_setencryptkey(string key)
 * sets the public key for next encrypt operation.
 * please note, that the given key must return only 1 result from the keyring
 * it should be the best to provide a fingerprint here
 */
PHP_FUNCTION(gnupg_setencryptkey){
	char	*key_id = NULL;
    int		key_id_len;

	zval			*this = getThis();
	gnupg_object	*intern;

    gpgme_sign_result_t	result;
    gpgme_key_t			gpgme_key;
	
	GNUPG_FROM_OBJECT(intern, this);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &key_id, &key_id_len) == FAILURE){
        return;
	}
	if((intern->err = gpgme_get_key(intern->ctx, key_id, &gpgme_key, 0)) != GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
    }
	if(intern->encryptkey){
		gpgme_key_release(intern->encryptkey);
	}
	intern->encryptkey = gpgme_key;
    RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearsignerkey(void)
 * removes all keys which are set for signing
 */
PHP_FUNCTION(gnupg_clearsignerkey){
	zval			*this = getThis();
	gnupg_object	*intern;
	
	GNUPG_FROM_OBJECT	(intern, this);
	
	gpgme_signers_clear	(intern->ctx);
	RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool gnupg_clearencryptkey(void)
 * removes all keys which are set for encryption
 */
PHP_FUNCTION(gnupg_clearencryptkey){
	zval			*this = getThis();
	gnupg_object	*intern;

	GNUPG_FROM_OBJECT	(intern, this);
	
	gpgme_key_release   (intern->encryptkey);

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

    zval    	 *this = getThis();
    gnupg_object *intern;

    char    *userret;
    int     ret_size;

    gpgme_data_t in, out;

    GNUPG_FROM_OBJECT(intern, this);

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE){
        return;
    }
    gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
    if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
        GNUPG_ERROR(intern,this);
    }
    if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
        GNUPG_ERROR(intern,this);
    }
    if((intern->err = gpgme_op_sign(intern->ctx, in, out, intern->signmode))!=GPG_ERR_NO_ERROR){
        GNUPG_ERROR(intern,this);
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
	zval *this = getThis();
	gnupg_object *intern;

	gpgme_data_t in, out;
	
	GNUPG_FROM_OBJECT(intern, this);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &value, &value_len) == FAILURE){
		return;
	}
	
	if(!intern->encryptkey){
		zend_update_property_string(Z_OBJCE_P(this), this, "error", 5, "no key for encryption set" TSRMLS_DC);
		RETURN_FALSE;
	}
	if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_data_new(&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_op_encrypt(intern->ctx, &intern->encryptkey, GPGME_ENCRYPT_ALWAYS_TRUST, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	userret		=	gpgme_data_release_and_get_mem(out,&ret_size);
	if(ret_size < 1){
		RETURN_FALSE;
	}
	gpgme_data_release  (in);
	free (out);
	/*
	gpgme_key_release   (gpgme_key);
	*/
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
	zval			*plaintext;
	zval 			*this = getThis();
	gnupg_object	*intern;
	
	char	*userret;
	int		ret_size;

	gpgme_data_t			in, out;
	gpgme_verify_result_t	result;
	gpgme_signature_t		nextsig;
	
	GNUPG_FROM_OBJECT(intern, this);
	
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|z", &value, &value_len, &plaintext) == FAILURE){
		return;
	}
	if((intern->err = gpgme_data_new_from_mem (&in, value, value_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_data_new_from_mem (&out, sigtext, 0, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_op_verify (intern->ctx, in, NULL, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	result				=	gpgme_op_verify_result (intern->ctx);
	
	array_init				(return_value);

	add_assoc_string		(return_value,	"fingerprint",	result->signatures->fpr,		1);
	add_assoc_long			(return_value,	"validity",		result->signatures->validity	);
	add_assoc_long			(return_value,	"timestamp",	result->signatures->timestamp	);
	add_assoc_long			(return_value,	"status",		result->signatures->status		);

	nextsig				=	result->signatures->next;
	if(nextsig){
		zend_update_property_string(Z_OBJCE_P(this), this, "error", 5, "multiple signatures found" TSRMLS_DC);
		RETURN_FALSE;
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

	zval 			*this = getThis();
	gnupg_object	*intern;

	char    *userret;
    int     ret_size;
	
	gpgme_data_t			in, out;
	gpgme_decrypt_result_t	result;
	  
	GNUPG_FROM_OBJECT(intern, this);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &enctxt, &enctxt_len) == FAILURE){
		return;
	}

	gpgme_set_passphrase_cb (intern->ctx, (void*) passphrase_cb, intern);
	
	if((intern->err = gpgme_data_new_from_mem (&in, enctxt, enctxt_len, 0))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_op_decrypt (intern->ctx, in, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	result = gpgme_op_decrypt_result (intern->ctx);

	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	RETURN_STRINGL			(userret,ret_size,1);
	gpgme_data_release		(in);
	free					(out);
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

	zval 		 *this = getThis();
	gnupg_object *intern;

	gpgme_data_t  out;

	GNUPG_FROM_OBJECT(intern, this);

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &searchkey, &searchkey_len) == FAILURE){
		return;
	}
	if((intern->err = gpgme_data_new (&out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	if((intern->err = gpgme_op_export (intern->ctx, searchkey, 0, out))!=GPG_ERR_NO_ERROR){
		GNUPG_ERROR(intern,this);
	}
	userret             =   gpgme_data_release_and_get_mem(out,&ret_size);
	if(ret_size < 1){
		RETURN_FALSE;
	}
	RETURN_STRINGL          (userret,ret_size,1);
	free					(out);
}
/* }}} */

PHP_FUNCTION(gnupg_keylistiterator_construct){
	zval *pattern;
	
	gnupg_keylistiterator_object *intern;
	zval *this = getThis();
	ze_gnupg_keylistiterator_object *ze_obj;

	gpgme_ctx_t ctx;
	gpgme_error_t err;

	int args = ZEND_NUM_ARGS();
	
	if (zend_parse_parameters(args TSRMLS_CC, "|z", &pattern) == FAILURE){
		return;
	}
	if((err = gpgme_new(&ctx))!=GPG_ERR_NO_ERROR){
		zend_throw_exception(zend_exception_get_default(),gpg_strerror(err),1 TSRMLS_CC);
	}
	if(args < 1){
		ALLOC_INIT_ZVAL(pattern);
		ZVAL_EMPTY_STRING(pattern);
	}
	ze_obj  =   (ze_gnupg_keylistiterator_object*) zend_object_store_get_object(this TSRMLS_CC);
	intern  =   emalloc(sizeof(gnupg_keylistiterator_object));
	intern->ctx	=	ctx;

	intern->pattern = *pattern;
	zval_copy_ctor(&intern->pattern);
	ze_obj->gnupg_keylistiterator_ptr   = intern;
}
PHP_FUNCTION(gnupg_keylistiterator_current){
	zval *this = getThis();
	gnupg_keylistiterator_object *intern;
	GNUPG_GET_ITERATOR(intern, this);
	RETURN_STRING(intern->gpgkey->uids[0].uid,1);
}

PHP_FUNCTION(gnupg_keylistiterator_key){
	zval *this = getThis();
    gnupg_keylistiterator_object *intern;
    GNUPG_GET_ITERATOR(intern, this);
	RETURN_STRING(intern->gpgkey->subkeys[0].fpr,1);
}

PHP_FUNCTION(gnupg_keylistiterator_next){
	zval *this = getThis();
	gnupg_keylistiterator_object *intern;
	gpgme_error_t err;
	GNUPG_GET_ITERATOR(intern, this);

	intern->itkey++;
	if(err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey)){
		gpgme_key_release(intern->gpgkey);
		intern->gpgkey = NULL;
	}
	RETURN_TRUE;
}

PHP_FUNCTION(gnupg_keylistiterator_rewind){
	zval *this = getThis();
	gnupg_keylistiterator_object *intern;
	gpgme_error_t err;
	GNUPG_GET_ITERATOR(intern, this);

	intern->itkey = 0;
	if((err = gpgme_op_keylist_start(intern->ctx, Z_STRVAL(intern->pattern), 0)) != GPG_ERR_NO_ERROR){
		zend_throw_exception(zend_exception_get_default(),gpg_strerror(err),1 TSRMLS_CC);
	}
	if((err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey))!=GPG_ERR_NO_ERROR){
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

PHP_FUNCTION(gnupg_keylistiterator_valid){
	zval *this = getThis();
	gnupg_keylistiterator_object *intern;

	GNUPG_GET_ITERATOR(intern, this);

	if(intern->gpgkey!=NULL){
		RETURN_TRUE;
	}else{
		RETURN_FALSE;
	}
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
