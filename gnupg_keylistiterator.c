/*
  +--------------------------------------------------------------------+
  | PECL :: gnupg                                                      |
  +--------------------------------------------------------------------+
  | Redistribution and use in source and binary forms, with or without |
  | modification, are permitted provided that the conditions mentioned |
  | in the accompanying LICENSE file are met.                          |
  +--------------------------------------------------------------------+
  | Copyright (c) 2006, Thilo Raufeisen <traufeisen@php.net>           |
  +--------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#ifdef ZEND_ENGINE_2

#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_interfaces.h"
#include "php_gnupg.h"
#include "php_gnupg_keylistiterator.h"

static int le_gnupg_keylistiterator;

static zend_object_handlers gnupg_keylistiterator_object_handlers;

/* {{{ defs */
#define GNUPG_GET_ITERATOR() \
    zval *this = getThis(); \
    gnupg_keylistiterator_object *intern; \
    if(this){ \
        intern  =   (gnupg_keylistiterator_object*) zend_object_store_get_object(getThis() TSRMLS_CC); \
        if(!intern){ \
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid or unitialized gnupg object"); \
            RETURN_FALSE; \
        } \
    }
/* }}} */

/* {{{ free_iterator_storage */
static void gnupg_keylistiterator_dtor(gnupg_keylistiterator_object *intern TSRMLS_DC){
	if(!intern){
		return;
	}
	gpgme_op_keylist_end(intern->ctx);
	gpgme_key_release(intern->gpgkey);
	gpgme_release(intern->ctx);
/*
	zval_dtor(&intern->pattern);
*/	
	if(intern->zo.properties){
		zend_hash_destroy(intern->zo.properties);
		FREE_HASHTABLE(intern->zo.properties);
	}
	efree(intern);
}
/* }}} */

/* {{{ keylistiterator_objects_new */
zend_object_value gnupg_keylistiterator_objects_new(zend_class_entry *class_type TSRMLS_DC){
	gnupg_keylistiterator_object *intern;
	zend_object_value retval;
	gpgme_ctx_t ctx;

	intern =	emalloc(sizeof(gnupg_keylistiterator_object));
	intern->zo.ce = class_type;
	intern->zo.properties = NULL;
	retval.handle   =   zend_objects_store_put(intern,NULL,(zend_objects_free_object_storage_t) gnupg_keylistiterator_dtor,NULL TSRMLS_CC);
	retval.handlers	=	(zend_object_handlers *) & gnupg_keylistiterator_object_handlers;

    gpgme_new(&ctx);
	intern->ctx		=	ctx;
	return retval;
}
/* }}} */

/* {{{ methodlist gnupg_keylistiterator */
static zend_function_entry gnupg_keylistiterator_methods[] = {
	ZEND_ME(gnupg_keylistiterator,	__construct,	NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg_keylistiterator,	current,		NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg_keylistiterator,	key,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg_keylistiterator,	next,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg_keylistiterator,	rewind,			NULL,	ZEND_ACC_PUBLIC)
	ZEND_ME(gnupg_keylistiterator,	valid,			NULL,	ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}	
};
/* }}} */

/* {{{ _gnupg_keylistiterator_init
 */
int _gnupg_keylistiterator_init(INIT_FUNC_ARGS)
{
	zend_class_entry ce; 
	
	INIT_CLASS_ENTRY(ce, "gnupg_keylistiterator", gnupg_keylistiterator_methods);
	
	ce.create_object 	=	gnupg_keylistiterator_objects_new;
	gnupg_keylistiterator_class_entry = zend_register_internal_class(&ce TSRMLS_CC);
	memcpy(&gnupg_keylistiterator_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	le_gnupg_keylistiterator = zend_register_list_destructors_ex(NULL, NULL, "ctx_keylistiterator", module_number);
	
	zend_class_implements   (gnupg_keylistiterator_class_entry TSRMLS_CC, 1, zend_ce_iterator);
	
	return SUCCESS;
}
/* }}} */


PHP_FUNCTION(gnupg_keylistiterator___construct){
	zval *pattern;

	int args = ZEND_NUM_ARGS();

	GNUPG_GET_ITERATOR();

	if(args > 0){
		if (zend_parse_parameters(args TSRMLS_CC, "|z", &pattern) == FAILURE){
			return;
		}
		intern->pattern = *pattern;
		zval_copy_ctor(&intern->pattern);
	}else{
		ZVAL_EMPTY_STRING(&intern->pattern);
	}
}
PHP_FUNCTION(gnupg_keylistiterator_current){
	GNUPG_GET_ITERATOR();
	
	RETURN_STRING(intern->gpgkey->uids[0].uid,1);
}

PHP_FUNCTION(gnupg_keylistiterator_key){
    GNUPG_GET_ITERATOR();
	
	RETURN_STRING(intern->gpgkey->subkeys[0].fpr,1);
}

PHP_FUNCTION(gnupg_keylistiterator_next){
	GNUPG_GET_ITERATOR();

	if(intern->gpgkey){
		gpgme_key_release(intern->gpgkey);
	}

	if(intern->err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey)){
		gpgme_key_release(intern->gpgkey);
		intern->gpgkey = NULL;
	}
	RETURN_TRUE;
}

PHP_FUNCTION(gnupg_keylistiterator_rewind){
	GNUPG_GET_ITERATOR();

	if((intern->err = gpgme_op_keylist_start(intern->ctx, Z_STRVAL(intern->pattern), 0)) != GPG_ERR_NO_ERROR){
		zend_throw_exception(zend_exception_get_default(),gpg_strerror(intern->err),1 TSRMLS_CC);
	}
	if((intern->err = gpgme_op_keylist_next(intern->ctx, &intern->gpgkey))!=GPG_ERR_NO_ERROR){
		RETURN_FALSE;
	}
	RETURN_TRUE;
}

PHP_FUNCTION(gnupg_keylistiterator_valid){
	GNUPG_GET_ITERATOR();

	if(intern->gpgkey!=NULL){
		RETURN_TRUE;
	}else{
		RETURN_FALSE;
	}
}
#endif /* ZEND_ENGINE_2 */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
