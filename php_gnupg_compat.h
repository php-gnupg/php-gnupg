/*
  +--------------------------------------------------------------------+
  | PECL :: gnupg                                                      |
  +--------------------------------------------------------------------+
  | Redistribution and use in source and binary forms, with or without |
  | modification, are permitted provided that the conditions mentioned |
  | in the accompanying LICENSE file are met.                          |
  +--------------------------------------------------------------------+
  | Copyright (c) 2025, Jakub Zelenka <bukka@php.net>                  |
  +--------------------------------------------------------------------+
*/

#ifndef PHP_GNUPG_COMPAT_H
#define PHP_GNUPG_COMPAT_H

/* ZEND_ACC_CTOR and ZEND_ACC_DTOR removed in PHP 7.4 */
#ifndef ZEND_ACC_CTOR
#define ZEND_ACC_CTOR 0
#endif
#ifndef ZEND_ACC_DTOR
#define ZEND_ACC_DTOR 0
#endif

/* zend_function_entry constness added in PHP 7.4 */
#if PHP_VERSION_ID < 70400
#define GNUPG_FUNCTION_ENTRY zend_function_entry
#else
#define GNUPG_FUNCTION_ENTRY const zend_function_entry
#endif

/* object handlers comparison name changed in PHP 8.0 */
#if PHP_VERSION_ID < 80000
#define GNUPG_COMPARE_HANDLER_NAME compare_objects
#else
#define GNUPG_COMPARE_HANDLER_NAME compare
#endif

/* tentative return types added in PHP 8.1 */
#ifndef ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX
#define ZEND_BEGIN_ARG_WITH_TENTATIVE_RETURN_TYPE_INFO_EX(name, return_reference, required_num_args, type, allow_null) \
	ZEND_BEGIN_ARG_INFO_EX(name, 0, return_reference, required_num_args)
#endif

#endif /* PHP_GNUPG_COMPAT_H */