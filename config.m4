dnl $Id$
dnl config.m4 for extension gnupg

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

PHP_ARG_WITH(gnupg, for gnupg support,
dnl Make sure that the comment is aligned:
[  --with-gnupg             Include gnupg support])

dnl Otherwise use enable:

dnl PHP_ARG_ENABLE(gnupg, whether to enable gnupg support,
dnl Make sure that the comment is aligned:
dnl [  --enable-gnupg           Enable gnupg support])

if test "$PHP_GNUPG" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-gnupg -> check with-path
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/gpgme.h"  # you most likely want to change this
  if test -r $PHP_GNUPG/$SEARCH_FOR; then # path given as parameter
    GNUPG_DIR=$PHP_GNUPG
  else # search default path list
    AC_MSG_CHECKING([for gnupg files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        GNUPG_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi
  
  if test -z "$GNUPG_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please reinstall the gnupg distribution])
  fi

  dnl # --with-gnupg -> add include path
  PHP_ADD_INCLUDE($GNUPG_DIR/include)

  dnl # --with-gnupg -> check for lib and symbol presence
  LIBNAME=gpgme # you may want to change this
  LIBSYMBOL=gpgme_check_version # you most likely want to change this 

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $GNUPG_DIR/lib, GNUPG_SHARED_LIBADD)
    AC_DEFINE(HAVE_GNUPGLIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong gnupg lib version or lib not found])
  ],[
    -L$GNUPG_DIR/lib -lm -ldl
  ])
  PHP_SUBST(GNUPG_SHARED_LIBADD)

  PHP_NEW_EXTENSION(gnupg, [gnupg.c gnupg_keylistiterator.c], $ext_shared)
fi
