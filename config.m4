dnl $Id$
dnl config.m4 for extension gnupg

PHP_ARG_WITH(gnupg, for gnupg support,
[  --with-gnupg             Include gnupg support])

if test "$PHP_GNUPG" != "no"; then
  SEARCH_PATH="/usr/local /usr" 
  SEARCH_FOR="/include/gpgme.h"  
  if test -r $PHP_GNUPG/$SEARCH_FOR; then
    GNUPG_DIR=$PHP_GNUPG
  else
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
    AC_MSG_ERROR([Please reinstall the gpgme distribution])
  fi

  PHP_ADD_INCLUDE($GNUPG_DIR/include)

  LIBNAME=gpgme
  LIBSYMBOL=gpgme_check_version

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $GNUPG_DIR/lib, GNUPG_SHARED_LIBADD)
    AC_DEFINE(HAVE_GNUPGLIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong gpgme lib version or lib not found])
  ],[
    -L$GNUPG_DIR/lib -lm -ldl
  ])
  PHP_SUBST(GNUPG_SHARED_LIBADD)

  PHP_NEW_EXTENSION(gnupg, [gnupg.c gnupg_keylistiterator.c], $ext_shared)
fi
