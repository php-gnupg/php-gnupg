dnl $Id$
dnl config.m4 for extension gnupg
AC_CANONICAL_HOST
case $host_os in
   *BSD*)
        GNUPG_DL=""
        ;;
    *)
        GNUPG_DL="-ldl"
        ;;
esac
 

PHP_ARG_WITH(gnupg, for gnupg support,
[  --with-gnupg[=dir]       Include gnupg support])

if test "$PHP_GNUPG" != "no"; then
  SEARCH_PATH="/usr/local/include /usr/include /usr/local/include/gpgme/ /usr/include/gpgme/"
  SEARCH_FOR="gpgme.h"
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

  PHP_ADD_INCLUDE($GNUPG_DIR)

  LIBNAME=gpgme
  LIBSYMBOL=gpgme_check_version

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $GNUPG_DIR/lib, GNUPG_SHARED_LIBADD)
    AC_DEFINE(HAVE_GNUPGLIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong gpgme lib version or lib not found])
  ],[
    -L$GNUPG_DIR/lib -lm $GNUPG_DL
  ])
  PHP_SUBST(GNUPG_SHARED_LIBADD)

  PHP_NEW_EXTENSION(gnupg, [gnupg.c gnupg_keylistiterator.c], $ext_shared)
fi

AC_ARG_WITH([gpg], [AS_HELP_STRING([--with-gpg],
        [path to gpg v1.x])], [], [with_gpg=no])

AC_PATH_PROG(GNUPG_PATH, gpg)
if test "$with_gpg" != "no"; then
  if test "$with_gpg" != "yes"; then
    if test -x "$with_gpg"; then
      ac_cv_path_GNUPG_PATH=$with_gpg
    else
      if test -x "$ac_cv_path_GNUPG_PATH"; then
        AC_MSG_RESULT($with_gpg invalid: using $ac_cv_path_GNUPG_PATH)
      else
        AC_MSG_RESULT($with_gpg invalid)
      fi
    fi
  fi
  if test -x "$ac_cv_path_GNUPG_PATH"; then
    AC_DEFINE_UNQUOTED([GNUPG_PATH], ["$ac_cv_path_GNUPG_PATH"], [Path to gpg v1.x])
  fi
fi
