dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002-2021 Simon Josefsson
#
# This file is part of GNU SASL.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.64])
AC_INIT([GNU SASL], [1.10.0], [bug-gsasl@gnu.org], [gsasl])
AC_CONFIG_AUX_DIR([lib/build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.13 -Wall -Wno-override])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
gl_EARLY
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR
LT_INIT([win32-dll])
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(DIA, dia, $missing_dir)
AM_MISSING_PROG(EPSTOPDF, epstopdf, $missing_dir)

# Internationalization.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.8])

# Checks for header files.
AC_CHECK_HEADERS(pwd.h)

# Checks for library functions.
AC_SEARCH_LIBS(socket, socket)
AC_CHECK_FUNCS(getpwuid)

# Allow disabling of obsolete stuff.
AC_ARG_ENABLE(obsolete,
  AS_HELP_STRING([--disable-obsolete], [disable backwards compatibility code]),
    obsolete=$enableval)
if test "$obsolete" = "no"; then
  AC_DEFINE([GSASL_NO_OBSOLETE], 1,
    [Define to 1 if you don't want backwards compatibility code.])
else
  obsolete=yes
fi
AC_MSG_CHECKING([if backwards compatibility code should be present])
AC_MSG_RESULT($obsolete)
AM_CONDITIONAL(OBSOLETE, test "$obsolete" = "yes")

# Check for GnuTLS.
AC_ARG_WITH(gnutls,
  AS_HELP_STRING([--without-gnutls], [disable GnuTLS support]),
	gnutls=$withval, gnutls=yes)
if test "$gnutls" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(gnutls,, [#include <gnutls/gnutls.h>],
    [gnutls_session_set_verify_cert (NULL, NULL, 0);])
fi
if test "$ac_cv_libgnutls" != yes; then
  gnutls=no
  AC_MSG_WARN([GnuTLS >= 3.4 not found.  STARTTLS support disabled.])
fi
AC_MSG_CHECKING([if STARTTLS support via GnuTLS should be built])
AC_MSG_RESULT($gnutls)

if test "$ac_cv_libgnutls" = yes; then
  save_LIBS="$LIBS"
  LIBS="$LIBS $LIBGNUTLS"
  AC_CHECK_FUNCS([gnutls_session_channel_binding])
  LIBS="$save_LIBS"
fi

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# For gnulib stuff in gl/.
gl_INIT
AC_DEFINE([GNULIB_NO_VLA], 1, [Disable VLA usage in gettext.h.])
AM_CONDITIONAL(WINDOWS, test "$gl_cv_func_wsastartup" = "yes")

# Check for Lasso.  For examples/saml20/.  Disabled by default on Windows.
lasso_default=yes
if test "$gl_cv_func_wsastartup" = "yes"; then
  lasso_default=no
fi
AC_ARG_WITH(lasso,
  AS_HELP_STRING([--without-lasso],
                 [disable Lasso (used by examples/saml20/)]),
  lasso=$withval, lasso=$lasso_default)
if test "$lasso" != "no"; then
  PKG_CHECK_MODULES(LASSO, lasso >= 2.2.1, [lasso=yes], [lasso=no])
  AC_SUBST(LASSO_CFLAGS)
  LASSO_CFLAGS=`echo $pkg_cv_LASSO_CFLAGS | sed -e 's,\\\\,,g'`
fi
AM_CONDITIONAL(LASSO, test "$lasso" = "yes")

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
		  [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  gl_WARN_ADD([-Werror], [WERROR_CFLAGS])
  gl_WARN_ADD([-Wno-missing-field-initializers], [WEASY_CFLAGS])
  gl_WARN_ADD([-Wno-unused-parameter], [WEASY_CFLAGS])
  gl_WARN_ADD([-Wno-sign-compare], [WEASY_CFLAGS])
  gl_WARN_ADD([-Wno-deprecated-declarations], [WEASY_CFLAGS])

  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wpadded"                 # Our structs are not padded
  nw="$nw -Wundef"                  # warns on '#if GNULIB_FOO' etc in gnulib
  nw="$nw -Wc++-compat"             # We don't care strongly about C++ compilers
  nw="$nw -Wswitch-enum"            # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsign-conversion"        # Too many warnings for now
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wunreachable-code"       # Too many false positives
  nw="$nw -Wsuggest-attribute=pure" # Is it worth using attributes?
  nw="$nw -Wsuggest-attribute=const" # Is it worth using attributes?

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done
fi

AC_CONFIG_SUBDIRS([lib])

AC_CONFIG_FILES([
  Makefile
  doc/Makefile
  doc/cyclo/Makefile
  doc/doxygen/Doxyfile
  doc/reference/Makefile
  doc/reference/version.xml
  examples/Makefile
  examples/openid20/Makefile
  examples/saml20/Makefile
  gl/Makefile
  gltests/Makefile
  po/Makefile.in
  src/Makefile
  tests/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of main build options:

  version:            ${VERSION}
  Host/Target system: ${host}
  Build system:       ${build}
  Install prefix:     ${prefix}
  Compiler:           cc: ${CC} cflags: ${CFLAGS} cppflags: ${CPPFLAGS}
  Valgrind:           $opt_valgrind_tests ${VALGRIND}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
  Warning flags:      $gl_gcc_warnings werror $WERROR_CFLAGS wstack $WSTACK_CFLAGS warn $WARN_CFLAGS

  Obsolete functions: $obsolete

  GnuTLS support:     $gnutls
        CPPFLAGS:     $INCLIBGNUTLS
           LDADD:     $LTLIBGNUTLS

  Lasso support:      $lasso
       CPPFLAGS:      $LASSO_CFLAGS
          LDADD:      $LASSO_LIBS
])
