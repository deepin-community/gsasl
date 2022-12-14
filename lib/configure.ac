dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002-2021 Simon Josefsson
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

AC_PREREQ([2.64])
AC_INIT([libgsasl], [1.10.0], [bug-gsasl@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 17)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 10)

# Used when creating libgsasl-XX.def.
DLL_VERSION=`expr ${LT_CURRENT} - ${LT_AGE}`
AC_SUBST(DLL_VERSION)

AM_INIT_AUTOMAKE([1.10 -Wall])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
gl_EARLY
m4_pattern_allow([AM_PROG_AR])
AM_PROG_AR
LT_INIT([win32-dll])

# Internationalization.
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.19.8])

# ANONYMOUS
AC_ARG_ENABLE(anonymous,
  AS_HELP_STRING([--disable-anonymous], [don't use the ANONYMOUS mechanism]),
  anonymous=$enableval)
if test "$anonymous" != "no" ; then
	anonymous=yes
	AC_DEFINE(USE_ANONYMOUS, 1, [Define to 1 if you want ANONYMOUS.])
fi
AC_MSG_CHECKING([if ANONYMOUS should be used])
AC_MSG_RESULT($anonymous)
AM_CONDITIONAL(ANONYMOUS, test x$anonymous = xyes)

# EXTERNAL
AC_ARG_ENABLE(external,
  AS_HELP_STRING([--disable-external], [don't use the EXTERNAL mechanism]),
  external=$enableval)
if test "$external" != "no" ; then
	external=yes
	AC_DEFINE(USE_EXTERNAL, 1, [Define to 1 if you want EXTERNAL.])
fi
AC_MSG_CHECKING([if EXTERNAL should be used])
AC_MSG_RESULT($external)
AM_CONDITIONAL(EXTERNAL, test x$external = xyes)

# PLAIN
AC_ARG_ENABLE(plain,
  AS_HELP_STRING([--disable-plain], [don't use the PLAIN mechanism]),
  plain=$enableval)
if test "$plain" != "no" ; then
	plain=yes
	AC_DEFINE(USE_PLAIN, 1, [Define to 1 if you want PLAIN.])
fi
AC_MSG_CHECKING([if PLAIN should be used])
AC_MSG_RESULT($plain)
AM_CONDITIONAL(PLAIN, test x$plain = xyes)

# LOGIN
AC_ARG_ENABLE(login,
  AS_HELP_STRING([--disable-login], [don't use the LOGIN mechanism]),
  login=$enableval)
if test "$login" != "no" ; then
	login=yes
	AC_DEFINE(USE_LOGIN, 1, [Define to 1 if you want LOGIN.])
fi
AC_MSG_CHECKING([if LOGIN should be used])
AC_MSG_RESULT($login)
AM_CONDITIONAL(LOGIN, test x$login = xyes)

# SECURID
AC_ARG_ENABLE(securid,
  AS_HELP_STRING([--disable-securid], [don't use the SECURID mechanism]),
  securid=$enableval)
if test "$securid" != "no" ; then
	securid=yes
	AC_DEFINE(USE_SECURID, 1, [Define to 1 if you want SECURID.])
fi
AC_MSG_CHECKING([if SECURID should be used])
AC_MSG_RESULT($securid)
AM_CONDITIONAL(SECURID, test x$securid = xyes)

# NTLM
AC_ARG_ENABLE(ntlm,
  AS_HELP_STRING([--disable-ntlm], [don't use the NTLM mechanism]),
  ntlm=$enableval)
if test "$ntlm" != "no"; then
    AC_LIB_HAVE_LINKFLAGS(ntlm,, [#include <ntlm.h>],
      [buildSmbNtlmAuthRequest_noatsplit (0, 0, 0);])
  if test "$ac_cv_libntlm" != yes; then
    ntlm=no
    AC_MSG_WARN([Libntlm >= 0.3.5 not found, disabling NTLM.])
  else
    ntlm=yes
    AC_DEFINE(USE_NTLM, 1, [Define to 1 if you want NTLM.])
  fi
fi
AC_MSG_CHECKING([if NTLM should be used])
AC_MSG_RESULT($ntlm)
AM_CONDITIONAL(NTLM, test x$ntlm = xyes)

# CRAM-MD5
AC_ARG_ENABLE(cram-md5,
  AS_HELP_STRING([--disable-cram-md5], [don't use the CRAM-MD5 mechanism]),
  cram_md5=$enableval)
if test "$cram_md5" != "no" ; then
	cram_md5=yes
	AC_DEFINE(USE_CRAM_MD5, 1, [Define to 1 if you want CRAM-MD5.])
fi
AC_MSG_CHECKING([if CRAM-MD5 should be used])
AC_MSG_RESULT($cram_md5)
AM_CONDITIONAL(CRAM_MD5, test x$cram_md5 = xyes)

# DIGEST-MD5
AC_ARG_ENABLE(digest-md5,
  AS_HELP_STRING([--disable-digest-md5], [don't use the DIGEST-MD5 mechanism]),
  digest_md5=$enableval)
if test "$digest_md5" != "no" ; then
	digest_md5=yes
	AC_DEFINE(USE_DIGEST_MD5, 1, [Define to 1 if you want DIGEST-MD5.])
fi
AC_MSG_CHECKING([if DIGEST-MD5 should be used])
AC_MSG_RESULT($digest_md5)
AM_CONDITIONAL(DIGEST_MD5, test x$digest_md5 = xyes)

# SCRAM-SHA-1
AC_ARG_ENABLE(scram-sha1,
  AS_HELP_STRING([--enable-scram-sha1], [use the SCRAM-SHA-1 mechanism]),
  scram_sha1=$enableval)
if test "$scram_sha1" != "no" ; then
  scram_sha1=yes
  AC_DEFINE(USE_SCRAM_SHA1, 1, [Define to 1 if you want SCRAM-SHA-1.])
fi
AC_MSG_CHECKING([if SCRAM-SHA-1 should be used])
AC_MSG_RESULT($scram_sha1)

# SCRAM-SHA-256
AC_ARG_ENABLE(scram-sha256,
  AS_HELP_STRING([--enable-scram-sha256], [use the SCRAM-SHA-256 mechanism]),
  scram_sha256=$enableval)
if test "$scram_sha256" != "no" ; then
  scram_sha256=yes
  AC_DEFINE(USE_SCRAM_SHA256, 1, [Define to 256 if you want SCRAM-SHA-256.])
fi
AC_MSG_CHECKING([if SCRAM-SHA-256 should be used])
AC_MSG_RESULT($scram_sha256)

AM_CONDITIONAL(SCRAM, test "$scram_sha1$scram_sha256" != "nono")

# SAML20
AC_ARG_ENABLE(saml20,
  AS_HELP_STRING([--disable-saml20], [don't use the SAML20 mechanism]),
  saml20=$enableval, saml20=yes)
if test "$saml20" != "no" ; then
	saml20=yes
	AC_DEFINE(USE_SAML20, 1, [Define to 1 if you want SAML20.])
fi
AC_MSG_CHECKING([if SAML20 should be used])
AC_MSG_RESULT($saml20)
AM_CONDITIONAL(SAML20, test x$saml20 = xyes)

# OPENID20
AC_ARG_ENABLE(openid20,
  AS_HELP_STRING([--disable-openid20], [don't use the OPENID20 mechanism]),
  openid20=$enableval, openid20=yes)
if test "$openid20" != "no" ; then
	openid20=yes
	AC_DEFINE(USE_OPENID20, 1, [Define to 1 if you want OPENID20.])
fi
AC_MSG_CHECKING([if OPENID20 should be used])
AC_MSG_RESULT($openid20)
AM_CONDITIONAL(OPENID20, test x$openid20 = xyes)

# GS2, first part
AC_ARG_ENABLE(gs2,
  AS_HELP_STRING([--disable-gs2], [don't use the GS2 mechanism]),
  gs2=$enableval)
if test "$gs2" != "no" ; then
  gs2=yes
fi

# GSSAPI, first part
AC_ARG_ENABLE(gssapi,
  AS_HELP_STRING([--disable-gssapi], [don't use the GSSAPI mechanism]),
  gssapi=$enableval)
if test "$gssapi" != "no" ; then
  gssapi=yes
fi

# GSSAPI.
AC_ARG_WITH(gssapi-impl,
  AS_HELP_STRING([--with-gssapi-impl=no/gss/kfw/mit/heimdal/yes],
                 [select GSS-API implementation]),
  gssapi_impl=$withval, gssapi_impl=yes)
if test "$gs2" = no && test "$gssapi" = no; then
  gssapi_impl=no
else
  AC_MSG_NOTICE([checking for GSS implementation ($gssapi_impl)])
fi

if test "$gssapi_impl" = "gss"; then
  AC_MSG_NOTICE([trying GSS])
  AC_LIB_HAVE_LINKFLAGS(gss,, [#include <gss.h>], [
#if GSS_VERSION_NUMBER < 0x010000
too old version
#else
gss_check_version (0);
#endif
])
  if test "$ac_cv_libgss" != yes; then
    gssapi_impl=no
    AC_MSG_WARN([GNU GSS not found, disabling GSSAPI.])
  fi
elif test "$gssapi_impl" = "kfw"; then
  AC_MSG_NOTICE([trying MIT Kerberos for Windows GSS-API library])
  AC_LIB_HAVE_LINKFLAGS(gssapi32,, [#include <gssapi/gssapi.h>],
                        [gss_release_oid (NULL, NULL)])
  if test "$ac_cv_libgssapi32" != yes; then
    gssapi_impl=no
    AC_MSG_WARN([MIT Kerberos for Windows not found, disabling GSSAPI.])
  fi
elif test "$gssapi_impl" = "mit"; then
  AC_MSG_NOTICE([trying MIT])
  AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
  if test "$KRB5_CONFIG" != "no" ; then
    GSS_CFLAGS="`$KRB5_CONFIG --cflags`"
    GSS_LIBS="`$KRB5_CONFIG --libs gssapi`"
  else
    AC_MSG_WARN([MIT Kerberos krb5-config not found, disabling GSSAPI])
    gssapi_impl=no
  fi
elif test "$gssapi_impl" = "heimdal"; then
  AC_MSG_NOTICE([trying Heimdal])
  AC_PATH_PROG(KRB5_CONFIG, krb5-config, no)
  if test "$KRB5_CONFIG" != "no" ; then
    GSS_CFLAGS="`$KRB5_CONFIG --cflags`"
    GSS_LIBS="`$KRB5_CONFIG --libs gssapi`"
  else
    AC_MSG_WARN([Heimdal krb5-config not found, disabling GSSAPI])
    gssapi_impl=no
  fi
elif test "$gssapi_impl" != "no"; then
  AC_MSG_NOTICE([auto-detecting GSS/MIT/Heimdal])
  AC_MSG_NOTICE([use --with-gssapi-impl=IMPL to hard code])
  AC_MSG_NOTICE([where IMPL is `gss', `mit', or `heimdal'])
  AC_LIB_HAVE_LINKFLAGS(gss,, [#include <gss.h>], [
#if GSS_VERSION_NUMBER < 0x010000
too old version
#else
gss_check_version (0);
#endif
])
  if test "$ac_cv_libgss" = yes; then
    gssapi_impl=gss
    AC_MSG_NOTICE([GNU GSS found])
  elif test "$cross_compiling" != "no"; then
    AC_MSG_WARN([Cross-compiling, won't rely on MIT/Heimdal krb5-config])
    AC_MSG_NOTICE([Use --with-gssapi-impl=mit or --with-gssapi-impl=heimdal.])
    gssapi_impl=no
  else
    AC_MSG_WARN([GNU GSS not found (see http://www.gnu.org/software/gss/)...])
    AC_MSG_WARN([Auto-detecting MIT/Heimdal is unreliable, disabling GSSAPI])
    gssapi_impl=no
  fi
fi

AC_SUBST([GSS_CFLAGS])
AC_SUBST([GSS_LIBS])

# KERBEROS_V5
AC_ARG_ENABLE(kerberos_v5,
  AS_HELP_STRING([--enable-kerberos_v5],
    [use the KERBEROS_V5 mechanism]),
  kerberos_v5=$enableval, kerberos_v5=no)
if test "$kerberos_v5" != "no" ; then
  AC_LIB_HAVE_LINKFLAGS(shishi,, [#include <shishi.h>], [shishi ();])
  if test "$ac_cv_libshishi" != yes; then
    kerberos_v5=no
    AC_MSG_WARN([GNU Shishi not found, disabling KERBEROS_V5])
  else
    kerberos_v5=yes
    AC_DEFINE(USE_KERBEROS_V5, 1, [Define to 1 if you want KERBEROS_V5.])
  fi
fi
AC_MSG_CHECKING([if KERBEROS_V5 should be used])
AC_MSG_RESULT($kerberos_v5)
AM_CONDITIONAL(KERBEROS_V5, test x$kerberos_v5 = xyes)

# Check for libidn
AC_ARG_WITH(stringprep,
  AS_HELP_STRING([--without-stringprep], [disable non-ASCII support]),
  stringprep=$withval, stringprep=yes)
if test "$stringprep" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(idn,, [#include <stringprep.h>],
      [stringprep_check_version (0);])
  if test "$ac_cv_libidn" != yes; then
    stringprep=no
    AC_MSG_WARN([GNU Libidn not found.  Stringprep disabled.])
  else
    stringprep=yes
    save_LIBS="$LIBS"
    LIBS="$LIBS $LIBIDN"
    AC_CHECK_FUNCS(pr29_8z)
    AC_CHECK_HEADERS(pr29.h)
    LIBS="$save_LIBS"
  fi
fi
AC_MSG_CHECKING([if non-ASCII support via Libidn should be built])
AC_MSG_RESULT($stringprep)

# Allow disabling of client or server.
AC_ARG_ENABLE(client,
              AS_HELP_STRING([--disable-client], [disable client code]),
	      client=$enableval)
AC_ARG_ENABLE(server,
              AS_HELP_STRING([--disable-server], [disable server code]),
	      server=$enableval)
if test "$client" != "no"; then
  AC_DEFINE(USE_CLIENT, 1, [Define to 1 if you want client code.])
  client=yes
fi
if test "$server" != "no"; then
  AC_DEFINE(USE_SERVER, 1, [Define to 1 if you want server code.])
  server=yes
fi
if test "$server" = "no" && test "$client" = "no"; then
  AC_MSG_ERROR([Disabling both client and server mode is meaningless])
fi
AC_MSG_CHECKING([if client code should be built])
AC_MSG_RESULT($client)
AC_MSG_CHECKING([if server code should be built])
AC_MSG_RESULT($server)
AM_CONDITIONAL(CLIENT, test x$client = xyes)
AM_CONDITIONAL(SERVER, test x$server = xyes)

# Allow disabling of obsolete stuff.
AC_ARG_ENABLE(obsolete,
  AS_HELP_STRING([--disable-obsolete], [disable backwards compatibility code]),
    obsolete=$enableval)
if test "$obsolete" = "no"; then
  AC_DEFINE(GSASL_NO_OBSOLETE, 1,
    [Define to 1 if you don't want backwards compatibility code.])
else
  obsolete=yes
fi
AC_MSG_CHECKING([if backwards compatibility code should be present])
AC_MSG_RESULT($obsolete)
AM_CONDITIONAL(OBSOLETE, test "$obsolete" = "yes")

# For gnulib stuff in gl/ which may modify gssapi_impl, see gl/m4/gss-extra.m4.
gl_INIT
AC_DEFINE([GNULIB_NO_VLA], 1, [Disable VLA usage in gettext.h.])

# Disable GSSAPI/GS2 if we can't find GSS-API implementation
if test "$gssapi_impl" = "no"; then
  gs2=no
  gssapi=no
fi

# GS2, second part
if test "$gs2" != "no" ; then
  AC_DEFINE(USE_GS2, 1, [Define to 1 if you want GS2.])
fi
AC_MSG_CHECKING([if GS2 should be used])
AC_MSG_RESULT($gs2)
AM_CONDITIONAL(GS2, test x$gs2 = xyes)

# GSSAPI, second part
if test "$gssapi" != "no" ; then
  AC_DEFINE(USE_GSSAPI, 1, [Define to 1 if you want GSSAPI.])
fi
AC_MSG_CHECKING([if GSSAPI should be used])
AC_MSG_RESULT($gssapi)
AM_CONDITIONAL(GSSAPI, test x$gssapi = xyes)

sj_UPDATE_HEADER_VERSION([$srcdir/src/gsasl.h])

MAJOR_VERSION=`echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`
MINOR_VERSION=`echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`
PATCH_VERSION=`echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`
NUMBER_VERSION=`printf "0x%02x%02x%02x" $MAJOR_VERSION $MINOR_VERSION $PATCH_VERSION`
sj_UPDATE_HEADER([$srcdir/src/gsasl.h],
		 "s/VERSION_MAJOR .*/VERSION_MAJOR $MAJOR_VERSION/")
sj_UPDATE_HEADER([$srcdir/src/gsasl.h],
		 "s/VERSION_MINOR .*/VERSION_MINOR $MINOR_VERSION/")
sj_UPDATE_HEADER([$srcdir/src/gsasl.h],
		 "s/VERSION_PATCH .*/VERSION_PATCH $PATCH_VERSION/")
sj_UPDATE_HEADER([$srcdir/src/gsasl.h],
		 "s/VERSION_NUMBER .*/VERSION_NUMBER $NUMBER_VERSION/")

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
  gl_WARN_ADD([-Wframe-larger-than=800], [WSTACK_CFLAGS])
  gl_WARN_ADD([-Wno-deprecated-declarations], [WOBSOLETE_CFLAGS])
  gl_WARN_ADD([-Wno-unused-parameter], [WOBSOLETE_CFLAGS])

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

AC_CONFIG_FILES([
  Makefile
  anonymous/Makefile
  cram-md5/Makefile
  digest-md5/Makefile
  scram/Makefile
  saml20/Makefile \
  openid20/Makefile \
  external/Makefile
  gl/Makefile
  gltests/Makefile
  gs2/Makefile
  gssapi/Makefile
  kerberos_v5/Makefile
  libgsasl.pc
  login/Makefile
  ntlm/Makefile
  plain/Makefile \
  po/Makefile.in
  securid/Makefile
  src/Makefile
  tests/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of library build options:

  version:            ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
  Host/Target system: ${host}
  Build system:       ${build}
  Install prefix:     ${prefix}
  Compiler:           cc: ${CC} cflags: ${CFLAGS} cppflags: ${CPPFLAGS}
  Valgrind:           $opt_valgrind_tests ${VALGRIND}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
  Warning flags:      $gl_gcc_warnings werror $WERROR_CFLAGS wstack $WSTACK_CFLAGS warn $WARN_CFLAGS

  Obsolete functions: $obsolete

  Client side:        $client
  Server side:        $server

  Libidn:             $LTLIBIDN
  Libgcrypt:          $LIB_CRYPTO
  Libntlm:            $LTLIBNTLM
  GSS-API:            $gssapi_impl ltlibgss: $LTLIBGSS ltlibgssapi32: $LTLIBGSSAPI32 gss_libs: $GSS_LIBS

  ANONYMOUS:          $anonymous
  EXTERNAL:           $external
  PLAIN:              $plain
  LOGIN:              $login
  SECURID:            $securid
  NTLM:               $ntlm
  CRAM-MD5:           $cram_md5
  DIGEST-MD5:         $digest_md5
  SCRAM-SHA-1:        $scram_sha1
  SCRAM-SHA-256:      $scram_sha256
  SAML20:             $saml20
  OPENID20:           $openid20
  GS2:                $gs2
  GSSAPI:             $gssapi
])
