# configure.ac for gladd
# 
# this file is part of GLADD
# 
# Copyright (c) 2012-2017 Brett Sheffield <brett@gladserv.com>
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
# along with this program (see the file COPYING in the distribution).
# If not, see <http://www.gnu.org/licenses/>.

# To build configure script:
#   autoconf configure.ac > configure

AC_INIT([gladd], [0.2.10], [brett@gladserv.com])
AC_CONFIG_SRCDIR([xml.c])
AC_PROG_CC
AC_LANG(C)
AC_PREFIX_DEFAULT([/usr/local/bin])
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# with arguments
AC_ARG_WITH(gnutls, [ --with-gnutls enable gnutls])
AC_ARG_WITH(ldif, [ --with-ldif enable ldif])
AC_ARG_WITH(openssl, [ --with-openssl enable openssl])
AC_ARG_WITH(postgres, [ --without-postgres disable postgres])
AC_ARG_WITH(mysql, [ --without-mysql disable mysql])
AC_ARG_WITH(tds, [ --without-tds disable tds support])
AC_ARG_WITH(openldap, [ --without-openldap disable openldap])
AC_ARG_WITH(xml, [ --without-xml disable xml support])
AC_ARG_WITH(librecast, [ --without-librecast disable librecast support])

withlibrecast=1
withauth=0
withpam=0
AC_CHECK_LIB([b64], [base64_decode_block], [withauth=1] , [withauth=0])
AC_CHECK_LIB([pam], [pam_authenticate], [withpam=1] , [withpam=0])
if test "$withauth" == "0"
then
        AC_MSG_NOTICE([b64 missing])
fi

if test "$withpam" == "0"
then
        AC_MSG_NOTICE([pam missing])
        withauth=0
fi

if test "$withauth" == "0"
then
        AC_MSG_NOTICE([****** disabling auth])
        AC_SUBST(auth, -D_NAUTH)
else
        AC_MSG_NOTICE([****** enabling auth])
        AC_SUBST(autho, auth.o)
        AC_SUBST(authtesto, auth_test.o)
        AC_SUBST(libpam, "-lpam -lpam_misc")
        AC_SUBST(lb64, -lb64)
fi

gladdb=0
AC_CHECK_LIB([gladdb], [db_connect], [gladdb=1] , [gladdb=0])
if test "$gladdb" == "0"
then
        AC_MSG_NOTICE([libgladdb missing, disabling])
        AC_SUBST(libgladdb, -D_NGLADDB)
        # disable backends
        with_mysql=no
        with_postgres=no
        with_ldap=no
        with_ldif=no
        with_tds=no
        gladdb_my=0
        gladdb_ldif=0
        gladdb_ldap=0
        gladdb_pg=0
        gladdb_tds=0
else
        AC_SUBST(dbtesto, db_test.o)
        AC_SUBST(lgladdb, -lgladdb)
        AC_CHECK_LIB(gladdb,[db_connect_my],gladdb_my=1,gladdb_my=0)
        AC_CHECK_LIB(gladdb,[process_ldif],gladdb_ldif=1,gladdb_ldif=0)
        AC_CHECK_LIB(gladdb,[db_connect_ldap],gladdb_ldap=1,gladdb_ldap=0)
        AC_CHECK_LIB(gladdb,[db_connect_pg],gladdb_pg=1,gladdb_pg=0)
        AC_CHECK_LIB(gladdb,[db_connect_tds],gladdb_tds=1,gladdb_tds=0)
fi

AC_CHECK_LIB([curl], [curl_easy_init], , AC_MSG_ERROR([libcurl required]))
AC_CHECK_LIB([pam], [pam_start])
AC_CHECK_LIB([pam_misc], [pam_misc_setenv])
# FIXME: Replace `main' with a function in `-lrt':
#AC_CHECK_LIB([rt], [main])
AC_CHECK_LIB([uuid], [uuid_generate],,AC_MSG_ERROR([uuid-dev required]))
AC_CHECK_LIB([xml2], [xmlDocSetRootElement],,AC_MSG_ERROR([xml2 required]))
AC_CHECK_LIB([xslt], [xsltApplyStylesheet],,AC_MSG_ERROR([xslt required]))

# choose SSL library
if test "$with_gnutls" == "yes"
then
	AC_CHECK_LIB([gnutls], [gnutls_global_init],
		AC_MSG_NOTICE([GNUTTLS enabled.])
		AC_SUBST(cflagssl, -D_GNUTLS)
		AC_SUBST(ssl, gnutls)
		AC_SUBST(libssl,["`pkg-config gnutls --cflags --libs`"])
	,
		AC_MSG_ERROR([gnutls required for --with-gnutls])
	)
elif test "$with_openssl" == "yes"
then
	AC_CHECK_LIB([ssl], [SSL_library_init],
		AC_MSG_NOTICE([OPENSSL enabled.])
		AC_SUBST(cflagssl, -D_OPENSSL)
		AC_SUBST(ssl, openssl)
		AC_SUBST(libssl,["`pkg-config --libs openssl`"])
	,
		AC_MSG_ERROR([openssl required for --with-openssl])
	)
else
        AC_MSG_NOTICE([No SSL library selected.  Disabling SSL.])
        AC_SUBST(ssl, tls)
fi

# backend support
if test "$with_mysql" == "no"
then
        gladdb_my=0
fi

if test "$gladdb_my" == "0"
then
	AC_MSG_NOTICE([disabling mysql support])
	AC_SUBST(mysql, -D_NMY)
else
	AC_SUBST(libmysql, ["`mysql_config --libs`"])
	AC_SUBST(cflagmysql, ["`mysql_config --cflags`"])
fi

if test "$with_ldif" == "no"
then
        gladdb_ldif=0
fi

if test "$gladdb_ldif" == "0"
then
	AC_MSG_NOTICE([disabling ldif support])
	AC_SUBST(ldif, -D_NLDIF)
else
	AC_CHECK_LIB([ldap],[ldap_parse_ldif_record],
	,
		AC_MSG_WARN([ldif not found - disabling])
		AC_SUBST(ldif, -D_NLDIF)
	)
	AC_SUBST(libldif, ["-lldap -llber"])
fi

if test "$with_openldap" == "no"
then
        gladdb_ldap=0
fi

if test "$gladdb_ldap" == "0"
then
	AC_MSG_NOTICE([disabling openldap support])
	AC_SUBST(openldap, -D_NLDAP)
else
	AC_CHECK_LIB([ldap], [ldap_initialize],
		AC_SUBST(libopenldap, -lldap)
	,
		AC_MSG_WARN([openldap not found - disabling])
		AC_SUBST(openldap, -D_NLDAP)
	)
fi

if test "$with_librecast" == "no"
then
	withlibrecast=0
fi

if test "$withlibrecast" == "0"
then
	AC_MSG_NOTICE([disabling librecast support])
	AC_SUBST(librecast, -D_NLIBRECAST)
else
	AC_CHECK_LIB([librecast], [lc_ctx_new],
		AC_SUBST(librecasto, librecast.o)
		AC_SUBST(liblibrecast, -llibrecast)
	,
		AC_MSG_WARN([librecast not found - disabling])
		AC_SUBST(librecast, -D_NLIBRECAST)
	)
fi

if test "$with_postgres" == "no"
then
        gladdb_pg=0
fi

if test "$gladdb_pg" == "0"
then
	AC_MSG_NOTICE([disabling postgres support])
	AC_SUBST(postgres, -D_NPG)
else
	AC_CHECK_LIB([pq], [PQconnectdb],
		AC_SUBST(incpostgres, -I/usr/include/postgresql)
		AC_SUBST(libpg, -lpq)
	,
		AC_MSG_WARN([postgres not found - disabling])
		AC_SUBST(postgres, -D_NPG)
	)
fi

if test "$with_tds" == "no"
then
        gladdb_tds=0
fi

if test "$gladdb_tds" == "0"
then
	AC_MSG_NOTICE([disabling tds support])
	AC_SUBST(tds, -D_NTDS)
else
	AC_CHECK_LIB([sybdb], [dbinit],
		AC_SUBST(libtds, -lsybdb)
	,
		AC_MSG_WARN([sybdb not found - disabling])
		AC_SUBST(tds, -D_NTDS)
	)
fi

# xml support (presently required)
if test "$with_xml" == "no"
then
	AC_MSG_NOTICE([disabling xml support])
	AC_SUBST(xml, -D_NXML)
else
	AC_SUBST(incxml, -I/usr/include/libxml2)
	AC_SUBST(libxml, -lxml2)
fi

AC_CHECK_LIB([git2], [git_blob_lookup], [git=1] , [git=0])
if test "$git" == "1"
then
        AC_SUBST(lgit2, -lgit2)
	AC_SUBST(git, -D_GIT)
else
	AC_SUBST(git, " ")
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h stdlib.h string.h sys/file.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memchr memmove memset mkdir socket strdup strerror strndup strrchr strstr strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
