AC_PREREQ([2.69])
AC_INIT(bbf, 0.1, no@no.no)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/bbf.cpp])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall])

AC_LANG([C++])
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

LT_PREREQ([2.2.6])
LT_INIT([disable-static])

dnl AC_CHECK_LIB([m])

AC_CHECK_HEADERS([sstream])

AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_FUNC_ERROR_AT_LINE

# Boost
#------

BOOST_REQUIRE([1.54],, [AC_MSG_ERROR([Boost 1.54 is required])])
BOOST_SYSTEM([mt])
BOOST_FILESYSTEM([mt])
BOOST_REGEX([mt])

# Required libraries
#-------------------

PKG_CHECK_MODULES([secp256k1], [libsecp256k1 >= 0.0.1])
AC_SUBST([secp256k1_PKG], ['libsecp256k1 >= 0.0.1'])
AC_SUBST([secp256k1_CPPFLAGS], [${secp256k1_CFLAGS}])
AC_MSG_NOTICE([secp256k1_CPPFLAGS : ${secp256k1_CPPFLAGS}])
AC_MSG_NOTICE([secp256k1_LIBS : ${secp256k1_LIBS}])

PKG_CHECK_MODULES([bitcoin], [libbitcoin >= 0.0.1])
AC_SUBST([bitcoin_PKG], ['libbitcoin >= 0.0.1'])
AC_SUBST([bitcoin_CPPFLAGS], [${bitcoin_CFLAGS}])
AC_MSG_NOTICE([bitcoin_CPPFLAGS : ${bitcoin_CPPFLAGS}])
AC_MSG_NOTICE([bitcoin_LIBS : ${bitcoin_LIBS}])


# Debug support
#--------------
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],
	[enable debug data generation (def=no)])],
	[debugit="$enableval"],
	[debugit=no])
AC_MSG_RESULT([$debugit])
if test x"$debugit" = x"yes"; then
	AC_DEFINE([DEBUG],[],[Debug Mode])
	AM_CXXFLAGS="$AM_CXXFLAGS -g -O0"
else
	AC_DEFINE([NDEBUG],[],[No-debug Mode])
	AM_CXXFLAGS="$AM_CXXFLAGS -O3"
fi
AC_SUBST([AM_CXXFLAGS])


AC_CONFIG_FILES([Makefile src/Makefile])
AC_CONFIG_SUBDIRS([])
AC_OUTPUT
