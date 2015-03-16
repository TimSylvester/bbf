AM_CPPFLAGS = -std=c++11 -DHAVE_CONFIG_H -I$(top_srcdir)

noinst_PROGRAMS = bbf
bbf_SOURCES = bbf.cpp
bbf_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/../bloom
bbf_LDADD = -lbitcoin -lsecp256k1 -lboost_system -lboost_regex -lboost_filesystem




