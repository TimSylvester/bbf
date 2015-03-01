#!/bin/bash
CC=clang
WARN='-Wall -Wextra -pedantic-errors'
DBG='-ggdb -g3'
OPT='-O3'
LIBS='-lbitcoin -lboost_filesystem -lboost_system -lboost_regex -lsecp256k1 -lstdc++ -lm'
$CC -c -std=c++11 $WARN $OPT $DBG -I../bloom -DBC_STATIC bbf.cc && \
$CC $WARN $DBG $OPT -o bbf -L/usr/local/lib bbf.o $LIBS

