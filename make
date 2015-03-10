#!/bin/bash
CC=clang
WARN='-Wall -Wextra -pedantic-errors'
DBG='-ggdb -g3'
OPT='-O0'
LIBS='-lbitcoin -lboost_filesystem -lboost_system -lboost_regex -lsecp256k1 -lstdc++ -lm'
$CC -c -std=c++11 $WARN $OPT $DBG RandSecretGenerator.cpp && \
$CC $WARN $DBG $OPT -o RandSecretGenerator RandSecretGenerator.o $LIBS && \
$CC -c -std=c++11 $WARN $OPT $DBG -I../bloom -DBC_STATIC bbf.cpp && \
$CC $WARN $DBG $OPT -o bbf bbf.o $LIBS

