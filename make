#!/bin/bash
CC=clang
WARN='-Wall -Wextra -pedantic-errors'
DBG='-ggdb -g3'
OPT='-O0'
LIBS='-lbitcoin -lboost_filesystem -lboost_system -lboost_regex -lsecp256k1 -lstdc++ -lm'
$CC -c -std=c++11 $WARN $OPT $DBG -o .obj/Sha2Generator.o Sha2Generator.cpp && \
$CC $WARN $DBG $OPT -o bin/Sha2Generator .obj/Sha2Generator.o $LIBS && \
$CC -c -std=c++11 $WARN $OPT $DBG -o .obj/RandSecretGenerator.o RandSecretGenerator.cpp && \
$CC $WARN $DBG $OPT -o bin/RandSecretGenerator .obj/RandSecretGenerator.o $LIBS && \
$CC -c -std=c++11 $WARN $OPT $DBG -I../bloom -DBC_STATIC -o .obj/bbf.o bbf.cpp && \
$CC $WARN $DBG $OPT -o bin/bbf .obj/bbf.o $LIBS

