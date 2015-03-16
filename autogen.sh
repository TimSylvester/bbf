#!/bin/sh
mkdir m4 2>/dev/null
mkdir config 2>/dev/null
autoreconf --force --install -I config -I m4
