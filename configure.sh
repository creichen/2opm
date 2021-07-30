#! /bin/bash

CC_DEFAULT="gcc"
CFLAGS_DEFAULT="-O3 -Wall -Werror"
ARCH_DEFAULT=`uname -m`
PREFIX_DEFAULT="/usr/local/"
VERSION=`cat VERSION`

DIRECTORIES=". src docs"

if [ x$1 != x ]; then
    echo "Usage: $0"
    echo "Builds all required Makefiles.  You can set the following environment variables:"
    echo "  CC    : override C compiler [${CC_DEFAULT}]"
    echo "  CFLAGS: override C compiler flags [${CFLAGS_DEFAULT}]"
    echo "  PREFIX: Installation prefix [${PREFIX_DEFAULT}]"
    echo "  ARCH  : override target architecture [${ARCH_DEFAULT}]"
    exit 0
fi

if [ x${CC} == x ]; then
    CC=${CC_DEFAULT}
fi

if [[ x${CFLAGS} == x ]]; then
    CFLAGS=${CFLAGS_DEFAULT}
fi

if [ x${ARCH} == x ]; then
    ARCH=${ARCH_DEFAULT}
fi

if [ x${PREFIX} == x ]; then
    PREFIX=${PREFIX_DEFAULT}
fi

if [ ${ARCH} != x86_64 ]; then
    echo "Unsupported architecture: ${ARCH}"
    echo "Sorry, this package will not work on your CPU without porting."
    exit 1
fi

ESCAPED_PREFIX=`echo $PREFIX | sed 's/\//\\\\\//g'`
if [ x${VERSION} == x ]; then
    echo "Missing VERSION file!"
    exit 1
fi

VERSION_MM=`echo ${VERSION} | sed 's/\.[0-9a-zA-Z_-]\+$//'`

echo "Configuring version ${VERSION} ..."

for M in ${DIRECTORIES}; do
    cat $M/Makefile.t \
	| sed "s/%%CC%%/${CC}/" \
	| sed "s/%%CFLAGS%%/${CFLAGS}/" \
	| sed "s/%%ARCH%%/${ARCH}/" \
	| sed "s/%%PREFIX%%/${ESCAPED_PREFIX}/" \
	| sed "s/%%VERSION%%/${VERSION}/" \
	| sed "s/%%VERSION_MM%%/${VERSION_MM}/" \
	      > $M/Makefile
    echo "..." $M/Makefile
done
