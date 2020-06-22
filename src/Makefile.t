CC=%%CC%%
CFLAGS=%%CFLAGS%%
ARCH=%%ARCH%%
PREFIX=%%PREFIX%%
VERSION=%%VERSION%%
VERSION_MM=%%VERSION_MM%%
FLEX=flex

PYTHON=python3
GEN=generate.py

A2OPMBIN_OBJS=asm.o lexer.o parser.o lexer-support.o

GENSRC=assembler.h assembler.c assembler-instructions.h assembler-instructions.c lexer.c

LIB2OPM_OBJS=builtins-registry.o builtins.o errors.o labels.o memory.o registers.o \
     assembler-buffer.o assembler.o assembler-instructions.o debugger.o
LIB2OPM_HEADERS=asm.h assembler.h assembler-buffer.h debugger.h errors.h registers.h

LIBCHASH_OBJS=chash.o
LIBCHASH_HEADERS=chash.h

.PHONY: default clean

default: 2opm

2opm: ${GENSRC} ${A2OPMBIN_OBJS} lib2opm.a libchash.a
	${CC} ${A2OPMBIN_OBJS} lib2opm.a libchash.a -o 2opm

libchash.a: ${LIBCHASH_OBJS}
	ar rcs $@ $^

lib2opm.a: ${LIB2OPM_OBJS}
	ar rcs $@ $^

assembler.c: assembler.h ${GEN}
	${PYTHON} ${GEN} code > $@

assembler.h: ${GEN}
	${PYTHON} ${GEN} headers > $@

assembler-instructions.c: assembler-instructions.h ${GEN}
	${PYTHON} ${GEN} assembler > $@

assembler-instructions.h: ${GEN}
	${PYTHON} ${GEN} assembler-header > $@

clean:
	rm -f 2opm
	rm -f libchash.a lib2opm.a
	rm -f *.o
	rm -f ${GENSRC}

%.o : %.c *.h
	${CC} -c ${CFLAGS} -DARCH=${ARCH} -DVERSION=\"${VERSION}\" $< -o $@

lexer.c: lexer.l
	if [ x`which ${FLEX}` != x ]; then $(FLEX) $(LFLAGS) -o $@ $^; fi # allow building if shipped with source even if flex is missing
