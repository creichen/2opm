CC=%%CC%%
CFLAGS=%%CFLAGS%%
ARCH=%%ARCH%%
PREFIX=%%PREFIX%%
VERSION=%%VERSION%%
VERSION_MM=%%VERSION_MM%%
FLEX=flex

PYTHON=python3
GEN=generate.py

OBJS=builtins-registry.o builtins.o asm.o errors.o labels.o lexer.o memory.o parser.o \
     assembler-buffer.o assembler.o assembler-instructions.o chash.o debugger.o lexer-support.o registers.o

GENSRC=assembler.h assembler.c assembler-instructions.h assembler-instructions.c lexer.c

.PHONY: default clean

default: 2opm

2opm: ${GENSRC} ${OBJS}
	${CC} ${OBJS} -o 2opm

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
	rm -f *.o
	rm -f ${GENSRC}

%.o : %.c *.h
	${CC} -c ${CFLAGS} -DARCH=${ARCH} -DVERSION=\"${VERSION}\" $< -o $@

lexer.c: lexer.l
	if [ x`which ${FLEX}` != x ]; then $(FLEX) $(LFLAGS) -o $@ $^; fi # allow building if shipped with source even if flex is missing
