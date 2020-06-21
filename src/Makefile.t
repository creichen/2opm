CC=%%CC%%
CFLAGS=%%CFLAGS%%
ARCH=%%ARCH%%
PREFIX=%%PREFIX%%
FLEX=flex

PYTHON=python3
GEN=generate.py

OBJS=address-store.o asm-builtins.o asm.o asm-errors.o asm-labels.o asm-lexer.o asm-memory.o asm-parse.o \
     assembler-buffer.o assembler.o assembler-instructions.o chash.o debugger.o lexer-support.o registers.o

GENSRC=assembler.h assembler.c assembler-instructions.h assembler-instructions.c asm-lexer.c

.PHONY: default clean

default: 2opm

2opm: ${GENSRC} ${OBJS}
	${CC} ${OBJS} -o 2opm

assembler.c: assembler.h
	${PYTHON} ${GEN} code > $@

assembler.h:
	${PYTHON} ${GEN} headers > $@

assembler-instructions.c: assembler-instructions.h
	${PYTHON} ${GEN} assembler > $@

assembler-instructions.h:
	${PYTHON} ${GEN} assembler-header > $@

clean:
	rm -f 2opm
	rm -f *.o
	rm -f ${GENSRC}

%.o : %.c
	${CC} -c ${CFLAGS} -DARCH=${ARCH} $< -o $@

2opm/asm-lexer.c: 2opm/asm-lexer.l
	# allow building if shipped with source even if flex is missing
	if [ x`which ${FLEX}` != x ]; then $(FLEX) $(LFLAGS) -o $@ $^; fi
