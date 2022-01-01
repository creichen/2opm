CC=%%CC%%
CFLAGS=%%CFLAGS%%
ARCH=%%ARCH%%
BIN_DIR=%%PREFIX%%/bin
LIB_DIR=%%PREFIX%%/lib
HEADER_DIR=%%PREFIX%%/include/2opm
CHASH_HEADER_DIR=%%PREFIX%%/include/chashtable
VERSION=%%VERSION%%
VERSION_MM=%%VERSION_MM%%
FLEX=flex

PYTHON=python3
GEN=generate.py

A2OPMBIN_OBJS=asm.o lexer.o parser.o lexer-support.o

GENSRC=registers.h registers.c assembler.h assembler.c \
     assembler-instructions.h assembler-instructions.c lexer.c

LIB2OPM_OBJS=builtins-registry.o builtins.o errors.o labels.o memory.o registers.o \
     assembler-buffer.o assembler.o assembler-instructions.o debugger.o
LIB2OPM_HEADERS=asm.h assembler.h assembler-buffer.h debugger.h errors.h registers.h

LIBCHASH_OBJS=chash.o
LIBCHASH_HEADERS=chash.h

.PHONY: default clean install uninstall test test-gen test-2opm

default: 2opm

2opm: ${GENSRC} ${A2OPMBIN_OBJS} lib2opm.a libchashtable.a
	${CC} ${A2OPMBIN_OBJS} lib2opm.a libchashtable.a -o 2opm

libchashtable.a: ${LIBCHASH_OBJS}
	ar rcs $@ $^

lib2opm.a: ${LIB2OPM_OBJS}
	ar rcs $@ $^

registers.c: registers.h ${GEN}
	${PYTHON} ${GEN} registers.c > $@

registers.h: ${GEN}
	${PYTHON} ${GEN} registers.h > $@

assembler.c: assembler.h ${GEN}
	${PYTHON} ${GEN} assembler.c > $@

assembler.h: ${GEN}
	${PYTHON} ${GEN} assembler.h > $@

assembler-instructions.c: assembler-instructions.h ${GEN}
	${PYTHON} ${GEN} assembler-instructions.c > $@

assembler-instructions.h: ${GEN}
	${PYTHON} ${GEN} assembler-instructions.h > $@

clean:
	rm -f 2opm
	rm -f libchashtable.a lib2opm.a
	rm -f *.o
	rm -f ${GENSRC}

install: 2opm
	mkdir -p ${BIN_DIR} || echo 'Binary directory exists'
	mkdir -p ${LIB_DIR} || echo 'Library directory exists'
	mkdir -p ${HEADER_DIR} || echo '2opm header directory exists'
	mkdir -p ${CHASH_HEADER_DIR} || echo 'CHash header directory exists'
	cp 2opm ${BIN_DIR}
	cp lib2opm.a ${LIB_DIR}
	cp libchashtable.a ${LIB_DIR}
	for n in ${LIB2OPM_HEADERS}; do cp $$n ${HEADER_DIR}; done
	for n in ${LIBCHASH_HEADERS}; do cp $$n ${CHASH_HEADER_DIR}; done

uninstall:
	rm -rf ${HEADER_DIR}
	rm -rf ${CHASH_HEADER_DIR}
	rm -f ${BIN_DIR}/2opm
	rm -f ${LIB_DIR}/lib2opm.a
	rm -f ${LIB_DIR}/libchashtable.a
	for n in ${LIB2OPM_HEADERS}; do rm -f ${HEADER_DIR}/$$n; done
	for n in ${LIBCHASH_HEADERS}; do rm -f ${CHASH_HEADER_DIR}/$$n; done

test: test-gen test-2opm

test-gen:
	${PYTHON} ./test_gen_assembly.py

test-2opm: 2opm
	./generate.py test ./2opm

%.o : %.c *.h
	${CC} -c ${CFLAGS} -DARCH=${ARCH} -DVERSION=\"${VERSION}\" $< -o $@

lexer.c: lexer.l
	if [ x`which ${FLEX}` != x ]; then $(FLEX) $(LFLAGS) -o $@ $^; fi # allow building if shipped with source even if flex is missing
