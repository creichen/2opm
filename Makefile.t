PREFIX=%%PREFIX%%
VERSION=%%VERSION%%
DIST=2opm-%%VERSION%%

.PHONY: default 2opm clean docs all

DISTFILES_DOCS=docs/2opm.tex docs/2opm.pdf docs/Makefile.t
DISTFILES_SRC=src/generate.py src/lexer.l src/*.c src/*.h src/Makefile.t
DISTFILES=configure.sh Makefile.t LICENCE README.md VERSION

default: all

all: 2opm docs

clean:
	rm -f bin/2opm
	cd src; make clean
	cd docs; make clean

docs:
	cd docs; make

2opm: bin/2opm

src/2opm:
	cd src; make 2opm

dist: 2opm docs
	rm -rf dist
	mkdir dist
	mkdir dist/${DIST}
	mkdir dist/${DIST}/docs
	mkdir dist/${DIST}/src
	cp ${DISTFILES} dist/${DIST}/
	cp ${DISTFILES_SRC} dist/${DIST}/src
	cp ${DISTFILES_DOCS} dist/${DIST}/docs
	cd dist; tar cvfz ${DIST}.tar.gz ${DIST}

bin/2opm: src/2opm
	mkdir bin || echo "Proceeding with existing directory"
	cp src/2opm bin/
