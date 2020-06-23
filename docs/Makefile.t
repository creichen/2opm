DOC_DIR=%%PREFIX%%/share/doc/2opm-%%VERSION_MM%%
VERSION=%%VERSION%%
VERSION_MM=%%VERSION_MM%%
PYTHON=python3
GENERATE=../src/generate.py

.PHONY: all clean install uninstall

all: 2opm.pdf

2opm.pdf: asm-ops.tex 2opm.sty
	echo ${VERSION} > version.tex
	pdflatex 2opm.tex
	pdflatex 2opm.tex

2opm.sty: ${GENERATE}
	${PYTHON} ${GENERATE} latex-sty > $@

clean:
	rm -f 2opm.pdf
	rm -f *.out *.log *.aux

install: 2opm.pdf
	mkdir -p ${DOC_DIR} || echo 'Documentation directory exists'
	cp 2opm.pdf ${DOC_DIR}
	cp ../LICENCE ${DOC_DIR}
	cp ../README.md ${DOC_DIR}
	cp ../VERSION ${DOC_DIR}

uninstall:
	rm -rf ${DOC_DIR}

asm-ops.tex: ${GENERATE}
	${PYTHON} ${GENERATE} latex > $@
