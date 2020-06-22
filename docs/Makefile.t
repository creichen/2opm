PREFIX=%%PREFIX%%
PYTHON=python3
GENERATE=../src/generate.py

.PHONY: all clean

all: 2opm.pdf

2opm.pdf: asm-ops.tex 2opm.sty
	pdflatex 2opm.tex
	pdflatex 2opm.tex

2opm.sty: ${GENERATE}
	${PYTHON} ${GENERATE} latex-sty > $@

clean:
	rm -f 2opm.pdf
	rm -f *.out *.log *.aux

asm-ops.tex: ${GENERATE}
	${PYTHON} ${GENERATE} latex > $@
