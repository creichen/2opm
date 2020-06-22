.PHONY: default 2opm clean docs all

default: all

all: 2opm docs

clean:
	cd src; make clean
	cd docs; make clean

docs:
	cd docs; make

2opm: bin/2opm

bin/2opm:
	cd src; make 2opm
	mkdir bin
	cp src/2opm bin/
