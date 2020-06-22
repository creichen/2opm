PREFIX=%%PREFIX%%

.PHONY: default 2opm clean docs all

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

bin/2opm: src/2opm
	mkdir bin || echo "Proceeding with existing directory"
	cp src/2opm bin/
