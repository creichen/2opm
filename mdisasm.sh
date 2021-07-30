#! /bin/bash

TMPFILE=`mktemp`
TMPFILE2=`mktemp`
src/2opm -p $1 > ${TMPFILE}
cat ${TMPFILE} | awk --field-separator='\t' '{printf "db_0x%s\n", substr($2,2)}' | sed 's/ *$//g' | sed 's/ /, 0x/g' | tr '_' ' ' | awk 'BEGIN {n=0; printf "bits 64\nglobal _start\nsection .text\n_start:\n"} // {print "in AL, ", (n++); print $0}' > tmp.s
nasm tmp.s -f elf64 -o tmp.o && objdump -M intel -d tmp.o > ${TMPFILE2}
cat ${TMPFILE} ${TMPFILE2}  | awk 'BEGIN {n = 0; mode=0 } /^000000000/ {mode=1}  /e4 .*in *al,/ {print a[$3]; skip=1 } // { if (skip) { skip = 0 } else { if (mode == 0) { a[sprintf("%02x", n++)] = $0 } else printf "\033[1;34m%s\033[0m\n", $0 } }'
rm ${TMPFILE2}
rm ${TMPFILE}

