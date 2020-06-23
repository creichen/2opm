# 2OPM: Two-Operand Pseudo MIPS Assembly for amd64 / x86-64

2OPM is an educational project to extract and simplify core parts of
the amd64 ISA into a "MIPS-like" set of instructions.  In other words,
it lets you program your x86-64 / amd64 CPU (almost) directly with a
thin (and often invisible) translation layer, in an attempt to make
the instruction set smaller and quicker to learn.

Target audience: instructors teaching compilers / programming language
implementation courses, and students interested in learning assembly
programming.

Features:
- Stand-alone run-time (runs only from source assembly files, for now,
  but saving to / loading machine code images is planned)
- C API for dynamically generating machine code, suitable e.g. for
  writing a just-in-time compiler
- interactive debugger at the level of 2opm assembly

# Installing 2opm

Dependencies:
- x86-64 or amd64 CPU
- A sufficiently "UNIX-y" system (Linux works fine, FreeBSD should work,
  OS X worked in the past but hasn't been tested in a while)
  - Python3 (used only to generate code and documentation)
  - bash
  - A C compiler (currently defaults to gcc, but you can override by setting `CC`)
  - GNU Make or something similar
  - pdflatex for building the documentation
  - flex, the lexer genreator (not needed for packages built via `make dist`)

To build and run locally:

```
./configure.sh && make
./bin/2opm examples/hello.s
```

Or to install:

```
PREFIX=install/dir ./configure.sh && make && make install
```

To build the source package for distribution:

```
make dist
```


# Using 2opm

Running 2opm on an assembly file automatically assembles and
executes the file:

```
./bin/2opm <sourcefile.s>
```

or, to run it in the interactive debugger:

```
./bin/2opm -d <sourcefile.s>
```

## Overview

2opm renames the x86-64 registers to MIPS-style register names:

| Name                         | Purpose              |
|------------------------------|----------------------|
| $v0                          | Return Value         |
| $a0, $a1, $a2, $a3, $a4, $a5 | Arguments            |
| $s0, $s1, $s2, $s3           | Saved registers      |
| $t0, $t1                     | Temporary registers  |
| $sp                          | Stack Pointer        |
| $fp                          | Frame Pointer        |
| $gp                          | Global Pointer       |


## Example

Below is a program that translates the string "Hello, World!" to uppercase and prints it:

```
.text
main:
    	subi $sp, 24
        sd   $fp, -16($sp)
        sd   $s0, -8($sp)

    	move $a1, $gp
    	addi $a1, string     ; output string buffer
    	move $t1, $a1
    	li   $s0, 0x40
        li   $a2, 0          ; length
loop:
    	lb   $t0, 0($t1)
    	beqz $t0, done_loop
        addi $a2, 1
    	ble  $t0, $s0, skip
    	andi $t0, 0x5f
skip:
    	sb   $t0, 0($t1)
    	addi $t1, 1
    	j loop
done_loop:
        li   $v0, 1	         ; syscall 1 (Linux only) is write()
        li   $a0, 0          ; stdout
        syscall

        ld   $s0, -8($sp)
        ld   $fp, -16($sp)
        addi $sp, 24
    	jreturn
.data
.asciiz
string:
    	"Hello, World!\n"
```
Use syscall 4 to run this on OS X instead.
For portable input and output, 2opm provides a small set of
built-in subroutines that are automatically linked against
any code.

## Documentation

Refer to docs/2opm.pdf for complete documentation.
