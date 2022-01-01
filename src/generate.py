#! /usr/bin/env python3
# This file is Copyright (C) 2014, 2020, 2021 Christoph Reichenbach
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the
#   Free Software Foundation, Inc.
#   59 Temple Place, Suite 330
#   Boston, MA  02111-1307
#   USA
#
# The author can be reached as "creichen" at the usual gmail server.

import sys
import amd64
import registers
import gen_assembly
import instruction_set

arch = amd64

try:
    from termcolor import colored
except:
    def colored(text, *col):
        return text

instructions = instruction_set.build_for(arch.MISet)

mkp = gen_assembly.mkp
make_prln = gen_assembly.make_prln

def print_usage():
    print('usage: ')
    for n in ['assembler.h', 'assembler.c', 'latex', 'assembler-instructions.c', 'assembler-instructions.h', 'registers.c', 'registers.h', 'test <path-to-2opm-binary> [optional-list-of-comma-separated-insns]']:
        print('\t' + sys.argv[0] + ' ' + n)

def print_warning(prln=print):
    prln('// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!')

def print_header_header():
    print('#include "assembler-buffer.h"')
    print('#include <stdio.h>')
    print('#include <stdint.h>')

def print_code_header():
    print('''
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "assembler-buffer.h"
#include "debugger.h"
#include "registers.h"

static int32_t
decode_int32_t(void* mem) {
	int32_t v;
	memcpy(&v, mem, sizeof(int32_t));
	return v;
}
''')

def print_tab_aligned(table : list[tuple[str, str]], prln=print):
    # max len of first column:
    maxlen = max(len(row[0]) for row in table)
    def add_tab_len(v):
        return (v + 8) & ~0x7
    tablen = add_tab_len(maxlen)

    for (k, v) in table:
        klen = len(k)
        k += '\t'
        klen = add_tab_len(klen)

        while klen < tablen:
            k += '\t'
            klen += 8

        prln(k + v)


def print_offset_calculator_header(trail=';'):
    print('int')
    print('asm_arg_offset(char *insn, asm_arg *args, int arg_nr)' + trail)


def print_assembler_header(prln=print):
    print("""// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#ifndef A2OPM_INSTRUCTIONS_H
#define A2OPM_INSTRUCTIONS_H

#include "assembler-buffer.h"

typedef union {
	label_t *label;
	int r;			// register nr
	unsigned long long imm;	// immediate
} asm_arg;

""")

    count = 1
    table = [('#define ASM_ARG_ERROR', '0')]

    for mtype in gen_assembly.MachineArgType.ALL:
        table.append((f'#define {mtype.asm_arg}', '%d' % count))
        count += 1

    print_tab_aligned(table, prln=print)

    print('''

/**
 * Returns the number of arguments, or -1 if the instruction is unknown
 */
int
asm_insn_get_args_nr(char *insn);

/**
 * Decodes the type of the specified argument
 */
int
asm_insn_get_arg(char *insn, int arg_nr);

/**
 * Issues a single instruction.  No error checking is performed.
 */
void
asm_insn(buffer_t *buf, char *insn, asm_arg *args, int args_nr);

/**
 * Computes the offset of the `arg_nr'th argument in the given instruction, or -1 if it has no unique memory offset
 */
''')
    print_offset_calculator_header()
    print("#endif // !defined(A2OPM_INSTRUCTIONS_H)")

def print_assembler_module(prln=print):
    print(f'''
// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#include <ctype.h>
#include <stdio.h>
#include <strings.h>

#include "assembler-buffer.h"
#include "assembler.h"
#include "assembler-instructions.h"

#define INSTRUCTIONS_NR {len(instructions)}
#define ARGS_MAX { max(len(i.args) for i in instructions) }

static struct {{
	char *name;
	int args_nr;
	int args[ARGS_MAX];
}} instructions[INSTRUCTIONS_NR] = {{''')
    for insn in instructions:
        args = insn.args
        print ('\t{{ .name = "{name}", .args_nr = {args_nr}, .args = {{ {args} }} }},'
               .format(name = insn.name,
                       args_nr = len(insn.args),
                       args = ', '.join(a.mtype.asm_arg for a in args)))
    print('};')

    print('''
int
asm_insn_get_args_nr(char *insn)
{
	for (int i = 0; i < INSTRUCTIONS_NR; i++) {
		if (0 == strcasecmp(insn, instructions[i].name)) {
			return instructions[i].args_nr;
		}
	}
	return -1;
}

int
asm_insn_get_arg(char *insn, int arg_nr)
{
	for (int i = 0; i < INSTRUCTIONS_NR; i++) {
		if (0 == strcasecmp(insn, instructions[i].name)) {
			if (arg_nr < 0 || arg_nr >= instructions[i].args_nr) {
				return -1;
			} else {
				return instructions[i].args[arg_nr];
			}
		}
	}
	return -1;
}

void
asm_insn(buffer_t *buf, char *insn, asm_arg *args, int args_nr)
{''')
    def search_tree(action, insns, prln, prefix=''):

        depth = len(prefix)
        choices = []
        match = None

        action_triggered = False # did we locally or recursively trigger an action?
        prln_temp = make_prln()

        handled_trees = set()
        for insn in instructions:
            name = insn.name + '\0'
            if name[:depth].upper() != prefix.upper():
                continue

            if name.upper() == prefix:
                match = insn
            else:
                rest = name.upper()[depth:]
                key = rest[0]
                if key in handled_trees:
                    continue
                handled_trees = handled_trees | set([key])
                new_prefix = prefix + key
                keymark = '\\0' if key == '\0' else key

                prln_recurse_temp = make_prln()
                p = mkp(depth + 1, prln=prln_recurse_temp)

                p(f"if (toupper(insn[{depth}]) == '{keymark}') {{")
                triggered = search_tree(action = action,
                                        insns = [i for i in insns if i.name[depth+1:].upper() == new_prefix],
                                        prln = prln_recurse_temp,
                                        prefix = new_prefix)
                if triggered:
                    p("}")
                    prln_recurse_temp.print_all(prln_temp)
                    action_triggered = True
        if match:
            prln_temp2 = make_prln()
            action(match, mkp(depth + 1, prln=prln_temp2))
            if not prln_temp2.is_empty():
                prln_temp2.print_all(prln_temp)
                action_triggered = True
            else:
                prln_temp2.print_all(print)
        if action_triggered:
            prln_temp.print_all(prln)
        # otherwise, nothing we did here was relevant: forget the output

        return action_triggered


    def gen_arg(insn, arg):
        index = insn.argindex(arg)
        if arg.mtype.kind == 'r':
            field = 'r'
        elif arg.mtype.kind == 'i':
            field = 'imm'
        elif arg.mtype.kind == 'a':
            field = 'label'
        else:
            raise Exception('Unknown argument type: %s' % arg.mtype.kind)
        return f'args[{index}].{field}'

    def action_emit(insn, p):
        args = ', '.join(['buf'] + [gen_arg(insn, arg) for arg in insn.args])
        p(f'{insn.c_emit_fn}({args});')
        p(f'return;')

    searchtree = search_tree(action_emit, instructions, prln)

    print('\tfprintf(stderr, "Unknown instruction: %s\\n", insn);')
    print('\treturn;')
    print('}')
    print('')
    print_offset_calculator_header('')
    print('{')

    def action_return_offsets(insn, p):
        for arg in insn.args:
            offset = insn.arg_offset(arg)
            if offset is not None:
                arg_access = insn.argindex(arg)
                p(f'if (arg_nr == {arg_access}) return {offset};')

    search_tree(action_return_offsets, instructions, prln)

    print('\treturn -1;')
    print('}')

def print_docs():
    print('\\begin{tabular}{llp{8cm}}')
    print('\\small')
    for i in instructions:
        [a,b,c] = i.gen_LaTeX_table()
        print(a + '&\t' + b + '&\t' + c + '\\\\')
    print('\\end{tabular}')

def print_sty():
    insn_names = [i.name for i in instructions]
    print('''
\\lstdefinelanguage[2opm]{{Assembler}}%
{{morekeywords=[1]{{{KW}}},%
morekeywords=[2]{{.asciiz,.data,.text,.byte,.word}},%
comment=[l]\\#%
}}[keywords,strings,comments]
'''.format(KW=','.join(insn_names)))


class RegisterFile:
    def __init__(self):
        self.regs = registers.REGISTERS
        self.mach_regs = instructions.machine_insn_set.registers
        self.mach_regmap = instructions.machine_insn_set.register_mapping

    def native(self, reg):
        return self.mach_regmap[reg]

    @property
    def temps(self):
        return [reg for reg in self.regs if reg.is_temp]

    @property
    def args(self):
        return [reg for reg in self.regs if reg.category == registers.ARG]

    @property
    def callee_saved(self):
        return [reg for reg in self.regs if reg.callee_saved]


def print_registers_h(prln=print):
    print_warning(prln=prln)
    rf = RegisterFile()

    regnames = []
    for reg in rf.regs:
        rs = reg.name[1:].upper()
        regnames.append(f'#define REGISTER_{rs}	{rf.native(reg).num}')

    regnames = '\n'.join(regnames)

    print(f'''

#ifndef _A2OPM_REGISTERS_H
#define _A2OPM_REGISTERS_H

// Number of supported registers
#define REGISTERS_NR		{len(rf.regs)}
// Number of native machine register (may be a superset)
#define REGISTERS_NATIVE_NR	{len(rf.mach_regs)}

// Register names
{regnames}

#define REGISTERS_TEMP_NR		{len(rf.temps)}	// Caller-saved (not including args/special registers)
#define REGISTERS_CALLEE_SAVED_NR	{len(rf.callee_saved)}	// Callee-saved
#define REGISTERS_ARGUMENT_NR		{len(rf.args)}	// Arguments

typedef struct {{
	char *native; // native register name
	char *mips;   // 2OPM name
}} regname_t;

extern regname_t register_names[REGISTERS_NATIVE_NR];
extern int registers_ALL[REGISTERS_NR];
extern int registers_temp[REGISTERS_TEMP_NR];
extern int registers_callee_saved[REGISTERS_CALLEE_SAVED_NR];
extern int registers_argument[REGISTERS_ARGUMENT_NR];


#endif // !defined(_A2OPM_REGISTERS_H)
''')


def print_registers_c(prln=print):
    print_warning(prln=prln)
    rf = RegisterFile()

    regnames = []
    num = 0
    for mreg in rf.mach_regs:
        assert mreg.num == num
        num += 1
        suffix = '};' if mreg == rf.mach_regs[-1] else ','
        pname = mreg.name2opm
        if pname is None:
            pname = '$_%d' % pname.num
            suffix += '\t// not mapped'
        regnames.append(f'	{{"{mreg.name}",	"{pname}"}}{suffix}')
    regnames = '\n'.join(regnames)

    def listify_native_regnums(regs):
        return ', '.join('%s' % rf.native(r).num for r in regs)

    prln(f'''
#include "registers.h"

regname_t register_names[REGISTERS_NR] = {{
{regnames}

int registers_callee_saved[REGISTERS_CALLEE_SAVED_NR] = {{
	{listify_native_regnums(rf.callee_saved)}
}};

int registers_temp[REGISTERS_TEMP_NR] = {{
	{listify_native_regnums(rf.temps)}
}};

int registers_argument[REGISTERS_ARGUMENT_NR] = {{
	{listify_native_regnums(rf.args)}
}};
''')


def run_tests(binary, names):
    insns = 0
    tested = 0
    failed = 0
    skipped = []
    notest = []
    for insn in instructions:
        if names != [] and insn.name not in names:
            skipped.append(insn.name)
            continue
        insns += 1
        if insn.test is None:
            notest.append(insn.name)
        else:
            tested += 1
            print('Testing %s:' % insn.name)
            did_fail = 0 if insn.test.run(binary, insn) else 1
            if did_fail == 1:
                print(colored('  FAILED', 'red'))
            else:
                print(colored('  OK', 'green'))
            failed += did_fail
    print('insns = %d | tested = %d | failed = %d' % (insns, tested, failed))
    if len(skipped):
        print('Skipped: ' + ', '.join(skipped))
    if len(notest):
        print('No tests available: ' + ', '.join(notest))
    sys.exit(1 if failed > 0 else 0)

if len(sys.argv) > 1:
    if sys.argv[1] == 'assembler.h':
        print_warning()
        print_header_header()
        for insn in instructions:
            insn.print_encoder_header()
        instructions.print_disassembler_doc()
        instructions.print_disassembler_header()

    elif sys.argv[1] == 'assembler.c':
        print_warning()
        print_code_header()
        for insn in instructions:
            insn.print_encoder()
            print("\n")
        instructions.print_disassembler(arch.MISet)

    elif sys.argv[1] == 'latex':
        print_docs()

    elif sys.argv[1] == 'latex-sty':
        print_sty()

    elif sys.argv[1] == 'assembler-instructions.c':
        print_assembler_module()

    elif sys.argv[1] == 'assembler-instructions.h':
        print_assembler_header()

    elif sys.argv[1] == 'registers.c':
        print_registers_c()

    elif sys.argv[1] == 'registers.h':
        print_registers_h()

    elif sys.argv[1] == 'test':
        run_tests(sys.argv[2], sys.argv[3:])

    else:
        print_usage()

else:
    print_usage()
