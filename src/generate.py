#! /usr/bin/env python3
# This file is Copyright (C) 2014, 2020 Christoph Reichenbach
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

# assume 16 registers total

import subprocess
import sys
import tempfile
from amd64 import * #FIXME
import amd64

try:
    from termcolor import colored
except:
    def colored(text, *col):
        return text


# class Insn(object):
#     emit_prefix = LIB_PREFIX + "emit_"

#     def __init__(self, name, descr, machine_code, args, test=None):
#         self.name = name
#         self.descr = descr
#         self.function_name = name
#         self.is_static = False
#         self.machine_code = machine_code
#         assert type(machine_code) is list
#         self.args = args
#         assert type(args) is list
#         self.format_string = None # optional format string override
#         self.test = test

#         arg_type_counts = {}
#         for arg in self.args:
#             if arg is not None:
#                 n = arg.strGenericName()
#                 if n not in arg_type_counts:
#                     arg_type_counts[n] = 1
#                 else:
#                     arg_type_counts[n] += 1

#         arg_type_multiplicity = dict(arg_type_counts)

#         # name the arguments
#         revargs = list(args)
#         revargs.reverse()
#         for arg in revargs:
#             if arg is not None:
#                 n = arg.strGenericName()
#                 if n is None:
#                     raise Exception('Cannot stringify arg %s' % arg)
#                 if arg_type_multiplicity[n] > 1:
#                     arg.setName(n + str(arg_type_counts[n]))
#                     arg_type_counts[n] -= 1
#                 else:
#                     arg.setName(n) # only one of these here

#     def allEncodings(self):
#         return [self]

#     def getArgs(self):
#         return self.args

#     def printHeader(self, trail=';'):
#         arglist = []
#         for arg in self.args:
#             if not arg.isDisabled():
#                 arglist.append(arg.strType() + ' ' + arg.strName())
#         if self.is_static:
#             print('static void')
#         else:
#             print('void')
#         print(Insn.emit_prefix + self.function_name + '(' + ', '.join(["buffer_t *buf"] + arglist) + ')' + trail)

#     def machineCodeLen(self):
#         return '%d' % len(self.machine_code)

#     def prepareMachineCodeLen(self, p):
#         pass

#     def postprocessMachineCodeLen(self, p):
#         pass

#     def initialMachineCodeOffset(self):
#         return 0

#     def printDataUpdate(self, p, offset, machine_code_byte, spec):
#         p('data[%d] = 0x%02x%s;' % (offset, machine_code_byte, spec))

#     def getConstructionBitmaskBuilders(self, offset):
#         builders = []
#         build_this_byte = True
#         for arg in self.args:
#             if arg is not None:
#                 if arg.inExclusiveRegion(offset):
#                     return None

#                 builder = arg.getBuilderFor(offset)
#                 if builder is not None:
#                     builders.append('(' + builder + ')')
#         return builders

#     def printOffsetCalculatorBranch(self, tabs, argarg):
#         al = []
#         for arg in self.args:
#             exclusive_region = arg.getExclusiveRegion()
#             if (exclusive_region):
#                 al.append('%d' % exclusive_region[0])
#             else:
#                 al.append('-1')

#         print((tabs + 'return ({arg} < 0 || {arg} >= {max})?-1: ((int[]){{ {offsets} }})[{arg}];'
#                .format(arg=argarg, max=len(self.args),
#                        offsets=', '.join(al))))

#     def printGenerator(self):
#         self.printHeader(trail='')
#         print('{')
#         p = mkp(1)
#         self.prepareMachineCodeLen(p)
#         p('const int machine_code_len = %s;' % self.machineCodeLen())
#         p('unsigned char *data = buffer_alloc(buf, machine_code_len);')
#         self.postprocessMachineCodeLen(p)

#         # Basic machine code generation: copy from machine code string and or in any suitable arg bits
#         offset = self.initialMachineCodeOffset()
#         for byte in self.machine_code:
#             builders = self.getConstructionBitmaskBuilders(offset)
#             if builders is not None:
#                 if len(builders) > 0:
#                     builders = [''] + builders # add extra ' | ' to beginning
#                 self.printDataUpdate(p, offset, byte, ' | '.join(builders))

#             offset += 1

#         for arg in self.args:
#             if arg is not None:
#                 if arg.getExclusiveRegion() is not None:
#                     arg.printCopyToExclusiveRegion(p, 'data')

#         print('}')

#     def printTryDisassemble(self, data_name, max_len_name):
#         self.printTryDisassembleOne(data_name, max_len_name, self.machine_code, 0)

#     def setFormat(self, string):
#         self.format_string = string
#         return self

#     def printTryDisassembleOne(self, data_name, max_len_name, machine_code, offset_shift):
#         checks = []

#         offset = offset_shift
#         for byte in machine_code:
#             bitmask = 0xff
#             for arg in self.args:
#                 if arg is not None:
#                     bitmask = bitmask & arg.maskOut(offset)

#             if bitmask != 0:
#                 if bitmask == 0xff:
#                     checks.append('data[%d] == 0x%02x' % (offset - offset_shift, byte))
#                 else:
#                     checks.append('(data[%d] & 0x%02x) == 0x%02x' % (offset - offset_shift, bitmask, byte))
#             offset += 1

#         assert len(checks) > 0

#         p = mkp(1)
#         p(('if (%s >= %d && ' % (max_len_name, len(machine_code))) + ' && '.join(checks) + ') {')
#         pp = mkp(2)

#         pp('const int machine_code_len = %d;' % len(machine_code));
#         formats = []
#         format_args = []
#         for arg in self.args:
#             if arg is not None:
#                 (format_addition, format_args_addition) = arg.printDisassemble('data', -offset_shift, pp)
#                 formats = formats + format_addition
#                 format_args = format_args + format_args_addition
#         pp('if (file) {');
#         if len(formats) == 0:
#             pp('\tfprintf(file, "%s");' % self.name)
#         else:
#             format_string = ', '.join(formats)
#             if self.format_string is not None:
#                 format_string = self.format_string % tuple(formats)
#             pp(('\tfprintf(file, "%s\\t' % self.name) + format_string + '", ' + ', '.join(format_args) + ');');
#         pp('}')
#         pp('return machine_code_len;')
#         p('}')

#     def genLatexTable(self):
#         '''Returns list with the following elements (as LaTeX): [insn-name, args, short description]'''

#         args = []
#         m = { 'r' : 0 }
#         for a in self.args:
#             args.append(a.genLatex(m))

#         valstr = m['v'] if 'v' in m else '?'

#         descr = self.descr

#         if type(descr) is not str:
#             descr = self.descr.getDescription()

#         descr = (descr
#                  .replace('\\', '\\')
#                  .replace('%v', '\\texttt{' + valstr + '}')
#                  .replace('%a', '\\texttt{addr}'))

#         anonymous_regnames = 4

#         regnames = ['pc', 'sp', 'gp', 'fp']
#         for (pfx, count) in [('a', 6), ('v', 1), ('t', 2), ('s', 4)]:
#             for c in range(0, count + 1):
#                 regnames.append(pfx + str(c))

#         for r in regnames:
#             descr = descr.replace('$' + r, '\\texttt{\\$' + r + '}')

#         descr = (descr
#                  .replace('$$', '$')
#                  .replace('_', '\\_'))

#         descr = make_anonymous_regnames_subscript(descr)

#         name = '\\textcolor{dblue}{\\textbf{\\texttt{' + self.name.replace('_', '\\_') + '}}}'

#         return [name, ', '.join(args), descr]


# class NewInsn(Insn):
#     emit_prefix = LIB_PREFIX + "emit_"

#     def __init__(self, name, descr, implementation, test=None):
#         machine_code, args = implementation.generate()
#         Insn.__init__(self, name, descr, machine_code, args, test=test)

class InsnAlternatives(Insn):
    '''
    Multiple alternative instruction encodings wrapped into the same call
    '''
    def __init__(self, name, descr, default, options, test=None):
        '''
        name: Name of the joint instruction
        default: Default instruction encoding, a pair of (machine_code, args) as for Insn
        options: Alternative instrucion encodings, a tuple (cond, (machine_code, args)) where
                 "cond" is a C conditional that may refer to arguments (of the "default") by "{arg0}" .. "{argn}"

                 Alternative encodings may skip args (specify as "None").  Make sure to
                 maintain the order of the original argument list, though.
        '''
        Insn.__init__(self, name, descr, default[0], default[1], test=test)
        self.options = {opt : Insn(name, descr, machine_code, args) for (opt, (machine_code, args)) in options}

        name_nr = 0

        for o in self.options.values():
            o.is_static = True
            o.function_name = o.name + '__%d' % name_nr
            name_nr += 1

        self.default_option = Insn(name, descr, default[0], default[1])
        self.default_option.is_static = True
        self.default_option.function_name = self.default_option.name + '__%d' % name_nr

    def allEncodings(self):
        return list(self.options.values()) + [self]

    def setFormat(self, fmt):
        Insn.setFormat(self, fmt)
        for n in self.options.values():
            n.setFormat(fmt)
        self.default_option.setFormat(fmt);
        return self

    def printOffsetCalculatorBranch(self, tabs, argarg):
        print('{')
        argdict = {}
        count = 0
        for arg in self.args:
            n = arg.strGenericName()
            argdict['arg%d' % count] = 'args[%d].%s' % (count, n)
            count += 1
        for (condition, option) in self.options.items():
            print((tabs + 'if (%s)' % (condition.format(**argdict))))
            option.printOffsetCalculatorBranch('\t' + tabs, argarg)
        self.default_option.printOffsetCalculatorBranch(tabs, argarg)
        print('{t}}}'.format(t = tabs))

    def printGenerator(self):
        self.default_option.printGenerator()
        print('')
        for o in self.options.values():
            o.printGenerator()
            print('')

        # Print selection function
        arglist = []
        argdict = {}
        count = 0
        for arg in self.args:
            n = arg.strName()
            argdict['arg%d' % count] = n
            arglist.append(n)
            count += 1

        def invoke(insn):
            ma = ['buf']
            mc = 0
            for arg in insn.args:
                if not arg.isDisabled():
                    ma.append(arglist[mc])
                mc += 1
            return Insn.emit_prefix + insn.function_name + '(' + ', '.join(ma) + ');'

        self.printHeader(trail='')
        print('{')
        p = mkp(1)
        pp = mkp(2)
        for (condition, option) in self.options.items():
            p('if (%s) {' % (condition.format(**argdict)))
            pp(invoke(option));
            pp('return;')
            p('}')
        # otherwise default
        p(invoke(self.default_option))
        print('}')

    def getArgs(self):
        return self.default_option.getArgs()

    def printLatex(self, m):
        return self.default_option.printLatex(m)


class OptPrefixInsn (Insn):
    '''
    An instruction that permits an optional prefix byte.
    This byte is generated iff one bit in byte -1 must be set to nonzero.
    '''

    def __init__(self, name, descr, opt_prefix, machine_code, args, test=None):
        Insn.__init__(self, name, descr, [opt_prefix] + machine_code, args, test)
        self.opt_prefix = opt_prefix

    def machineCodeLen(self):
        return Insn.machineCodeLen(self) + ' - 1 + data_prefix_len';

    def prepareMachineCodeLen(self, p):
        p('int data_prefix_len = 0;')
        p('if (%s) { data_prefix_len = 1; }' % (' || '.join(self.getConstructionBitmaskBuilders(-1))))

    def postprocessMachineCodeLen(self, p):
        p('data += data_prefix_len;')

    def initialMachineCodeOffset(self):
        return -1

    def printDataUpdate(self, p, offset, mcb, spec):
        pp = p
        if (offset < 0):
            pp = mkp(2)
            p('if (data_prefix_len) {')
        Insn.printDataUpdate(self, pp, offset, mcb, spec)
        if (offset < 0):
            p('}')

    def printTryDisassemble(self, data_name, max_len_name):
        self.printTryDisassembleOne(data_name, max_len_name, self.machine_code, -1)
        self.printTryDisassembleOne(data_name, max_len_name, self.machine_code[1:], 0)


def Name(mips, intel=None):
    '''
    Adjust this if you prefer the Intel asm names
    '''
    return mips


def printDisassemblerDoc():
    print('/**')
    print(' * Disassembles a single assembly instruction and prints it to stdout')
    print(' *')
    print(' * @param data: pointer to the instruction to disassemble')
    print(' * @param max_len: max. number of viable bytes in the instruction')
    print(' * @return Number of bytes in the disassembled instruction, or 0 on error')
    print(' */')

def printDisassemblerHeader(trail=';'):
    print('int')
    print('disassemble_one(FILE *file, unsigned char *data, int max_len)' + trail)

def printDisassembler(instructions):
    printDisassemblerHeader(trail='')
    print('{')
    p = mkp(1)
    p('char* addr_prefix;')
    for preinsn in instructions:
        for insn in preinsn.allEncodings():
            insn.printTryDisassemble('data', 'max_len')
    p('return 0; // failure')
    print('}')


REGISTERS = [
    ('$v0', 0),
    ('$a3', 0),
    ('$a2', 0),
    ('$s0', 0),
    ('$sp', 'stack'),
    ('$fp', 'stack'),
    ('$a1', 0),
    ('$a0', 0),
    ('$a4', 0),
    ('$a5', 0),
    ('$t0', 'temp'),
    ('$t1', 'temp'),
    ('$s1', 0),
    ('$s2', 0),
    ('$s3', 0),
    ('$gp', 0)]

class TestCaseAbstract:
    def __init__(self):
        pass

    def execute(self, testsuite):
        return testsuite.execute(self.body(testsuite))

    def body(self, testsuite):
        return testsuite.body(self.testcode, self.testdata)


class TestCase(TestCaseAbstract):
    def __init__(self, testcode, testdata, expected):
        TestCaseAbstract.__init__(self)
        self.testcode = testcode
        self.testdata = testdata
        self.expected = expected


class TestSet(TestCaseAbstract):
    def __init__(self, cases):
        TestCaseAbstract.__init__(self)
        self.cases = cases

    @property
    def testcode(self):
        return [line for case in self.cases for line in case.testcode]

    @property
    def testdata(self):
        return [line for case in self.cases for line in case.testdata]

    @property
    def expected(self):
        return ''.join(case.expected for case in self.cases)


class Test:
    '''Test suite for one instruction'''
    ALL_REGISTERS = [r[0] for r in REGISTERS]
    TEMP_REGISTERS = [r[0] for r in REGISTERS if r[1] == 'temp']
    NON_TEMP_REGISTERS = [r[0] for r in REGISTERS if r[1] != 'temp']

    # caller-saved registers that have no deep semantics and can be used to back up other registers:
    BACKUP_REGISTERS = [ '$t0', '$t1',
                         '$a1', '$a2', '$a3' ]

    def __init__(self, testclosure):
        self.testclosure = testclosure
        self.no_shared_registers = False
        self.testcases = []
        self.label_counter = 0
        self.binary = None

    def run(self, binary, insn):
        '''False iff test fails'''
        return False

    def body(self, code, data):
        full = ['.text', 'main:'] + code + ['  jreturn', '.data'] + data
        return ''.join(s + '\n' for s in full)

    def without_shared_registers(self):
        '''Each register parameter must be unique'''
        self.no_shared_registers = True
        return self

    def fresh_label(self, name):
        n = self.label_counter
        self.label_counter += 1
        return 'L%d_%s' % (n, name)

    def expect_preservation(self, binary, operations, register, data, temp_reg):
        '''check operation to confirm that the register is preserved through the operations

        operations: either a list of strings of instructions to run, or a function that takes an int from 0,1,2
                and returns such a list.  We use 'operations' three times, so if the list includes jump labels,
                it should generate fresh jump labels that utilise that index.
        '''

        expected = [1, 2, 3]
        sum_body = []

        if type(operations) is list:
            ops = list(operations)
            operations = lambda _: ops

        for n in expected:
            is_temp = register in Test.TEMP_REGISTERS
            sum_body += ((['  move ' + temp_reg + ', ' + register + '  ; pres-backup'] if not is_temp else [])
                         + ['  li ' + register + ', %d' % n]
                         + operations(n)
                         + (['  move $a0, ' + register + '  ; pres-restore'] if not register == '$a0' else [])
                         + (['  move ' + register + ', ' + temp_reg] if not (register == '$a0' or is_temp) else [])
                         + ['  jal print_int'])
        return self.expect(binary, sum_body, data, expected)

    def execute(self, testbody):
        with tempfile.NamedTemporaryFile() as tfile:
            tfile.write(testbody.encode('utf-8'))
            tfile.flush()
            output = subprocess.run([self.binary, tfile.name], input='', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output

    def expect(self, binary, testbody, testdata, expected_lines):
        self.binary = binary

        expected = ''.join(str(to) + '\n' for to in expected_lines)
        testcase = TestCase(testbody, testdata, expected)
        self.testcases.append(testcase)

    def check_tests(self, tests):
        tset = TestSet(tests)
        return self.check_test(tset)

    def check_test(self, test):
        result = test.execute(self)
        failed = False
        result_stdout = result.stdout.decode('utf-8')
        if result.returncode != 0:
            return result
        elif result_stdout != test.expected:
            return result
        return True

    def explain_failure(self, index, test, result):
        result_stdout = result.stdout.decode('utf-8')
        if result.returncode != 0:
            print("  => unexpected exit code %d" % result.returncode)
        elif result_stdout != test.expected:
            print("  => unexpected output")
        print("  test # %d" % index)
        print('/--[code]------------------------------------------')
        print(test.body(self))
        print('|--[stdout]----------------------------------------')
        print(result_stdout)
        print('|--[expected]--------------------------------------')
        print(test.expected)
        print('|--[stderr]----------------------------------------')
        print(result.stderr.decode('utf-8'))
        print('\\--------------------------------------------------')

    def get_free_temps(self, args):
        return [r for r in self.BACKUP_REGISTERS if r not in args]

    def run_tests(self):
        print('  %d test cases' % len(self.testcases))
        if self.check_tests(self.testcases) != True:
            print('Test failure, identifying failing test case')
            self.run_tests_binsearch_find_failure()
            return False
        self.testcases = None  # deallocate
        return True

    def run_tests_binsearch_find_failure(self):
        def bsearch(index, all_cases):
            '''return True if bug found'''
            # print('%d/%d' % (index, len(all_cases)))
            if len(all_cases) == 0:
                return False
            if len(all_cases) == 1:
                t = all_cases[0]
                result = self.check_test(t)
                if result != True:
                    self.explain_failure(index, t, result)
                    return True
                return False
            # otherwise split
            midpoint = len(all_cases) // 2
            if self.check_tests(all_cases[:midpoint]) != True:
                # print('Failure in lower range after %d (%d candidates)' % (index, len(all_cases)))
                return bsearch(index, all_cases[:midpoint])
            else:
                # print('No failure in lower range after %d, must be in upper range after %d (%d candidates)' % (index, index + midpoint, len(all_cases)))
                # print('  quickconfirm: %s' % (self.check_tests(all_cases[midpoint:])))
                return bsearch(index + midpoint, all_cases[midpoint:])
            return True

        bsearch(0, self.testcases)

    def run_tests_linearly(self):
        for t in self.testcases:
            result = self.check_test(t)
            if result != True:
                self.explain_failure(t, result)
                return False
        return True


class ArithmeticTest(Test):
    TEST_VALUES=[0, 1, 2, 15, -7, -1]

    '''Tests an arithmetic operation with one result, no changes to unrelated registers'''
    def __init__(self, tc, results=1):
        Test.__init__(self, tc)
        self.limits = {}
        self.results_nr = results

    def filter_for_testarg(self, index, filter):
        '''
        Restrict the index-th parameter (starting at 0) to only values that pass the filter
        '''
        self.limits[index] = [v for v in self.test_values_for(index) if filter(v)]
        return self

    def test_values_for(self, index):
        if index in self.limits:
            return self.limits[index]
        return ArithmeticTest.TEST_VALUES

    def gen_tests_for_expected_behaviour(self, binary, insn):
        args = insn.args
        # First check that the operation produces intended results
        def try_test(init, args, bindings, resultindex):
            '''resultindex: args[resultindex] is an output register that we should check.
                 Usually 0, but not always (if self.results_nr > 1).'''
            used_regs = [a for a in args if a[0] == '$']
            regs_to_back_up = [r for r in used_regs if r not in Test.BACKUP_REGISTERS and not r == '$v0']
            unused_backups = [r for r in Test.BACKUP_REGISTERS if r not in used_regs]
            backups = []
            restores = []
            for rd in regs_to_back_up:
                backup_r = unused_backups.pop()
                backups.append('  move %s, %s' % (backup_r, rd))
                restores.append('  move %s, %s' % (rd, backup_r))

            body = (backups
                    + init
                    + ['  %s %s   ; test' % (insn.name, ', '.join(args))]
                    + ['  move $v0, %s' % args[resultindex]]
                    + restores
                    + ['  move $a0, $v0']
                    + ['  jal print_int'])

            def interpret_arg(arg):
                if arg[0] == '$':
                    return bindings[arg]
                else:
                    return int(arg)

            i_args = tuple(interpret_arg(a) for a in args)
            #print('i-args = %s' % [i_args])
            expected = [self.testclosure(*i_args)]
            # for insns that return multiple results
            if self.results_nr > 1:
                expected = [expected[0][resultindex]]

            return self.expect(binary, body, [], expected)

        def all_configs_behave(index, config_init, config_args, config_bindings):
            if index >= len(args):
                # first check that we are using the instruction in a "sensible" way
                if self.results_nr == 2 and config_args[0] == config_args[1]:
                    # Two outputs written to same register?  Result undefined
                    return

                for resultindex in range(0, self.results_nr):
                    try_test(config_init, config_args, config_bindings, resultindex)
                return

            kind = args[index].getKind()
            if kind == 'i':
                for v in self.test_values_for(index):
                    all_configs_behave(index + 1,
                                       config_init,
                                       config_args + [str(v)],
                                       config_bindings)
            elif kind == 'r':
                count = 0
                for reg in Test.ALL_REGISTERS:
                    count += 1
                    if reg in config_bindings: # register already initialised
                        if self.no_shared_registers:
                            continue
                        if config_bindings[reg] not in self.test_values_for(index):
                            continue # existing register binding not allowed at this index (this happens if we use the same reg. twice and a later position is more restrictive)
                        success = all_configs_behave(index + 1,
                                                     config_init,
                                                     config_args + [reg],
                                                     config_bindings)
                    else:
                        for v in self.test_values_for(index):
                            new_bindings = dict(config_bindings)
                            new_bindings[reg] = v
                            all_configs_behave(index + 1,
                                               config_init + ['  li %s, %s' % (reg, v)],
                                               config_args + [reg],
                                               new_bindings)
            else:
                raise Exception('Unexpected kind: %s' % kind)

        all_configs_behave(0,
                           [], # initialisation instructions
                           [], # args to insn call
                           {}) # mappings from register name to int binding

    def gen_tests_for_preservation(self, binary, insn):
        args = insn.args
        def try_test(args, tempreg):
            if type(tempreg) is tuple: # two results and two temp registers?
                body = ['  move %s, %s ; multiple results: back up #1' % (tempreg[0], args[0]),
                        '  move %s, %s ; multiple results: back up #2' % (tempreg[1], args[1]),
                        '  %s %s   ; test' % (insn.name, ', '.join(args)), # the insn we care about
                        '  move %s, %s' % (args[1], tempreg[1]),
                        '  move %s, %s' % (args[0], tempreg[0])
                        ]
                resultargs = [args[0], args[1]]
            else:
                body = ['  move %s, %s ; back up result register' % (tempreg, args[0]),
                        '  %s %s   ; test' % (insn.name, ', '.join(args)), # the insn we care about
                        '  move %s, %s' % (args[0], tempreg)]
                tempreg = [tempreg]
                resultargs = [args[0]]
            data = []

            for reg in Test.ALL_REGISTERS:
                if reg not in tempreg and reg not in resultargs:
                    self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg] + list(tempreg))[0])

        reg_args = []
        default_args = []
        RV0 = '$v0'
        index = 0
        for a in args:
            kind = args[index].getKind()
            if kind == 'r':
                reg_args.append(index)
                default_args.append(RV0)
            elif kind == 'i':
                default_args.append("0")
            else:
                raise Exception('Unexpected kind: %s' % kind)
            index += 1
        # check preservation for all registers at arglist positions stored in reg_args
        # (only vary one arg at a time)
        for shuffle_arg in reg_args:
            for subst_reg in Test.ALL_REGISTERS:
                args = list(default_args)
                args[shuffle_arg] = subst_reg

                # select suitable temp registers
                viable_temp_regs = self.get_free_temps(args)
                if len(viable_temp_regs) < self.results_nr + 1:
                    raise Exception('Not enough temporary registers')
                elif len(viable_temp_regs) > self.results_nr + 1:
                    viable_temp_regs = viable_temp_regs[:self.results_nr + 1]

                # construct pairs of temp regs for two-result operations
                if self.results_nr == 2:
                    viable_temp_regs = [(a, b) for a in viable_temp_regs for b in viable_temp_regs if a != b]

                for i in range(0, self.results_nr + 1): # [0,1] for 1 result, [0,1,2] for 2 results
                    try_test(args, viable_temp_regs[i])


    def run(self, binary, insn):
        self.gen_tests_for_expected_behaviour(binary, insn)
        self.gen_tests_for_preservation(binary, insn)
        return self.run_tests()


class BranchTest(Test):
    '''Tests an operation with a (conditional) branch'''
    def __init__(self, tc):
        Test.__init__(self, tc)
        self.generated = 0

    def gen_tests_for_expected_behaviour(self, binary, insn):
        args = insn.args[:-1]
        backup_registers = Test.BACKUP_REGISTERS

        def gen_cnf(test_regs, assignments, backups, out_reg):
            dest_label = self.fresh_label('dest')
            done_label = self.fresh_label('done')

            body = (  ['  move %s, %s ; backup' % (backups[r], r) for r in assignments]
                    + ['  li   %s, %s ; load' % (r, assignments[r]) for r in assignments]
                    + ['  %s  %s' % (insn.name, ', '.join(test_regs + [dest_label])),
                       '  li   %s, 0' % out_reg,
                       '  j    ' + done_label,
                       dest_label + ':',
                       '  li   %s, 1' % out_reg,
                       done_label + ':']
                    + ['  move %s, %s ; restore' % (r, backups[r]) for r in assignments]
                    + ['  move $a0, %s' % out_reg,
                       '  jal  print_int'])
            i_args = tuple([assignments[r] for r in test_regs])
            expected = [1 if self.testclosure(*i_args) else 0]
            self.generated += 1
            self.expect(binary,
                        body, [],
                        expected)

        def testcnf(test_regs, index, assignments):
            if index >= len(args):
                # find backup registers
                available_backups = [br for br in backup_registers if br not in assignments]
                backup_count = 0
                backups = {}
                for r in assignments:
                    backups[r] = available_backups[backup_count]
                    backup_count += 1
                gen_cnf(test_regs, assignments, backups, available_backups[backup_count])
                return
            for r in Test.ALL_REGISTERS:
                if r not in assignments:
                    upd_assignments = dict(assignments)

                    for i in [-1, 0, 1]:
                        upd_assignments[r] = i
                        testcnf([r] + test_regs, index + 1, upd_assignments)
                else:
                    testcnf([r] + test_regs, index + 1, assignments)

        testcnf([], # no initial test arguments
                0,  # start by generating argument for index 0, if needed
                {}) # variable assignments

        if self.generated == 0:
            raise Exception('No tests generated!') 

    def gen_tests_for_preservation(self, binary, insn):
        args = insn.args[:-1]
        def try_test(args, tempreg):
            def body(jump_label_index):
                dest_label = self.fresh_label('dest_%d' % jump_label_index)
                return ['  %s  %s   ; test' % (insn.name, ', '.join(args + [dest_label])), # the insn we care about
                        dest_label + ':']
            data = []

            for reg in Test.ALL_REGISTERS:
                self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg])[0])

        reg_args = []
        default_args = []
        RV0 = '$v0'
        index = 0
        for a in args:
            kind = args[index].getKind()
            if kind == 'r':
                reg_args.append(index)
                default_args.append(RV0)
            elif kind == 'i':
                default_args.append("0")
            else:
                raise Exception('Unexpected kind: %s' % kind)
            index += 1
        # check preservation for all registers at arglist positions stored in reg_args
        # (only vary one arg at a time)
        if reg_args == []:
            for i in [0, 1]:
                try_test([], self.get_free_temps([])[i])
        else:
            for shuffle_arg in reg_args:
                for subst_reg in Test.ALL_REGISTERS:
                    args = list(default_args)
                    args[shuffle_arg] = subst_reg
                    viable_temp_regs = self.get_free_temps(args)
                    for i in [0, 1]:
                        try_test(args, viable_temp_regs[i])

    def run(self, binary, insn):
        self.gen_tests_for_expected_behaviour(binary, insn)
        self.gen_tests_for_preservation(binary, insn)
        return self.run_tests()


MASK64 = 0xffffffffffffffff

def signed64(k):
    '''convert long to 64 bit signed integer equivalent'''
    k = k & MASK64
    if k > (MASK64 >> 1):
        #negative
        return -((MASK64 + 1) - k)
    return k

# shift ops
def shl(a, b):
    return signed64((a & MASK64) << (b & 0x3f))

def shr(a, b, arithmetic=False):
    if arithmetic and signed64(a) < 0:
        return signed64(((MASK64 << 32) | a) >> (b & 0x3f))  # only 6 bits of the shift offset are counted
    return signed64((a & MASK64) >> (b & 0x3f))

def sgn(x):
    return -1 if x < 0 else (0 if x == 0 else 1)

# int division that rounds towards zero
def intdiv(a, b):
    absval = abs(a) // abs(b)
    return absval * sgn(a) * sgn(b)

# int modulo
def intmod(a, b):
    absval = abs(a) % abs(b)
    return absval * sgn(a)

instructions = [
    Insn('move', '$r0 := $r1',
         amd64.MOV_rr(R(0), R(1)),
         test=ArithmeticTest(lambda a,b : b)),
    # NewInsn(Name(mips="li", intel="mov"), '$r0 := %v',
    #         amd64.MOV_ri(R(0), I(1)),
    #         test=ArithmeticTest(lambda a,b : b)),

    Insn('add', ArithmeticEffect('+'),
         amd64.ADD_rr(R(0), R(1)),
         test=ArithmeticTest(lambda a,b : a + b)),
    # NewInsn("addi", ArithmeticImmediateEffect('+'),
    #         amd64.ADD_ri(R(0), I(1)),
    #         test=ArithmeticTest(lambda a,b : a + b)),
    # Insn("sub", ArithmeticEffect('$-$'), [0x48, 0x29, 0xc0], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a,b : a - b)),
    # Insn(Name(mips="subi", intel="sub"), '$r0 := $r0 $$-$$ %v', [0x48, 0x81, 0xe8, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
    #      test=ArithmeticTest(lambda a,b : a - b)),
    # Insn(Name(mips="mul", intel="imul"), ArithmeticEffect('*'), [0x48, 0x0f, 0xaf, 0xc0], [ArithmeticSrcReg(3), ArithmeticDestReg(3)],
    #      test=ArithmeticTest(lambda a,b : a * b)),
    # Insn(Name(mips="div_a2v0", intel="idiv"), '$v0 := $a2:$v0 / $r0, $a2 := remainder', [0x48, 0xf7, 0xf8], [ArithmeticDestReg(2)]),
    # InsnAlternatives(Name(mips="divrem", intel="idiv"), '$r0, $r1 := ($r0 / $r2, $r0 mod $r2)  ($r0, $r1, $r2 must be distinct)',
    #      ([0x48, 0x90,		# 0  xchg   rax, r0
    #        0x48, 0x87, 0xc2,	# 2  xchg   rdx, r1
    #        0x48, 0x99,		# 5  cto            ;; (CQO) sign extend rax into rdx
    #        0x48, 0xf7, 0xf8,	# 7  idiv   r2
    #        0x48, 0x87, 0xc2,	# a  xchg   rdx, r1
    #        0x48, 0x90,		# d  xchg   rax, r0
    #        0x90, 0x90,
    #        0x90, 0x90
    #        ],
    #       [JointReg([ArithmeticDestReg(0x1),
    #                  ArithmeticDestReg(0xe, baseoffset=0xd)]),
    #        JointReg([ArithmeticSrcReg(0x4, baseoffset=0x2),
    #                  ArithmeticSrcReg(0xc, baseoffset=0xa)]),
    #        ArithmeticDestReg(0x9, baseoffset=0x7)]),
    #      [
    #          # ('({arg1} == 0) && ({arg2} == 2)',
    #          #  ),

    #          # ('{arg2} == 2 && {arg1} != 0',   # dividing by rdx? Have to flip things around a bit
    #          #  ([0x48, 0x87, 0xc2,	# 0  xchg   rdx(=r2), r1
    #          #    0x48, 0x90,		# 3  xchg   rax, r0
    #          #    0x48, 0x99,		# 5  cto            ;; (CQO) sign extend rax into rdx
    #          #    0x48, 0xf7, 0xf8,	# 7  idiv   r1
    #          #    # FIXME: flip!
    #          #    0x48, 0x87, 0xc2,	# a  xchg   rdx(=r2), r1
    #          #    0x48, 0x90,		# d  xchg   rax, r0
    #          #    0x90, 0x90,
    #          #    ],
    #          #   [JointReg([ArithmeticDestReg(0x4, baseoffset=0x3),
    #          #              ArithmeticDestReg(0xe, baseoffset=0xd)]),
    #          #    JointReg([ArithmeticSrcReg(0x2, baseoffset=0x0),
    #          #              ArithmeticSrcReg(0xc, baseoffset=0xa),
    #          #              ArithmeticDestReg(0x9, baseoffset=0x7)]),
    #          #    DisabledArg(ArithmeticDestReg(0x9, baseoffset=0x7), '2'),
    #          #    ])
    #          #  ),

    #          # ('{arg1} == 0 && {arg2} != 2',   # remainder in rax? Have to accommodate
    #          #  ([0x48, 0x87, 0xc2,	# 2  mov    rax, r0
    #          #    0x48, 0x90,		# 3  xchg   rdx, r0
    #          #    0x48, 0x99,		# 5  cto            ;; (CQO) sign extend rax into rdx
    #          #    0x48, 0xf7, 0xf8,	# 7  idiv   r2
    #          #    0x48, 0x87, 0xc2,	# a  xchg   rax, r0
    #          #    0x48, 0x87, 0xc2,	# c  xchg   r1, rdx
    #          #    0x90,
    #          #    0x90,
    #          #    0x90,
    #          #    ],
    #          #   [JointReg([ArithmeticDestReg(0x4, baseoffset=0x3),
    #          #              ArithmeticDestReg(0xb, baseoffset=0xa)]),
    #          #    DisabledArg(JointReg([ArithmeticSrcReg(0x4, baseoffset=0x2),
    #          #                          ArithmeticSrcReg(0xc, baseoffset=0xa)]),
    #          #                '0'),
    #          #    JointReg([ArithmeticSrcReg(0x2, baseoffset=0x0),
    #          #              ArithmeticSrcReg(0xe, baseoffset=0xc),
    #          #              ArithmeticDestReg(0x9, baseoffset=0x7)]),
    #          #    ])
    #          #  ),

    #          # ('{arg1} == 0 && {arg2} == 2',   # divide by rdx AND remainder in rax? Really trying to make this hard!
    #          #  ([0x48, 0x87, 0xc2,	# 0  xchg   r1, rdx(=r2)
    #          #    0x48, 0x90,		# 3  xchg   r0, rax
    #          #    0x48, 0x99,		# 5  cto            ;; (CQO) sign extend rax into rdx
    #          #    0x48, 0xf7, 0xf8,	# 7  idiv   r1
    #          #    # FIXME: flip!
    #          #    0x48, 0x87, 0xc2,	# a  xchg   r1, rdx(=r2)
    #          #    0x48, 0x90,		# d  xchg   r0, rax
    #          #    0x90,
    #          #    ],
    #          #   [JointReg([ArithmeticDestReg(0x4, baseoffset=0x3),
    #          #              ArithmeticDestReg(0xe, baseoffset=0xd)]),
    #          #    JointReg([ArithmeticSrcReg(0x2, baseoffset=0x0),
    #          #              ArithmeticSrcReg(0xc, baseoffset=0xa),
    #          #              ArithmeticDestReg(0x9, baseoffset=0x7)]),
    #          #    DisabledArg(ArithmeticDestReg(0x9, baseoffset=0x7), '2'),
    #          #    ])
    #          #  ),

    #          # ('{arg2} == 43 && {arg1} == 2',   # dividing by rdx AND want remainder there?  Allows (requires!) simplification
    #          #  ([0x48, 0x90,		# 0  xchg   r0, rax
    #          #    0x48, 0x99,		# 2  cto            ;; (CQO) sign extend rax into rdx
    #          #    0x48, 0xf7, 0xfa,	# 4  idiv   rdx
    #          #    0x48, 0x90,		# 7  xchg   r0, rax
    #          #    #############################
    #          #    ##### FIXME: unfixable? #####
    #          #    #############################
    #          #    # divrem $t0, $a2, $a2  seems like a sensible option, but we can't do it: cto would override the quotient, and non-cto will
    #          #    # produce incorrect results for negative $t0.
    #          #    0x90, 0x90,
    #          #    0x90, 0x90,
    #          #    0x90, 0x90,
    #          #    ],
    #          #   [JointReg([ArithmeticDestReg(0x1),
    #          #              ArithmeticDestReg(0x8, baseoffset=0x7)]),
    #          #    DisabledArg(ArithmeticDestReg(0x6, baseoffset=0x4), '2'),
    #          #    DisabledArg(ArithmeticDestReg(0x6, baseoffset=0x4), '2'),
    #          #    ])
    #          #  ),

    #          # ('({arg1} != 0) && ({arg2} == 2)',
    #          #  ),
    #      ],
    #                  test=ArithmeticTest(lambda a,b,c : (intdiv(a, c), intmod(a, c)), results=2).filter_for_testarg(2, lambda v : v != 0).without_shared_registers()),

    # Insn(Name(mips="not", intel="test_mov0_sete"), 'if $r1 = 0 then $r1 := 1 else $r1 := 0',  [0x48, 0x85, 0xc0, 0x40, 0xb8, 0,0,0,0, 0x40, 0x0f, 0x94, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), JointReg([ArithmeticSrcReg(2), ArithmeticDestReg(2)])],
    #      test=ArithmeticTest(lambda a,b : 1 if b == 0 else 0)),

    # Insn(Name(mips="and", intel="and"), '$r0 := $r0 bitwise-and $r1', [0x48, 0x21, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a, b : a & b)),
    # Insn(Name(mips="andi", intel="and"), '$r0 := $r0 bitwise-and %v', [0x48, 0x81, 0xe0, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
    #      test=ArithmeticTest(lambda a, b : a & b)),
    # Insn(Name(mips="or", intel="or"), '$r0 := $r0 bitwise-or $r1', [0x48, 0x09, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a, b : a | b)),
    # Insn(Name(mips="ori", intel="or"), '$r0 := $r0 bitwise-or %v', [0x48, 0x81, 0xc8, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
    #      test=ArithmeticTest(lambda a, b : a | b)),
    # Insn(Name(mips="xor", intel="xor"), '$r0 := $r0 bitwise-exclusive-or $r1', [0x48, 0x31, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a, b : a ^ b)),
    # Insn(Name(mips="xori", intel="xor"), '$r0 := $r0 bitwise-exclusive-or %v', [0x48, 0x81, 0xf0, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
    #      test=ArithmeticTest(lambda a, b : a ^ b)),

    # InsnAlternatives(Name(mips="sll", intel="shl"), '$r0 := $r0 $${<}{<}$$ $r1[0:7]',
    #                  ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe0, 0x48, 0x87, 0xc1], [
    #                      # xchg rcx, r0    ; rcx=$a0
    #                      # shl  r1, cl
    #                      # xchg rcx, r0    ; rcx=$a0
    #                      ArithmeticDestReg(5, baseoffset=3),
    #                      JointReg([ArithmeticSrcReg(2),
    #                                ArithmeticSrcReg(8, baseoffset=6)])]),
    #                  [ # sll $r, $a0 (RCX):
    #                      ('{arg1} == 1',
    #                       ([0x48, 0xd3, 0xe0], [
    #                           # shl  r1, cl
    #                           ArithmeticDestReg(2),
    #                           DisabledArg(ArithmeticDestReg(2), '1')
    #                       ])),
    #                    # sll $r, $r:
    #                      ('{arg0} == {arg1}',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe1, 0x48, 0x87, 0xc1], [
    #                           JointReg([ArithmeticSrcReg(2),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                    # sll $a0 (RCX), $r:
    #                      ('{arg0} == 1',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe0, 0x48, 0x87, 0xc1], [
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           # shl  r1, cl
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
    #                           DisabledArg(ArithmeticDestReg(8), '1'),
    #                           JointReg([ArithmeticSrcReg(2, baseoffset=0),
    #                                     ArithmeticDestReg(5, baseoffset=3),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                  ],
    #                  test=ArithmeticTest(lambda a, b : shl(a, (0x3f & b))),
    #              ),
    # Insn(Name(mips="slli", intel="shl"), '$r0 := $r0 bit-shifted left by %v', [0x48, 0xc1, 0xe0, 0], [ArithmeticDestReg(2), ImmByte(3)],
    #      test=ArithmeticTest(lambda a, b : shl(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0)),

    # InsnAlternatives(Name(mips="srl", intel="shr"), '$r0 := $r0 $${>}{>}$$ $r1[0:7]',
    #                  ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe8, 0x48, 0x87, 0xc1], [
    #                      ArithmeticDestReg(5, baseoffset=3),
    #                      JointReg([ArithmeticSrcReg(2),
    #                                ArithmeticSrcReg(8, baseoffset=6)])]),
    #                  [ # srl $r, $a0 (RCX):
    #                      ('{arg1} == 1',
    #                      ([0x48, 0xd3, 0xe8], [
    #                          ArithmeticDestReg(2),
    #                          DisabledArg(ArithmeticDestReg(2), '1')
    #                      ])),
    #                    # srl $r, $r:
    #                      ('{arg0} == {arg1}',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe9, 0x48, 0x87, 0xc1], [
    #                           JointReg([ArithmeticSrcReg(2),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                    # srl $a0 (RCX), $r:
    #                      ('{arg0} == 1',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe8, 0x48, 0x87, 0xc1], [
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           # srl  r1, cl
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
    #                           DisabledArg(ArithmeticDestReg(8), '1'),
    #                           JointReg([ArithmeticSrcReg(2, baseoffset=0),
    #                                     ArithmeticDestReg(5, baseoffset=3),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                  ],
    #                  test=ArithmeticTest(lambda a, b : shr((0xffffffffffffffff & a), (0x3f & b))),
    #              ),
    # Insn(Name(mips="srli", intel="shr"), '$r0 := $r0 bit-shifted right by %v', [0x48, 0xc1, 0xe8, 0], [ArithmeticDestReg(2), ImmByte(3)],
    #      test=ArithmeticTest(lambda a, b : shr(a, b)).filter_for_testarg(1, lambda x : x >= 0)),

    # InsnAlternatives(Name(mips="sra", intel="sar"), '$r0 := $r0 $${>}{>}$$ $r1[0:7], sign-extended',
    #                  ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf8, 0x48, 0x87, 0xc1], [
    #                      ArithmeticDestReg(5, baseoffset=3),
    #                      JointReg([ArithmeticSrcReg(2),
    #                                ArithmeticSrcReg(8, baseoffset=6)])]),
    #                  [('{arg1} == 1',
    #                      ([0x48, 0xd3, 0xf8], [
    #                          ArithmeticDestReg(2),
    #                          DisabledArg(ArithmeticDestReg(2), '1')
    #                      ])),
    #                    # sra $r, $r:
    #                      ('{arg0} == {arg1}',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf9, 0x48, 0x87, 0xc1], [
    #                           JointReg([ArithmeticSrcReg(2),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                    # sra $a0 (RCX), $r:
    #                      ('{arg0} == 1',
    #                       ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf8, 0x48, 0x87, 0xc1], [
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           # sra  r1, cl
    #                           # xchg rcx, r1    ; rcx=$a0
    #                           #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
    #                           DisabledArg(ArithmeticDestReg(8), '1'),
    #                           JointReg([ArithmeticSrcReg(2, baseoffset=0),
    #                                     ArithmeticDestReg(5, baseoffset=3),
    #                                     ArithmeticSrcReg(8, baseoffset=6)])])
    #                       ),
    #                  ],
    #                  test=ArithmeticTest(lambda a, b : shr(a, 0x3f & b, arithmetic=True)),
    #              ),
    # Insn(Name(mips="srai", intel="sar"), '$r0 := $r0 bit-shifted right by %v, sign extension', [0x48, 0xc1, 0xf8, 0], [ArithmeticDestReg(2), ImmByte(3)],
    #      test=ArithmeticTest(lambda a, b : shr(a, 0x3f & b, arithmetic=True)).filter_for_testarg(1, lambda x : x >= 0)),


    # Insn(Name(mips="slt", intel="cmp_mov0_setl"), 'if $r1 $$<$$ $r2 then $r1 := 1 else $r1 := 0',  [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x9c, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a, b, c : 1 if b < c else 0)),
    # Insn(Name(mips="sle", intel="cmp_mov0_setle"), 'if $r1 $$\le$$ $r2 then $r1 := 1 else $r1 := 0', [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x9e, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticDestReg(2), ArithmeticSrcReg(2)],
    #      test=ArithmeticTest(lambda a, b, c : 1 if b <= c else 0)),
    # Insn(Name(mips="seq", intel="cmp_mov0_sete"), 'if $r1 = $r2 then $r1 := 1 else $r1 := 0',  [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x94, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticSrcReg(2), ArithmeticDestReg(2)],
    #      test=ArithmeticTest(lambda a, b, c : 1 if b == c else 0)),
    # Insn(Name(mips="sne", intel="cmp_mov0_setne"), 'if $r1 $$\\ne$$ $r2 then $r1 := 1 else $r1 := 0', [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x95, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticSrcReg(2), ArithmeticDestReg(2)],
    #      test=ArithmeticTest(lambda a, b, c : 1 if b != c else 0)),

    # Insn(Name(mips="bgt", intel="cmp_jg"), 'if $r0 $$>$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8f, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a > b)),
    # Insn(Name(mips="bge", intel="cmp_jge"), 'if $r0 $$\\ge$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8d, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a >= b)),
    # Insn(Name(mips="blt", intel="cmp_jl"), 'if $r0 $$<$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8c, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a < b)),
    # Insn(Name(mips="ble", intel="cmp_jle"), 'if $r0 $$\\le$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8e, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a <= b)),
    # Insn(Name(mips="beq", intel="cmp_je"), 'if $r0 = $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x84, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a == b)),
    # Insn(Name(mips="bne", intel="cmp_jne"), 'if $r0 $$\\ne$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x85, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
    #      test=BranchTest(lambda a, b : a != b)),
    # Insn(Name(mips="bgtz", intel="cmp0_jg"), 'if $r0 $$>$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8f, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a > 0)),
    # Insn(Name(mips="bgez", intel="cmp0_jge"), 'if $r0 $$\ge$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8d, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a >= 0)),
    # Insn(Name(mips="bltz", intel="cmp0_jl"), 'if $r0 $$<$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8c, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a < 0)),
    # Insn(Name(mips="blez", intel="cmp0_jle"), 'if $r0 $$\\le$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8e, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a <= 0)),
    # Insn(Name(mips="bnez", intel="cmp0_jnz"), 'if $r0 $$\\ne$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x85, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a != 0)),
    # Insn(Name(mips="beqz", intel="cmp0_jz"), 'if $r0 = 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x84, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
    #      test=BranchTest(lambda a : a == 0)),

    # Insn(Name(mips="j", intel="jmp"), 'jump to %a', [0xe9, 0, 0, 0, 0], [PCRelative(1, 4, -5)],
    #      test=BranchTest(lambda : True)),
    # Insn(Name(mips="jr", intel="jmp"), 'jump to $r0', [0x40, 0xff, 0xe0], [ArithmeticDestReg(2)]),
    # Insn(Name(mips="jal", intel="callq"), 'push next instruction address, jump to %a', [0xe8, 0x00, 0x00, 0x00, 0x00], [PCRelative(1, 4, -5)]),
    # OptPrefixInsn(Name(mips="jalr", intel="callq"), "push next instruction address, jump to $r0" ,0x40, [0xff, 0xd0], [OptionalArithmeticDestReg(1)]),
    # Insn(Name(mips="jreturn", intel="ret"), 'jump to mem64[$sp]; $sp := $sp + 8', [0xc3], []),

    # InsnAlternatives(Name(mips="sb", intel="mov_byte_r"), 'mem8[$r1 + %v] := $r0[7:0]',
    #                  ([0x40, 0x88, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
    #                      ('{arg2} == 4', ([0x40, 0x88, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
    #                  ]).setFormat('%s, %s(%s)'),
    # InsnAlternatives(Name(mips="lb", intel="mov_byte_r"), '$r0 := mem8[$r1 + %v]', 
    #                  ([0x40, 0x0f, 0xb6, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(3), ImmInt(5), ArithmeticDestReg(3)]), [
    #                      ('{arg2} == 4', ([0x40, 0x0f, 0xb6, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(3), ImmInt(5), DisabledArg(ArithmeticDestReg(3), '4')]))
    #                  ]).setFormat('%s, %s(%s)'),

    # InsnAlternatives(Name(mips="sd", intel="mov_qword_r"), 'mem64[$r1 + %v] := $r0',
    #                  ([0x48, 0x89, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
    #                      ('{arg2} == 4', ([0x48, 0x89, 0x84, 0x24, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
    #                  ]).setFormat('%s, %s(%s)'),
    # InsnAlternatives(Name(mips="ld", intel="mov_r_qword"), '$r0 := mem64[$r1 + %v]',
    #                  ([0x48, 0x8b, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
    #                      ('{arg2} == 4', ([0x48, 0x8b, 0x84, 0x24, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
    #                  ]).setFormat('%s, %s(%s)'),

    # Insn(Name(mips="syscall", intel="syscall"), 'system call', [0x0f, 0x05], []),
    # Insn(Name(mips="push", intel="push"), '$sp := $sp - 8; mem64[$sp] = $r0', [0x48, 0x50], [ArithmeticDestReg(1)]),
    # Insn(Name(mips="pop", intel="pop"), '$r0 = mem64[$sp]; $sp := $sp + 8', [0x48, 0x58], [ArithmeticDestReg(1)]),
]


def printUsage():
    print('usage: ')
    for n in ['headers', 'code', 'latex', 'assembler', 'assembler-header', 'test <path-to-2opm-binary> [optional-list-of-comma-separated-insns]']:
        print('\t' + sys.argv[0] + ' ' + n)

def printWarning():
    print('// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!')

def printHeaderHeader():
    print('#include "assembler-buffer.h"')
    print('#include <stdio.h>')

def printCodeHeader():
    print('#include <string.h>')
    print('#include <stdio.h>')
    print('')
    print('#include "assembler-buffer.h"')
    print('#include "debugger.h"')
    print('#include "registers.h"')

def printOffsetCalculatorHeader(trail=';'):
    print('int')
    print('asm_arg_offset(char *insn, asm_arg *args, int arg_nr)' + trail)


def printAssemblerHeader():
    print("""// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#ifndef A2OPM_INSTRUCTIONS_H
#define A2OPM_INSTRUCTIONS_H

#include "assembler-buffer.h"

typedef union {
	label_t *label;
	int r;			// register nr
	unsigned long long imm;	// immediate
} asm_arg;

#define ASM_ARG_ERROR	0
#define ASM_ARG_REG	1
#define ASM_ARG_LABEL	2
#define ASM_ARG_IMM8U	3
#define ASM_ARG_IMM32U	4
#define ASM_ARG_IMM32S	5
#define ASM_ARG_IMM64U	6
#define ASM_ARG_IMM64S	7
// We may get further combinations later.

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

""")
    printOffsetCalculatorHeader()
    print("#endif // !defined(A2OPM_INSTRUCTIONS_H)")

def printAssemblerModule():
    print("""
// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#include <stdio.h>
#include <strings.h>

#include "assembler-buffer.h"
#include "assembler.h"
#include "assembler-instructions.h"

#define INSTRUCTIONS_NR {instructions_nr}
#define ARGS_MAX 5

static struct {{
	char *name;
	int args_nr;
	int args[ARGS_MAX];
}} instructions[INSTRUCTIONS_NR] = {{""".format(instructions_nr = len(instructions)))
    for insn in instructions:
        args = insn.getArgs()
        print ('\t{{ .name = "{name}", .args_nr = {args_nr}, .args = {{ {args} }} }},'
               .format(name = insn.name,
                       args_nr = len(insn.args),
                       args = ', '.join(a.getType() for a in args)))
    print('};')

    print("""
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
{
	// This isn't terribly efficient, but that's probably okay.""")
    for insn in instructions:
        args = insn.getArgs()
        arglist = list(args)
        for i in range(0, len(args)):
            arglist[i] = 'args[{i}].{select}'.format(i = str(i), select = args[i].strGenericName())

        print ('\tif (0 == (strcasecmp(insn, "{name}"))) {{\n\t\t{lib_prefix}emit_{name}({args});\n\t\treturn;\n\t}}'
               .format(name = insn.name,
                       lib_prefix = LIB_PREFIX,
                       args = ', '.join(['buf'] + arglist)))

    print('\tfprintf(stderr, "Unexpected instruction: %s\\n", insn);')
    print('\treturn;')
    print('}')
    print('')
    printOffsetCalculatorHeader('')
    print('{')
    for insn in instructions:
        print ('\tif (0 == strcasecmp("{name}", insn)) '
               .format(name = insn.name)),
        insn.printOffsetCalculatorBranch('\t\t', 'arg_nr')
    print('\treturn -1;')
    print('}')

def printDocs():
    print('\\begin{tabular}{llp{8cm}}')
    print('\\small')
    for i in instructions:
        [a,b,c] = i.genLatexTable()
        print(a + '&\t' + b + '&\t' + c + '\\\\')
    print('\\end{tabular}')

def printSty():
    insn_names = [i.name for i in instructions]
    print('''
\\lstdefinelanguage[2opm]{{Assembler}}%
{{morekeywords=[1]{{{KW}}},%
morekeywords=[2]{{.asciiz,.data,.text,.byte,.word}},%
comment=[l]\\#%
}}[keywords,strings,comments]
'''.format(KW=','.join(insn_names)))

def runTests(binary, names):
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
    if sys.argv[1] == 'headers':
        printWarning()
        printHeaderHeader()
        for insn in instructions:
            insn.printHeader()
        printDisassemblerDoc()
        printDisassemblerHeader()

    elif sys.argv[1] == 'code':
        printWarning()
        printCodeHeader()
        for insn in instructions:
            insn.printGenerator()
            print("\n")
        printDisassembler(instructions)

    elif sys.argv[1] == 'latex':
        printDocs()

    elif sys.argv[1] == 'latex-sty':
        printSty()

    elif sys.argv[1] == 'assembler':
        printAssemblerModule()

    elif sys.argv[1] == 'assembler-header':
        printAssemblerHeader()

    elif sys.argv[1] == 'test':
        runTests(sys.argv[2], sys.argv[3:])

    else:
        printUsage()

else:
    printUsage()
