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

import subprocess
import tempfile

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

    def try_test_for_preservation(self, binary, insn, try_test, args=None, results_nr=0):
        '''
        Try out a preservation test with all "reasonable" combinations of arguments:
        try_test(args: list[string], viable_temp_regs: list[string])

        @param results_nr: The number of arguments to the insn that are result arguments:
        0 for branches, 1 for most arithmetic, 2 for special ops that compute two results.
        '''
        if args is None:
            args = insn.args
        reg_args = []
        default_args = []
        RV0 = '$v0'
        index = 0
        for a in args:
            kind = a.kind
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
                if len(viable_temp_regs) < results_nr + 1:
                    raise Exception('Not enough temporary registers')
                elif len(viable_temp_regs) > results_nr + 1:
                    viable_temp_regs = viable_temp_regs[:results_nr + 1]

                # construct pairs of temp regs for two-result operations
                if results_nr == 2:
                    viable_temp_regs = [(a, b) for a in viable_temp_regs for b in viable_temp_regs if a != b]

                for i in range(0, results_nr + 1): # [0,1] for 1 result, [0,1,2] for 2 results
                    try_test(args, viable_temp_regs[i])


    def run_tests_linearly(self):
        for t in self.testcases:
            result = self.check_test(t)
            if result != True:
                self.explain_failure(t, result)
                return False
        return True


class ArithmeticTest(Test):
    '''
    Tests an arithmetic operation with one result, no changes to unrelated registers
    '''

    TEST_VALUES=[0, 1, 2, 15, -7, -1]

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

            kind = args[index].kind
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

        self.try_test_for_preservation(binary, insn, try_test, results_nr = self.results_nr)

    def run(self, binary, insn):
        self.gen_tests_for_expected_behaviour(binary, insn)
        self.gen_tests_for_preservation(binary, insn)
        return self.run_tests()


class BranchTest(Test):
    '''
    Tests an operation with a (conditional) branch
    '''

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
        def try_test(args, tempreg):
            def body(jump_label_index):
                dest_label = self.fresh_label('dest_%d' % jump_label_index)
                return ['  %s  %s   ; test' % (insn.name, ', '.join(args + [dest_label])), # the insn we care about
                        dest_label + ':']
            data = []

            for reg in Test.ALL_REGISTERS:
                self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg])[0])

        args = insn.args[:-1]
        self.try_test_for_preservation(binary, insn, try_test, args=args, results_nr=0)

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
