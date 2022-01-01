#! /usr/bin/env python3
# This file is Copyright (C) 2014, 2020--2022 Christoph Reichenbach
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
from registers import REGISTERS
import tempfile

RUN_TESTS_LINEARLY=False

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
    ALL_REGISTERS = [r.name for r in REGISTERS]
    TEMP_REGISTERS = [r.name for r in REGISTERS if r.is_temp]
    NON_TEMP_REGISTERS = [r.name for r in REGISTERS if not r.is_temp]

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
        if RUN_TESTS_LINEARLY:
            self.run_tests_linearly(debug=True)
        else:
            if self.check_tests(self.testcases) != True:
                print('Test failure, identifying failing test case')
                if not self.run_tests_binsearch_find_failure():
                    print('Could not find failure during binary search, this should not be happening')
                    print('Falling back to linear search')
                    self.run_tests_linearly()
                return False
        self.testcases = None  # deallocate
        return True

    def run_tests_binsearch_find_failure(self):
        def bsearch(index, all_cases):
            '''return True if bug found'''
            #print('[%d--%d]' % (index, index - 1 + len(all_cases)))
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
            if self.check_tests(all_cases[:midpoint]) == True:
                #print('No failure in lower range after %d, must be in upper range after %d (%d candidates)' % (index, index + midpoint, len(all_cases)))
                return bsearch(index + midpoint, all_cases[midpoint:])
            else:
                #print('Failure in lower range after %d (%d candidates)' % (index, len(all_cases)))
                #print('  quickconfirm: %s' % (self.check_tests(all_cases[midpoint:])))
                return bsearch(index, all_cases[:midpoint])

        return bsearch(0, self.testcases)

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
        for shuffle_arg in (reg_args if reg_args else [None]): # if we have no args, still run at least once
            for subst_reg in Test.ALL_REGISTERS:
                args = list(default_args)
                if len(args):
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

    def run_tests_linearly(self, debug=False):
        count = 0
        for t in self.testcases:
            # if debug:
            #     print(t)
            result = self.check_test(t)
            if result != True:
                self.explain_failure(count, t, result)
                return True
            count += 1
        return False

    def gen_tests_for_expected_behaviour(self, binary, insn):
        raise Exception('Implement Me')

    def gen_tests_for_preservation(self, binary, insn):
        raise Exception('Implement Me')

    def run(self, binary, insn):
        self.gen_tests_for_expected_behaviour(binary, insn)
        self.gen_tests_for_preservation(binary, insn)
        return self.run_tests()


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


class BranchTest(Test):
    '''
    Tests an operation with a (possibly conditional) branch
    '''

    def __init__(self, tc):
        Test.__init__(self, tc)
        self.generated = 0

    @property
    def needs_sp(self):
        return False

    @property
    def can_take_sp_arg(self):
        '''
        Should we test 'insn $sp'?
        '''
        return True

    def insn_args(self, insn):
        '''
        All the arguments we should test
        '''
        return insn.args[:-1]  # by default, omit the label argument

    def postprocess_jump(self, insn, arg_regs, out_reg, dest_label, post_branch_label, test_preservation):
        '''
        What should we do after the jump label if the jump/branch took place?

        Must load out_reg with the expected result, to be print later (unless test_preservation=True).  Must load non-0 in that case.

        @parma out_reg: register to load with the expected result, or a temp register for preservation tests
        @param test_preservation: are we running preservation tests (True) or expected behaviour tests (False)?
        @return: (list[code:str], expectation:int)
        '''
        return ([f'  li   {out_reg}, 1'],
                1)

    def gen_branch(self, insn, arg_regs, dest_label, post_branch_label, temp_reg, test_preservation=False):
        return ['  %s  %s' % (insn.name, ', '.join(arg_regs + [dest_label]))]

    def gen_tests_for_expected_behaviour(self, binary, insn):
        args = self.insn_args(insn)
        backup_registers = Test.BACKUP_REGISTERS

        def gen_cnf(arg_regs, assignments, backups, out_reg):
            dest_label = self.fresh_label('dest')
            done_label = self.fresh_label('done')
            post_branch_label = self.fresh_label('postbranch')

            if arg_regs == ['$sp'] and not self.can_take_sp_arg:
                # skip
                return

            (postprocess_jump, post_jump_expectation) = self.postprocess_jump(insn, arg_regs, out_reg, dest_label, post_branch_label, False)

            body = (  ['  move %s, %s ; backup' % (backups[r], r) for r in assignments]
                    + ['  li   %s, %s ; load' % (r, assignments[r]) for r in assignments]
                    + self.gen_branch(insn, arg_regs, dest_label, post_branch_label, '$t0')
                    + ['  li   %s, 0' % out_reg,
                       '  j    ' + done_label,
                       dest_label + ':']
                    + postprocess_jump
                    + [ done_label + ':']
                    + ['  move %s, %s ; restore' % (r, backups[r]) for r in assignments]
                    + ['  move $a0, %s' % out_reg,
                       '  jal  print_int'])
            i_args = tuple([assignments[r] for r in arg_regs])
            expected = [post_jump_expectation if self.testclosure(*i_args) else 0]
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
                post_branch_label = self.fresh_label('postbranch_%d' % jump_label_index)

                (postprocess_jump, post_jump_expectation) = self.postprocess_jump(insn, args, tempreg, dest_label, post_branch_label, True)

                return (self.gen_branch(insn, args, dest_label, post_branch_label, tempreg, test_preservation=True)
                        + [dest_label + ':']
                        + postprocess_jump)
                        #['  %s  %s   ; test' % (insn.name, ', '.join(args + [dest_label])), # the insn we care about
            data = []

            registers = Test.ALL_REGISTERS
            # for stack-based jumps, we can't check the preservation of $sp; we check that as part of the main checks
            if self.needs_sp:
                registers = [r for r in registers if r != '$sp']

            for reg in registers:
                if reg != tempreg:
                    self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg, tempreg])[0])

        args = self.insn_args(insn)
        self.try_test_for_preservation(binary, insn, try_test, args=args, results_nr=0)


class StackReturnTest(BranchTest):
    def __init__(self):
        BranchTest.__init__(self, lambda : True)

    @property
    def needs_sp(self):
        return True

    def gen_branch(self, insn, arg_regs, dest_label, post_branch_label, tempreg, test_preservation=False):
        return [f'  la   {tempreg}, {dest_label}',
                f'  push {tempreg}',
                f'  {insn.name}']


class JumpRegisterTest(BranchTest):
    def __init__(self):
        BranchTest.__init__(self, lambda _ : True)

    def insn_args(self, insn):
        return insn.args

    def postprocess_jump(self, insn, arg_regs, out_reg, dest_label, post_branch_label, test_preservation):
        if not test_preservation:
            return ([f'  la {out_reg}, {dest_label}',
                     f'  xor {out_reg}, {arg_regs[0]}',
                     f'  addi {out_reg}, 2',
                     ], 2)
        else:
            return BranchTest.postprocess_jump(self, insn, arg_regs, out_reg, dest_label, post_branch_label, test_preservation)

    def gen_branch(self, insn, arg_regs, dest_label, post_branch_label, tempreg, test_preservation=False):
        # If we are checking for register preservation for arg_regs[0], we mustn't write to it:
        tmp = tempreg if test_preservation else arg_regs[0]
        return [f'  la   {tmp}, {dest_label}',
                f'  {insn.name}  {tmp}',
                f'{post_branch_label}:'] # we only need this one for JumpAndLinkRegisterStackTest



class JumpAndLinkRegisterStackTest(JumpRegisterTest):
    def __init__(self):
        BranchTest.__init__(self, lambda _ : True)

    @property
    def needs_sp(self):
        return True

    @property
    def can_take_sp_arg(self): # don't test "jalr $sp"
        return False

    def postprocess_jump(self, insn, arg_regs, out_reg, dest_label, post_branch_label, test_preservation):
        if not test_preservation:
            return ([f'  la {arg_regs[0]}, {post_branch_label}',
                     f'  pop {out_reg}',
                     f'  xor {out_reg}, {arg_regs[0]}',
                     f'  addi {out_reg}, 2',
                     ], 2)
        else:
            return ([f'  pop {out_reg}'], None)


class JumpAndLinkStackTest(BranchTest):
    def __init__(self):
        BranchTest.__init__(self, lambda : True)

    @property
    def needs_sp(self):
        return True

    def postprocess_jump(self, insn, arg_regs, out_reg, dest_label, post_branch_label, test_preservation):
        if not test_preservation:
            # Not backing anyhting up, so we can grab any temp register
            return ([f'  la $t0, {post_branch_label}',
                     f'  pop {out_reg}',
                     f'  xor {out_reg}, $t0',
                     f'  addi {out_reg}, 2',
                     ], 2)
        else:
            return ([f'  pop {out_reg}'], None)

    def gen_branch(self, insn, arg_regs, dest_label, post_branch_label, tempreg, test_preservation=False):
        tmp = tempreg
        # return [f'  la   {tmp}, {dest_label}',
        #         f'  {insn.name}  {tmp}',
        return [f'  {insn.name} {dest_label}',
                f'{post_branch_label}:']


class MemoryTest(Test):
    '''
    Base class for MemoryReadTest and MemoryWriteTest
    '''
    selection = 0 # counter per call to data_section(); disambiguates labels

    def __init__(self, tc, bytes_nr, results=1):
        Test.__init__(self, tc)
        self.limits = {}
        self.bytes_nr = bytes_nr
        self.long_values = [0x010203040608090c * n for n in [1, 5, 7, 11, 13, 17, 19]]
        if bytes_nr == 8:
            self.asm_mem_region = '.word'
            self.loadop = 'ld'
            self.test_data = self.long_values
        elif bytes_nr == 1:
            self.asm_mem_region = '.byte'
            self.loadop = 'lb'
            self.test_data = [0x11 * n for n in range(0, 8)]
        else:
            raise Exception('Unsupported byte width: %d' % bytes_nr)
        self.results_nr = results

    def data_section(self, extract=0):
        '''
        @param How many test numbers to move from labels to the list of extracted values

        returns (data section, list of (label, initial value), list of extracted values)
        '''
        extracted = self.long_values[:extract]
        td = [d for d in self.test_data if d not in extracted]
        data = [self.asm_mem_region]
        mappings = []
        selection = MemoryTest.selection
        MemoryTest.selection += 1
        for t in td:
            label = 'datalabel_%d_%d' % (selection, len(mappings))
            mappings.append((label, t))
            data.append(label + ':')
            data.append('  %d' % t)
        return (data, mappings, extracted)

    def gen_tests_for_expected_behaviour(self, binary, insn):
        args = insn.args

        # hold back two numbers to initialise the inoutreg with (either to write, or to ensure it was overwritten on load)
        data, labels, extracted = self.data_section(2)

        iodata = extracted

        for inoutreg in Test.ALL_REGISTERS:
            for indexreg in Test.ALL_REGISTERS:
                for label_index in [2, 3]:
                    for delta in [0, -1, 1]:
                        for iodatum in iodata:
                            data, labels, extracted = self.data_section(2)
                            temps = self.get_free_temps([inoutreg, indexreg, '$a0'])
                            prefix = [
                                '  move %s, %s ; back up index' % (temps[0], indexreg),
                                '  move %s, %s ; back up loadstore' % (temps[1], inoutreg),
                                '  li %s, %d' % (inoutreg, iodatum),
                                '  la %s, %s' % (indexreg, labels[label_index][0]),
                            ]

                            call = ['  %s %s, %s(%s)' % (insn.name, inoutreg, delta * self.bytes_nr, indexreg)]

                            suffix = [
                                '  move %s, %s ; prep print' % (temps[2], inoutreg),
                                '  move %s, %s ; restore loadstore' % (inoutreg, temps[1]),
                                '  move %s, %s ; restore index' % (indexreg, temps[0]),
                                '  move $a0, %s' % (temps[2])
                            ]

                            if indexreg == inoutreg:
                                result = self.test_postprocess_operation_on_shared_registers(suffix, '$a0', labels[label_index][0], do_mask=False)
                                if result is not None:
                                    iodatum = result

                            suffix += [
                                '  jal print_int',
                            ]

                            body = prefix + call + suffix

                            expected_label_index = label_index + delta
                            current_label_index = 0
                            # Also print out memory contents
                            for (l, _) in labels:
                                body += [
                                    '  la $v0, %s' % l,
                                    '  %s $a0, 0($v0)' % self.loadop
                                ]

                                if current_label_index == expected_label_index:
                                    if indexreg == inoutreg:
                                        self.test_postprocess_operation_on_shared_registers(body, '$a0', labels[label_index][0], do_mask=True)

                                body += [
                                    '  jal print_int',
                                ]
                                current_label_index += 1

                            class Memory(list):
                                def update(self, index, v):
                                    l = Memory(self)
                                    l[index] = v
                                    return l

                            input_mem = Memory(l[1] for l in labels)
                            mem, n = self.testclosure(input_mem, iodatum, delta, label_index)
                            expected = [n] + mem
                            self.expect(binary, body, data, expected)

    def test_postprocess_operation_on_shared_registers(self, suffix, arg, label, do_mask):
        '''
        For tests of the form

          memop $r0, n($r0)

        we have $r0 both as index and as load or store value register.  For store
        operations, we must thus postprocess $r0 before we print it out, since it
        will be equal to a memory label whose address we can't predict.

        @param suffix  List of operations that we can attach postprocessing to
        @param arg     Register in which the contents of $r0 are stored right before printing them
        @param label   The label that we loaded into $r0
        @param do_mask 'arg' is truncated to the self.bytes_nr least significant bytes
        @return The value that we should expect for 'arg'
        '''
        raise Exception('Not implemented')

    def gen_tests_for_preservation(self, binary, insn):
        def try_test(args, tempregs_selection):
            for reg in Test.ALL_REGISTERS:
                tempreg = tempregs_selection
                if type(tempregs_selection) is tuple:
                    local_tempregs = list(tempregs_selection)
                else:
                    local_tempregs = [tempregs_selection]
                if reg in tempregs_selection:
                    continue
                (data, labels, extracted) = self.data_section()
                prefix, suffix = [], []

                if args[1] != '0':
                    print('args: %s' % [args])
                    raise Exception('args: %s' % [args])

                if type(tempreg) is tuple: # two results and two temp registers?
                    prefix = ['  move %s, %s ; dest register: back up' % (tempreg[0], args[0])]
                    suffix = ['  move %s, %s ; dest register: restore' % (args[0], tempreg[0])]
                    resultargs = [args[0], args[1]]
                    tempreg = [tempreg[1]]
                else:
                    tempreg = [tempreg]
                    resultargs = [args[0]]

                body = prefix + [
                    '  move %s, %s ; back up' % (tempreg[0], args[2]),
                    '  la %s, %s' % (args[2], labels[1][0]),
                    '  %s %s   ; test' % (insn.name, ', '.join(args)), # the insn we care about
                    '  move %s, %s ; restore' % (args[2], tempreg[0]),
                    ] + suffix

                if reg not in tempreg and reg not in resultargs:
                    self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg] + local_tempregs)[0])

        self.try_test_for_preservation(binary, insn, try_test, results_nr = self.results_nr + 1)


class MemoryLoadTest(MemoryTest):
    def __init__(self, tc, bytes_nr):
        MemoryTest.__init__(self, tc, bytes_nr, results=1)

    def test_postprocess_operation_on_shared_registers(self, suffix, arg, label, do_mask):
        pass


class MemoryStoreTest(MemoryTest):
    def __init__(self, tc, bytes_nr):
        MemoryTest.__init__(self, tc, bytes_nr, results=0)

    def test_postprocess_operation_on_shared_registers(self, suffix, arg, label, do_mask):
        suffix += [ '  la $t0, %s' % (label) ]
        if do_mask and self.bytes_nr < 8:
            suffix += [ '  andi $t0, 0x%x' % (0xffffffff >> ((4 - self.bytes_nr) << 3)) ]
        suffix += [ '  xor %s, $t0' % arg ]
        return 0


class PushTest(Test):
    '''
    Test for the 'push' operation
    '''
    def __init__(self):
        Test.__init__(self, None)

    def gen_tests_for_expected_behaviour(self, binary, insn):
        for pushreg in Test.ALL_REGISTERS:
            for loadval in [8, 32]:
                tmpreg = self.get_free_temps([pushreg])[0]
                sp_backupreg = '$s1' if pushreg == '$s0' else '$s0'
                body = [
                    f'  subi $sp, 256',
                    f'  sd   {sp_backupreg}, 128($sp)',
                    f'  move {sp_backupreg}, $sp',
                    f'  move {tmpreg}, {pushreg}',
                    f'  subi {pushreg}, {loadval}' if pushreg == '$sp' else f'  li   {pushreg}, {loadval}',
                    f'  push {pushreg}',
                    f'  move {pushreg}, {tmpreg}' if pushreg != '$sp' else '  ; --',
                    f'  move $a0, $sp',
                    f'  sub  $a0, {sp_backupreg}',
                    f'  jal  print_int',
                    f'  ld   $a0, 0($sp)',
                    f'  sub  $a0, $sp' if pushreg == '$sp' else f'  ; report verbatim',
                    f'  jal  print_int',
                    f'  move $sp, {sp_backupreg}',
                    f'  ld   {sp_backupreg}, 128($sp)',
                    f'  addi $sp, 256',
                ]

                if pushreg == '$sp':
                    expected = [-(loadval + 8), 8]
                else:
                    expected = [-8, loadval]

                self.expect(binary, body, [], expected)

    def gen_tests_for_preservation(self, binary, insn):
        def try_test(args, tempreg):
            for reg in Test.ALL_REGISTERS:
                if reg == '$sp':
                    continue # checked as part of the normal tests
                body = [
                    f'  move {tempreg}, $sp ; back up',
                    f'  push {reg}',
                    f'  move $sp, {tempreg}',
                ]

                if reg != tempreg:
                    self.expect_preservation(binary, body, reg, [], self.get_free_temps([reg, tempreg])[0])

        self.try_test_for_preservation(binary, insn, try_test, results_nr = 1)


class PopTest(Test):
    '''
    Test for the 'push' operation
    '''
    def __init__(self):
        Test.__init__(self, None)

    def gen_tests_for_expected_behaviour(self, binary, insn):
        for popreg in Test.ALL_REGISTERS:
            for loadval in [8, 32]:
                tmpreg = self.get_free_temps([popreg])
                sp_backupreg = '$s1' if popreg == '$s0' else '$s0'
                body = [
                    f'  subi $sp, 256',
                    f'  sd   {sp_backupreg}, 128($sp)',
                    f'  move {sp_backupreg}, $sp',
                    f'  move {tmpreg[0]}, {popreg}',
                    f'  subi {popreg}, {loadval}'         if popreg == '$sp' else f'  li   {popreg}, {loadval}',
                    f'  sd   {popreg}, 0({sp_backupreg})' if popreg == '$sp' else f'  sd   {popreg}, 0($sp)',
                    f'  move {popreg}, {sp_backupreg}'    if popreg == '$sp' else f'  li   {popreg}, -1',
                    f'  pop  {popreg}',
                    f'  move {tmpreg[1]}, {popreg}',
                    f'  move $a0, $sp',
                    f'  move {popreg}, {tmpreg[0]}'       if popreg != '$a0' else f'  ;--- skip',
                    # $a0 is $sp after pop
                    # sp_backupreg is $sp before pop
                    # tmpreg[1] is the popped value
                    f'  sd   {tmpreg[1]}, 0($sp)',
                    f'  sub  $a0, {sp_backupreg}',
                    f'  move $sp, {sp_backupreg}',
                    f'  jal  print_int',
                    f'  ld   $a0, 0($sp)',
                    f'  sub  $a0, $sp' if popreg == '$sp' else f'  ; report verbatim',
                    f'  jal  print_int',
                    f'  move $sp, {sp_backupreg}',
                    f'  ld   {sp_backupreg}, 128($sp)',
                    f'  addi $sp, 256',
                ]

                if popreg == '$sp':
                    expected = [-loadval, -loadval]
                else:
                    expected = [8, loadval]

                self.expect(binary, body, [], expected)

    def gen_tests_for_preservation(self, binary, insn):
        def try_test(args, tempreg):
            for reg in Test.ALL_REGISTERS:
                if reg == '$sp':
                    continue # checked as part of the normal tests
                body = [
                    f'  move {tempreg}, {reg} ; back up',
                    f'  subi $sp, 8',
                    f'  pop {reg}',
                    f'  move {reg}, {tempreg}',
                ]

                if reg != tempreg:
                    self.expect_preservation(binary, body, reg, [], self.get_free_temps([reg, tempreg])[0])

        self.try_test_for_preservation(binary, insn, try_test, results_nr = 1)


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
