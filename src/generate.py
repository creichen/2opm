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

# assume 16 registers total

import sys
import amd64
from gen_assembly import *
import gen_tests as tests

arch = amd64

try:
    from termcolor import colored
except:
    def colored(text, *col):
        return text


instructions = InsnSet(
    Insn('move', '$r0 := $r1',
         [R(0), R(1)],
         amd64.MOV_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a,b : b)),
    Insn('li', '$r0 := %v',
         [R(0), I64U],
         amd64.MOV_ri(R(0), I64U),
         test=tests.ArithmeticTest(lambda a,b : b)),

    # arithmetic

    Insn('add', ArithmeticEffect('+'),
         [R(0), R(1)],
         amd64.ADD_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a,b : a + b)),
    Insn('addi', ArithmeticImmediateEffect('+'),
         [R(0), I32U],
         amd64.ADD_ri(R(0), I32U),
         test=tests.ArithmeticTest(lambda a,b : a + b)),
    Insn('sub', ArithmeticEffect('$-$'),
         [R(0), R(1)],
         amd64.SUB_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a,b : a - b)),
    Insn('subi', '$r0 := $r0 $$-$$ %v',
         [R(0), I32U],
         amd64.SUB_ri(R(0), I32U),
         test=tests.ArithmeticTest(lambda a,b : a - b)),
    Insn('mul', ArithmeticEffect('*'),
         [R(0), R(1)],
         amd64.IMUL_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a,b : a * b)),

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
    #                  test=tests.ArithmeticTest(lambda a,b,c : (intdiv(a, c), intmod(a, c)), results=2).filter_for_testarg(2, lambda v : v != 0).without_shared_registers()),

    # logical not

    Insn('not', 'if $r1 = 0 then $r1 := 1 else $r1 := 0',
         [R(0), R(1)],
         [
             amd64.TEST_rr(R(1), R(1)),
             amd64.MOV_ri32(R(0), MachineLiteral(0)),
             amd64.SETE_r(R(0)),
         ],
         test=tests.ArithmeticTest(lambda a,b : 1 if b == 0 else 0)),

    # bitwise ops

    Insn('and', '$r0 := $r0 bitwise-and $r1',
         [R(0), R(1)],
         amd64.AND_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a, b : a & b)),
    Insn('andi', '$r0 := $r0 bitwise-and %v',
         [R(0), I32U],
         amd64.AND_ri(R(0), I32U),
         test=tests.ArithmeticTest(lambda a, b : a & b)),

    Insn('or', '$r0 := $r0 bitwise-or $r1',
         [R(0), R(1)],
         amd64.OR_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a, b : a | b)),
    Insn('ori', '$r0 := $r0 bitwise-or %v',
         [R(0), I32U],
         amd64.OR_ri(R(0), I32U),
         test=tests.ArithmeticTest(lambda a, b : a | b)),

    Insn('xor', '$r0 := $r0 bitwise-exclusive-or $r1',
         [R(0), R(1)],
         amd64.XOR_rr(R(0), R(1)),
         test=tests.ArithmeticTest(lambda a, b : a ^ b)),
    Insn('xori', '$r0 := $r0 bitwise-exclusive-or %v',
         [R(0), I32U],
         amd64.XOR_ri(R(0), I32U),
         test=tests.ArithmeticTest(lambda a, b : a ^ b)),

    # bit shifting

    Insn('sll', '$r0 := $r0 $${<}{<}$$ $r1[0:7]',
         [R(0), R(1)],
         Insn.cond(
             (R(1) == amd64.rcx)
             >> (amd64.SHL_r(R(0))),

             (R(0) == R(1))
             >> [
                 amd64.XCHG(amd64.rcx, R(0)),
                 amd64.SHL_r(amd64.rcx),
                 amd64.XCHG(amd64.rcx, R(0))
             ],

             (R(0) == amd64.rcx)
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SHL_r(R(1)),
                 amd64.XCHG(amd64.rcx, R(1))
             ],

             Insn@'default'
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SHL_r(R(0)),
                 amd64.XCHG(amd64.rcx, R(1))
             ]),
         test=tests.ArithmeticTest(lambda a, b : tests.shl(a, (0x3f & b)))),

    Insn('slli', '$r0 := $r0 bit-shifted left by %v',
         [R(0), I8U],
         amd64.SHL_ri(R(0), I8U),
         test=tests.ArithmeticTest(lambda a, b : tests.shl(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0)),

    Insn('srl', '$r0 := $r0 $${>}{>}$$ $r1[0:7]',
         [R(0), R(1)],
         Insn.cond(
             (R(1) == amd64.rcx)
             >> (amd64.SHR_r(R(0))),

             (R(0) == R(1))
             >> [
                 amd64.XCHG(amd64.rcx, R(0)),
                 amd64.SHR_r(amd64.rcx),
                 amd64.XCHG(amd64.rcx, R(0))
             ],

             (R(0) == amd64.rcx)
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SHR_r(R(1)),
                 amd64.XCHG(amd64.rcx, R(1))
             ],

             Insn@'default'
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SHR_r(R(0)),
                 amd64.XCHG(amd64.rcx, R(1))
             ]),
         test=tests.ArithmeticTest(lambda a, b : tests.shr(a, (0x3f & b)))),

    Insn('srli', '$r0 := $r0 bit-shifted right by %v',
         [R(0), I8U],
         amd64.SHR_ri(R(0), I8U),
         test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0)),

    Insn('sra', '$r0 := $r0 $${>}{>}$$ $r1[0:7], sign-extended',
         [R(0), R(1)],
         Insn.cond(
             (R(1) == amd64.rcx)
             >> (amd64.SAR_r(R(0))),

             (R(0) == R(1))
             >> [
                 amd64.XCHG(amd64.rcx, R(0)),
                 amd64.SAR_r(amd64.rcx),
                 amd64.XCHG(amd64.rcx, R(0))
             ],

             (R(0) == amd64.rcx)
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SAR_r(R(1)),
                 amd64.XCHG(amd64.rcx, R(1))
             ],

             Insn@'default'
             >> [
                 amd64.XCHG(amd64.rcx, R(1)),
                 amd64.SAR_r(R(0)),
                 amd64.XCHG(amd64.rcx, R(1))
             ]),
         test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b, arithmetic=True))),

    Insn('srai', '$r0 := $r0 bit-shifted right by %v, sign-extended',
         [R(0), I8U],
         amd64.SAR_ri(R(0), I8U),
         test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b, arithmetic=True)).filter_for_testarg(1, lambda x : x >= 0)),

    # conditional set

    Insn('slt', 'if $r1 $$<$$ $r2 then $r1 := 1 else $r1 := 0',
         [R(0), R(1), R(2)],
         [
             amd64.CMP_rr(R(1), R(2)),
             amd64.MOV_ri32(R(0), MachineLiteral(0)),
             amd64.SETL_r(R(0)),
         ],
         test=tests.ArithmeticTest(lambda a, b, c : 1 if b < c else 0)),

    Insn('sle', 'if $r1 $$\le$$ $r2 then $r1 := 1 else $r1 := 0',
         [R(0), R(1), R(2)],
         [
             amd64.CMP_rr(R(1), R(2)),
             amd64.MOV_ri32(R(0), MachineLiteral(0)),
             amd64.SETLE_r(R(0)),
         ],
         test=tests.ArithmeticTest(lambda a, b, c : 1 if b <= c else 0)),

    Insn('seq', 'if $r1 = $r2 then $r1 := 1 else $r1 := 0',
         [R(0), R(1), R(2)],
         [
             amd64.CMP_rr(R(1), R(2)),
             amd64.MOV_ri32(R(0), MachineLiteral(0)),
             amd64.SETE_r(R(0)),
         ],
         test=tests.ArithmeticTest(lambda a, b, c : 1 if b == c else 0)),

    Insn('sne', 'if $r1 $$\ne$$ $r2 then $r1 := 1 else $r1 := 0',
         [R(0), R(1), R(2)],
         [
             amd64.CMP_rr(R(1), R(2)),
             amd64.MOV_ri32(R(0), MachineLiteral(0)),
             amd64.SETNE_r(R(0)),
         ],
         test=tests.ArithmeticTest(lambda a, b, c : 1 if b != c else 0)),

    # branches

    Insn('bgt', 'if $r0 $$>$$ $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JG_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a > b)),
    Insn('bge', 'if $r0 $$\ge$$ $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JGE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a >= b)),
    Insn('blt', 'if $r0 $$<$$ $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JL_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a < b)),
    Insn('ble', 'if $r0 $$\le$$ $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JLE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a <= b)),
    Insn('beq', 'if $r0 = $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a == b)),
    Insn('bne', 'if $r0 $$\ne$$ $r1, then jump to %a',
         [R(0), R(1), PCREL32S],
         [ amd64.CMP_rr(R(0), R(1)),  amd64.JNE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a, b : a != b)),

    Insn('bgtz', 'if $r0 $$>$$ 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JG_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a > 0)),
    Insn('bgez', 'if $r0 $$\ge$$ 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JGE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a >= 0)),
    Insn('bltz', 'if $r0 $$<$$ 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JL_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a < 0)),
    Insn('blez', 'if $r0 $$\le$$ 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JLE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a <= 0)),
    Insn('beqz', 'if $r0 = 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a == 0)),
    Insn('bnez', 'if $r0 $$\ne$$ 0, then jump to %a',
         [R(0), PCREL32S],
         [ amd64.CMP_ri(R(0), MachineLiteral(0)),  amd64.JNE_i(PCREL32S) ],
         test=tests.BranchTest(lambda a : a != 0)),

    # store and load

    Insn('sb', 'mem8[$r1 + %v] := $r0[7:0]',
         [R(0), I32S, R(1)],
         #amd64.MOV_mr8(R(0), I32S, R(1)),
         Insn.cond((R(1) == amd64.rsp) >>  amd64.MOV_mr8_sp(R(0), I32S),
                   (R(1) == amd64.r12) >>  amd64.MOV_mr8_r12(R(0), I32S),
                   Insn@'default'      >>  amd64.MOV_mr8(R(0), I32S, R(1))),
         test=tests.MemoryStoreTest((lambda mem, a, b, c: (mem.update(b + c, a & 0xff), a)), 1),
         format='%s, %s(%s)'),
    Insn('lb', '$r0 := mem8[$r1 + %v]',
         [R(0), I32S, R(1)],
         Insn.cond((R(1) == amd64.rsp) >>  amd64.MOVZBQ_rm8_sp(R(0), I32S),
                   (R(1) == amd64.r12) >>  amd64.MOVZBQ_rm8_r12(R(0), I32S),
                   Insn@'default'      >>  amd64.MOVZBQ_rm8(R(0), I32S, R(1))),
         test=tests.MemoryLoadTest((lambda mem, a, b, c: (mem, mem[b + c] & 0xff)), 1),
         format='%s, %s(%s)'),

    Insn('sd', 'mem64[$r1 + %v] := $r0',
         [R(0), I32S, R(1)],
         Insn.cond((R(1) == amd64.rsp) >>  amd64.MOV_mr_sp(R(0), I32S),
                   (R(1) == amd64.r12) >>  amd64.MOV_mr_r12(R(0), I32S),
                   Insn@'default'      >>  amd64.MOV_mr(R(0), I32S, R(1))),
         test=tests.MemoryStoreTest((lambda mem, a, b, c: (mem.update(b + c, a), a)),  8),
         format='%s, %s(%s)'),
    Insn('ld', '$r0 := mem64[$v + %r1goo]',
         [R(0), I32S, R(1)],
         Insn.cond((R(1) == amd64.rsp) >>  amd64.MOV_rm_sp(R(0), I32S),
                   (R(1) == amd64.r12) >>  amd64.MOV_rm_r12(R(0), I32S),
                   Insn@'default'      >>  amd64.MOV_rm(R(0), I32S, R(1))),
         test=tests.MemoryLoadTest((lambda mem, a, b, c: (mem, mem[b + c])), 8),
         format='%s, %s(%s)'),

    # jumps

    Insn('j', 'push next instruction address, jump to %a',
         [PCREL32S],
         amd64.JMP_i(PCREL32S),
         test=tests.BranchTest(lambda : True)),
    Insn('jr', 'jump to $r0',
         [R(0)],
         amd64.JMP_r(R(0)),
         test=tests.JumpRegisterTest()),
    Insn('jal', 'push next instruction address, jump to %a',
         [PCREL32S],
         amd64.CALLQ_i(PCREL32S),
         test=tests.JumpAndLinkStackTest()),
    Insn('jalr', 'push next instruction address, jump to $r0',
         [R(0)],
         amd64.CALLQ_r(R(0))),
    Insn('jreturn', 'jump to mem64[$sp]; $sp := $sp + 8',
         [],
         amd64.RET(),
         test=tests.StackReturnTest()),

    # syscall

    Insn('syscall', 'system call',
         [],
         amd64.SYSCALL()),

    # push and pop

    Insn("push", '$sp := $sp - 8; mem64[$sp] = $r0',
         [R(0)],
         amd64.PUSH(R(0)),
         test=tests.PushTest()),
    Insn("pop", '$r0 = mem64[$sp]; $sp := $sp + 8',
         [R(0)],
         amd64.POP(R(0)),
         test=tests.PopTest())
)


def print_usage():
    print('usage: ')
    for n in ['headers', 'code', 'latex', 'assembler', 'assembler-header', 'test <path-to-2opm-binary> [optional-list-of-comma-separated-insns]']:
        print('\t' + sys.argv[0] + ' ' + n)

def print_warning():
    print('// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!')

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

    for mtype in MachineArgType.ALL:
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
    if sys.argv[1] == 'headers':
        print_warning()
        print_header_header()
        for insn in instructions:
            insn.print_encoder_header()
        instructions.print_disassembler_doc()
        instructions.print_disassembler_header()

    elif sys.argv[1] == 'code':
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

    elif sys.argv[1] == 'assembler':
        print_assembler_module()

    elif sys.argv[1] == 'assembler-header':
        print_assembler_header()

    elif sys.argv[1] == 'test':
        run_tests(sys.argv[2], sys.argv[3:])

    else:
        print_usage()

else:
    print_usage()
