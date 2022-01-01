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

from gen_assembly import *
import gen_tests as tests

InsnBuilder = InsnSet.make()
Insn = InsnBuilder.insn
build_for = InsnBuilder.build


Insn('move', '$r0 := $r1',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a,b : b))
Insn('li', '$r0 := %v',
     [R0, I64U],
     test=tests.ArithmeticTest(lambda a,b : b))

# arithmetic

Insn('add', ArithmeticEffect('+'),
     [R0, R1],
     test=tests.ArithmeticTest(lambda a,b : a + b))
Insn('addi', ArithmeticImmediateEffect('+'),
     [R0, I32U],
     test=tests.ArithmeticTest(lambda a,b : a + b))
Insn('sub', ArithmeticEffect('$-$'),
     [R0, R1],
     test=tests.ArithmeticTest(lambda a,b : a - b))
Insn('subi', '$r0 := $r0 $$-$$ %v',
     [R0, I32U],
     test=tests.ArithmeticTest(lambda a,b : a - b))
Insn('mul', ArithmeticEffect('*'),
     [R0, R1],
     test=tests.ArithmeticTest(lambda a,b : a * b))

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
     [R0, R1],
     test=tests.ArithmeticTest(lambda a,b : 1 if b == 0 else 0)),

# bitwise ops

Insn('and', '$r0 := $r0 bitwise-and $r1',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : a & b))
Insn('andi', '$r0 := $r0 bitwise-and %v',
     [R0, I32U],
     test=tests.ArithmeticTest(lambda a, b : a & b))

Insn('or', '$r0 := $r0 bitwise-or $r1',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : a | b))
Insn('ori', '$r0 := $r0 bitwise-or %v',
     [R0, I32U],
     test=tests.ArithmeticTest(lambda a, b : a | b))

Insn('xor', '$r0 := $r0 bitwise-exclusive-or $r1',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : a ^ b))
Insn('xori', '$r0 := $r0 bitwise-exclusive-or %v',
     [R0, I32U],
     test=tests.ArithmeticTest(lambda a, b : a ^ b))

# bit shifting

Insn('sll', '$r0 := $r0 $${<}{<}$$ $r1[0:7]',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : tests.shl(a, (0x3f & b))))

Insn('slli', '$r0 := $r0 bit-shifted left by %v',
     [R0, I8U],
     test=tests.ArithmeticTest(lambda a, b : tests.shl(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0))

Insn('srl', '$r0 := $r0 $${>}{>}$$ $r1[0:7]',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : tests.shr(a, (0x3f & b))))

Insn('srli', '$r0 := $r0 bit-shifted right by %v',
     [R0, I8U],
     test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0))

Insn('sra', '$r0 := $r0 $${>}{>}$$ $r1[0:7], sign-extended',
     [R0, R1],
     test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b, arithmetic=True)))

Insn('srai', '$r0 := $r0 bit-shifted right by %v, sign-extended',
     [R0, I8U],
     test=tests.ArithmeticTest(lambda a, b : tests.shr(a, 0x3f & b, arithmetic=True)).filter_for_testarg(1, lambda x : x >= 0))

# conditional set

Insn('sgt', 'if $r1 $$>$$ $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b > c else 0))

Insn('sge', 'if $r1 $$\ge$$ $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b >= c else 0))

Insn('slt', 'if $r1 $$<$$ $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b < c else 0))

Insn('sle', 'if $r1 $$\le$$ $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b <= c else 0))

Insn('seq', 'if $r1 = $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b == c else 0))

Insn('sne', 'if $r1 $$\ne$$ $r2 then $r1 := 1 else $r1 := 0',
     [R0, R1, R2],
     test=tests.ArithmeticTest(lambda a, b, c : 1 if b != c else 0))

# branches

Insn('bgt', 'if $r0 $$>$$ $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a > b))

Insn('bge', 'if $r0 $$\ge$$ $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a >= b))

Insn('blt', 'if $r0 $$<$$ $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a < b))

Insn('ble', 'if $r0 $$\le$$ $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a <= b))

Insn('beq', 'if $r0 = $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a == b))

Insn('bne', 'if $r0 $$\ne$$ $r1, then jump to %a',
     [R0, R1, PCREL32S],
     test=tests.BranchTest(lambda a, b : a != b))


Insn('bgtz', 'if $r0 $$>$$ 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a > 0))

Insn('bgez', 'if $r0 $$\ge$$ 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a >= 0))

Insn('bltz', 'if $r0 $$<$$ 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a < 0))

Insn('blez', 'if $r0 $$\le$$ 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a <= 0))

Insn('beqz', 'if $r0 = 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a == 0))

Insn('bnez', 'if $r0 $$\ne$$ 0, then jump to %a',
     [R0, PCREL32S],
     test=tests.BranchTest(lambda a : a != 0))

# store and load

Insn('sb', 'mem8[$r1 + %v] := $r0[7:0]',
     [R0, I32S, R1],
     test=tests.MemoryStoreTest((lambda mem, a, b, c: (mem.update(b + c, a & 0xff), a)), 1),
     format='%s, %s(%s)')
Insn('lb', '$r0 := mem8[$r1 + %v]',
     [R0, I32S, R1],
     test=tests.MemoryLoadTest((lambda mem, a, b, c: (mem, mem[b + c] & 0xff)), 1),
     format='%s, %s(%s)')

Insn('sd', 'mem64[$r1 + %v] := $r0',
     [R0, I32S, R1],
     test=tests.MemoryStoreTest((lambda mem, a, b, c: (mem.update(b + c, a), a)),  8),
     format='%s, %s(%s)')
Insn('ld', '$r0 := mem64[$v + %r1goo]',
     [R0, I32S, R1],
     test=tests.MemoryLoadTest((lambda mem, a, b, c: (mem, mem[b + c])), 8),
     format='%s, %s(%s)')

# jumps

Insn('j', 'push next instruction address, jump to %a',
     [PCREL32S],
     test=tests.BranchTest(lambda : True))

Insn('jr', 'jump to $r0',
     [R0],
     test=tests.JumpRegisterTest())

Insn('jal', 'push next instruction address, jump to %a',
     [PCREL32S],
     test=tests.JumpAndLinkStackTest())

Insn('jalr', 'push next instruction address, jump to $r0',
     [R0],
     test=tests.JumpAndLinkRegisterStackTest())

Insn('jreturn', 'jump to mem64[$sp]; $sp := $sp + 8',
     [],
     test=tests.StackReturnTest())

# syscall

Insn('syscall', 'system call',
     [])

# push and pop

Insn("push", '$sp := $sp - 8; mem64[$sp] = $r0',
     [R0],
     test=tests.PushTest())

Insn("pop", '$r0 = mem64[$sp]; $sp := $sp + 8',
     [R0],
     test=tests.PopTest())


