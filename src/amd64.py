# This file is Copyright (C) 2014-2021 Christoph Reichenbach
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
# The author can be reached as "christoph.reichenbach" at cs.lth.se


from gen_assembly import *

'''
AMD64 / x86_64 / EM64T / x64 instruction support for code generation

This file contains the amd64-specific ISA parts (or will, once refactoring is complete)
'''

REGISTER_PAIRINGS = [
    ("rax", "$v0"), # 0
    ("rcx", "$a3"),
    ("rdx", "$a2"),
    ("rbx", "$s0"),
    ("rsp", "$sp"), # 4
    ("rbp", "$fp"),
    ("rsi", "$a1"),
    ("rdi", "$a0"),
    ("r8",  "$a4"), # 8
    ("r9",  "$a5"),
    ("r10", "$t0"),
    ("r11", "$t1"),
    ("r12", "$s1"), # 12
    ("r13", "$s2"),
    ("r14", "$s3"),
    ("r15", "$gp")
]

REG_STRUCT = make_registers(REGISTER_PAIRINGS)
rax : MachineRegister = REG_STRUCT['rax']
rbx : MachineRegister = REG_STRUCT['rbx']
rcx : MachineRegister = REG_STRUCT['rcx']
rdx : MachineRegister = REG_STRUCT['rdx']
REGISTERS : list[Register] = REG_STRUCT['REGISTERS']

def ArithmeticDestReg(offset, baseoffset=0):
    return Reg([BitPattern(baseoffset, 0, 1), BitPattern(offset, 0, 3)])
def ArithmeticSrcReg(offset, baseoffset=0):
    return Reg([BitPattern(baseoffset, 2, 1), BitPattern(offset, 3, 3)])
def OptionalArithmeticDestReg(offset):
    return Reg([BitPattern(-1, 0, 1), BitPattern(offset, 0, 3)])


MachineInsn = MachineInsn('amd64')

'''MOV dest, src'''
MOV_rr = MachineInsn('MOV', [0x48, 0x89, 0xc0], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

'''MOV dest, imm64'''
MOV_ri = MachineInsn('MOV', [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0], [
    ArithmeticDestReg(1),
    ImmLongLong(2)
])

'''ADD dest, src'''
ADD_rr = MachineInsn('ADD',  [0x48, 0x01, 0xc0], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

'''ADD dest, imm_u32'''
ADD_ri = MachineInsn('ADD',  [0x48, 0x81, 0xc0, 0, 0, 0, 0], [
    ArithmeticDestReg(2),
    ImmUInt(3),
])

'''XCHG r0, r1'''
XCHG = MachineInsn('ADD',  [0x48, 0x87, 0xc1], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

