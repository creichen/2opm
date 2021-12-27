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
    ('rax', '$v0'), # 0
    ('rcx', '$a3'),
    ('rdx', '$a2'),
    ('rbx', '$s0'),
    ('rsp', '$sp'), # 4
    ('rbp', '$fp'),
    ('rsi', '$a1'),
    ('rdi', '$a0'),
    ('r8',  '$a4'), # 8
    ('r9',  '$a5'),
    ('r10', '$t0'),
    ('r11', '$t1'),
    ('r12', '$s1'), # 12
    ('r13', '$s2'),
    ('r14', '$s3'),
    ('r15', '$gp')
]

REG_STRUCT = make_registers(REGISTER_PAIRINGS)
rax : MachineRegister = REG_STRUCT['rax']
rbx : MachineRegister = REG_STRUCT['rbx']
rcx : MachineRegister = REG_STRUCT['rcx']
rdx : MachineRegister = REG_STRUCT['rdx']
REGISTERS : list[MachineRegister] = REG_STRUCT['REGISTERS']
REGISTER_MAP : dict[str, MachineRegister] = REG_STRUCT['REGISTER_MAP']

def ArithmeticDestReg(offset):
    return MachineFormalRegister(MultiByteEncoding.at((offset, 0, 3), (0, 0, 1)))
def ArithmeticSrcReg(offset):
    return MachineFormalRegister(MultiByteEncoding.at((offset, 3, 3), (0, 2, 1)))
def Immediate64U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM64U, MultiByteEncoding.span(offset, 8))
def Immediate32U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM32U, MultiByteEncoding.span(offset, 4))
def Immediate8U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM8U, SingleByteEncoding.at(offset, 0, 0, 8))

# FIXME: use address instead
def AddressPCRelative(offset):
    return MachineFormalImmediate(ASM_ARG_PCREL32S, MultiByteEncoding.span(offset, 4))

(MISet, MachineInsn) = MachineInsnFactory('amd64')

'''MOV dest, src'''
MOV_rr = MachineInsn('MOV', [0x48, 0x89, 0xc0], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

'''MOV dest, imm64'''
MOV_ri = MachineInsn('MOV', [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0], [
    ArithmeticDestReg(1),
    Immediate64U(2)
])

'''ADD dest, src'''
ADD_rr = MachineInsn('ADD',  [0x48, 0x01, 0xc0], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

'''ADD dest, imm_u32'''
ADD_ri = MachineInsn('ADD',  [0x48, 0x81, 0xc0, 0, 0, 0, 0], [
    ArithmeticDestReg(2),
    Immediate32U(3),
])

'''XCHG r0, r1'''
XCHG = MachineInsn('XCHG',  [0x48, 0x87, 0xc0], [
    ArithmeticDestReg(2),
    ArithmeticSrcReg(2)
])

'''PUSH r0'''
PUSH = MachineInsn('PUSH', [0x48, 0x50], [
    ArithmeticDestReg(1)
])

'''POP r0'''
POP = MachineInsn('POP', [0x48, 0x58], [
    ArithmeticDestReg(1)
])

'''JMP imm_addr'''
JMP_i = MachineInsn('JMP', [0xe9, 0x00, 0x00, 0x00, 0x00], [
    AddressPCRelative(1)
])

'''JMP r0'''
JMP_r = MachineInsn('JMP', [0x40, 0xff, 0xe0], [
    ArithmeticDestReg(2)
])

'''CALLQ imm_addr'''
CALLQ_i = MachineInsn('CALLQ', [0xe8, 0x00, 0x00, 0x00, 0x00], [
    AddressPCRelative(1)
])

'''CALLQ r0'''
CALLQ_r = MachineInsn('CALLQ', [0x40, 0xff, 0xd0], [
    ArithmeticDestReg(2)
])

'''RET'''
RET = MachineInsn('RET', [0xc3], [])

'''SHL r0, imm_u8'''
SHL_ri = MachineInsn('SHL', [0x48, 0xc1, 0xe0, 0], [
    ArithmeticDestReg(2),
    Immediate8U(3)
])

'''SHL r0, rcx'''
SHL_r_rcx = MachineInsn('SHL', [0x48, 0xd3, 0xe0], [
    ArithmeticDestReg(2)
])
