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

def ADReg(offset): # Arithmetic dest
    return MachineFormalRegister(MultiByteEncoding.at((offset, 0, 3), (0, 0, 1)))
def ASReg(offset): # Arithmetic src
    return MachineFormalRegister(MultiByteEncoding.at((offset, 3, 3), (0, 2, 1)))
def I64U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM64U, MultiByteEncoding.span(offset, 8))
def I32U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM32U, MultiByteEncoding.span(offset, 4))
def I8U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM8U, SingleByteEncoding.at(offset, 0, 0, 8))

def PCRel(offset):
    return MachineFormalImmediate(ASM_ARG_PCREL32S, MultiByteEncoding.span(offset, 4))

MISet, MI = MachineInsnFactory('amd64', globals())

MI('MOV.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x89, 0xc0])
MI('MOV.ri',	[ADReg(1), I64U(2)],	[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0])
MI('ADD.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x01, 0xc0])
MI('ADD.ri',	[ADReg(2), I32U(3)],	[0x48, 0x81, 0xc0, 0, 0, 0, 0])
MI('SUB.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x29, 0xc0])
MI('SUB.ri',	[ADReg(2), I32U(3)],	[0x48, 0x81, 0xe8, 0, 0, 0, 0])
MI('IMUL.rr',	[ASReg(3), ADReg(3)],	[0x48, 0x0f, 0xaf, 0xc0])
MI('XCHG',	[ADReg(2), ASReg(2)],	[0x48, 0x87, 0xc0])
MI('AND.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x21, 0xc0])
MI('AND.ri',	[ADReg(2), I32U(3)],	[0x48, 0x81, 0xe0, 0, 0, 0, 0])

MI('OR.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x09, 0xc0])
MI('OR.ri',	[ADReg(2), I32U(3)],	[0x48, 0x81, 0xc8, 0, 0, 0, 0])

MI('XOR.rr',	[ADReg(2), ASReg(2)],	[0x48, 0x31, 0xc0])
MI('XOR.ri',	[ADReg(2), I32U(3)],	[0x48, 0x81, 0xf0, 0, 0, 0, 0])

MI('SHL.r',	[ADReg(2)],		[0x48, 0xd3, 0xe0])
MI('SHL.ri',	[ADReg(2), I8U(3)],	[0x48, 0xc1, 0xe0, 0])
MI('SHR.r',	[ADReg(2)],		[0x48, 0xd3, 0xe8])
MI('SHR.ri',	[ADReg(2), I8U(3)],	[0x48, 0xc1, 0xe8, 0])
MI('SAR.r',	[ADReg(2)],		[0x48, 0xd3, 0xf8])
MI('SAR.ri',	[ADReg(2), I8U(3)],	[0x48, 0xc1, 0xf8, 0])
MI('JMP.r',	[ADReg(2)],		[0x40, 0xff, 0xe0])
MI('JMP.i',	[PCRel(1)],		[0xe9, 0x00, 0x00, 0x00, 0x00])
MI('CALLQ.r',	[ADReg(2)],		[0x40, 0xff, 0xd0])
MI('CALLQ.i',	[PCRel(1)],		[0xe8, 0x00, 0x00, 0x00, 0x00])
MI('RET',	[],			[0xc3])
MI('PUSH',	[ADReg(1)],		[0x48, 0x50])
MI('POP',	[ADReg(1)],		[0x48, 0x58])
