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
import instruction_set as prism_insns

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
rsp : MachineRegister = REG_STRUCT['rsp']
r12 : MachineRegister = REG_STRUCT['r12']
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
def I32S(offset):
    return MachineFormalImmediate(ASM_ARG_IMM32S, MultiByteEncoding.span(offset, 4))
def I8U(offset):
    return MachineFormalImmediate(ASM_ARG_IMM8U, SingleByteEncoding.at(offset, 0, 0, 8))

def PCRel(offset):
    return MachineFormalImmediate(ASM_ARG_PCREL32S, MultiByteEncoding.span(offset, 4))

MISet, MI = MachineInsnSet.make('amd64', globals())

# basic:
MI('MOV.rr',		[ADReg(2), ASReg(2)],		'x: 48 89 c0')
MI('MOV.ri',		[ADReg(1), I64U(2)],		'x: 48 b8 ## ## ## ## ## ## ## ##')
MI('MOV.ri32',		[ADReg(1), I32U(2)],		'x: 40 b8 ## ## ## ##')
MI('XCHG',		[ADReg(2), ASReg(2)],		'x: 48 87 c0')
# store:
MI('MOV.mr8',		[ASReg(2), I32S(3), ADReg(2)],	'x: 40 88 80 ## ## ## ##')
MI('MOV.mr8_sp',	[ASReg(2), I32S(4)],		'x: 40 88 84 24 ## ## ## ##')
MI('MOV.mr8_r12',	[ASReg(2), I32S(4)],		'x: 41 88 84 24 ## ## ## ##')
MI('MOV.mr',		[ASReg(2), I32S(3), ADReg(2)],	'x: 48 89 80 ## ## ## ##')
MI('MOV.mr_sp',		[ASReg(2), I32S(4)],		'x: 48 89 84 24 ## ## ## ##')
MI('MOV.mr_r12',	[ASReg(2), I32S(4)],		'x: 49 89 84 24 ## ## ## ##')
# load:
MI('MOVZBQ.rm8',	[ASReg(3), I32S(4), ADReg(3)],	'x: 48 0f b6 80 ## ## ## ##')
MI('MOVZBQ.rm8_sp',	[ASReg(3), I32S(5)],		'x: 48 0f b6 84 24 ## ## ## ##')
MI('MOVZBQ.rm8_r12',	[ASReg(3), I32S(5)],		'x: 49 0f b6 84 24 ## ## ## ##')
MI('MOV.rm',		[ASReg(2), I32S(3), ADReg(2)],	'x: 48 8b 80 ## ## ## ##')
MI('MOV.rm_sp',		[ASReg(2), I32S(4)],		'x: 48 8b 84 24 ## ## ## ##')
MI('MOV.rm_r12',	[ASReg(2), I32S(4)],		'x: 49 8b 84 24 ## ## ## ##')
# arithmetic:
MI('ADD.rr',		[ADReg(2), ASReg(2)],		'x: 48 01 c0')
MI('ADD.ri',		[ADReg(2), I32U(3)],		'x: 48 81 c0 ## ## ## ##')
MI('SUB.rr',		[ADReg(2), ASReg(2)],		'x: 48 29 c0')
MI('SUB.ri',		[ADReg(2), I32U(3)],		'x: 48 81 e8 ## ## ## ##')
MI('IMUL.rr',		[ASReg(3), ADReg(3)],		'x: 48 0f af c0')
# testing:
MI('TEST.rr',		[ADReg(2), ASReg(2)],		'x: 48 85 c0')
MI('CMP.rr',		[ADReg(2), ASReg(2)],		'x: 48 39 c0')
MI('CMP.ri',		[ADReg(2), I8U(3)],		'x: 48 83 c0 00')
# set conditional:
MI('SETG.r',		[ADReg(3)],			'x: 40 0f 9f c0')
MI('SETGE.r',		[ADReg(3)],			'x: 40 0f 9d c0')
MI('SETL.r',		[ADReg(3)],			'x: 40 0f 9c c0')
MI('SETLE.r',		[ADReg(3)],			'x: 40 0f 9e c0')
MI('SETE.r',		[ADReg(3)],			'x: 40 0f 94 c0')
MI('SETNE.r',		[ADReg(3)],			'x: 40 0f 95 c0')
# bitops:
MI('AND.rr',		[ADReg(2), ASReg(2)],		'x: 48 21 c0')
MI('AND.ri',		[ADReg(2), I32U(3)],		'x: 48 81 e0 ## ## ## ##')
MI('OR.rr',		[ADReg(2), ASReg(2)],		'x: 48 09 c0')
MI('OR.ri',		[ADReg(2), I32U(3)],		'x: 48 81 c8 ## ## ## ##')
MI('XOR.rr',		[ADReg(2), ASReg(2)],		'x: 48 31 c0')
MI('XOR.ri',		[ADReg(2), I32U(3)],		'x: 48 81 f0 ## ## ## ##')
MI('SHL.r',		[ADReg(2)],			'x: 48 d3 e0')
MI('SHL.ri',		[ADReg(2), I8U(3)],		'x: 48 c1 e0 00')
MI('SHR.r',		[ADReg(2)],			'x: 48 d3 e8')
MI('SHR.ri',		[ADReg(2), I8U(3)],		'x: 48 c1 e8 00')
MI('SAR.r',		[ADReg(2)],			'x: 48 d3 f8')
MI('SAR.ri',		[ADReg(2), I8U(3)],		'x: 48 c1 f8 00')
# branching and jumping:
MI('JE.i',		[PCRel(2)],			'x: 0f 84 ## ## ## ##')
MI('JNE.i',		[PCRel(2)],			'x: 0f 85 ## ## ## ##')
MI('JL.i',		[PCRel(2)],			'x: 0f 8c ## ## ## ##')
MI('JGE.i',		[PCRel(2)],			'x: 0f 8d ## ## ## ##')
MI('JLE.i',		[PCRel(2)],			'x: 0f 8e ## ## ## ##')
MI('JG.i',		[PCRel(2)],			'x: 0f 8f ## ## ## ##')
MI('JMP.r',		[ADReg(2)],			'x: 40 ff e0')
MI('JMP.i',		[PCRel(1)],			'x: e9 ## ## ## ##')
# subroutines:
MI('CALLQ.r',		[ADReg(2)],			'x: 40 ff d0')
MI('CALLQ.i',		[PCRel(1)],			'x: e8 ## ## ## ##')
MI('RET',		[],				'x: c3')
# special:
MI('SYSCALL',		[],				'x: 0f 05')
MI('PUSH.ax',		[],				'x: 50')
MI('PUSH',		[ADReg(1)],			'x: 48 50')
MI('POP',		[ADReg(1)],			'x: 48 58')

def implementations(insn, arg):
    R0 = arg.R0
    R1 = arg.R1
    R2 = arg.R2
    I8U = arg.I8U
    I32U = arg.I32U
    I32S = arg.I32S
    I64U = arg.I64U
    PCREL32S = arg.PCREL32S

    # basic ops

    insn.move		(R0, R1		).amd64 =	MOV_rr(R0, R1)
    insn.li		(R0, I64U	).amd64 =	MOV_ri(R0, I64U)

    # arithmetic

    insn.add		(R0, R1		).amd64 =	ADD_rr(R0, R1)
    insn.addi		(R0, I32U	).amd64 =	ADD_ri(R0, I32U)
    insn.sub		(R0, R1		).amd64 =	SUB_rr(R0, R1)
    insn.subi		(R0, I32U	).amd64 =	SUB_ri(R0, I32U)
    insn.mul		(R0, R1		).amd64 =	IMUL_rr(R0, R1)

    # logical not

    insn['not']		(R0, R1		).amd64 =	[ TEST_rr(R1, R1),
                                                          MOV_ri32(R0, MachineLiteral(0)),
                                                          SETE_r(R0) ]

    # bitwise

    for pinsn, amd64_rr, amd64_ri in [('and', AND_rr, AND_ri),
                                      ('or',  OR_rr,  OR_ri),
                                      ('xor', XOR_rr, XOR_ri)]:
        insn[pinsn]    (R0, R1  ).amd64 = amd64_rr(R0, R1)
        insn[pinsn+'i'](R0, I32U).amd64 = amd64_ri(R0, I32U)

    # bit shifting

    for pinsn, amd64_shift_r, amd64_shift_ri in [
            ('sll', SHL_r, SHL_ri),
            ('srl', SHR_r, SHR_ri),
            ('sra', SAR_r, SAR_ri)]:
        insn[f'{pinsn}i'](R0, I8U	).amd64 = ( amd64_shift_ri(R0, I8U) )
        insn[f'{pinsn}'] (R0, R1	).amd64 = (
            Insn.cond( (R1 == rcx)    >> ( amd64_shift_r(R0) ),
                       (R0 == R1)     >> [ XCHG(rcx, R0),
                                           amd64_shift_r(rcx),
                                           XCHG(rcx, R0) ],
                       (R0 == rcx)    >> [ XCHG(rcx, R1),
                                           amd64_shift_r(R1),
                                           XCHG(rcx, R1) ],
                       Insn@'default' >> [ XCHG(rcx, R1),
                                           amd64_shift_r(R0),
                                           XCHG(rcx, R1) ]
                      ))


    # conditional set and branches

    for cmp, amd64_br, amd64_set in [
            ('gt',	JG_i,	SETG_r),
            ('ge',	JGE_i,	SETGE_r),
            ('lt',	JL_i,	SETL_r),
            ('le',	JLE_i,	SETLE_r),
            ('eq',	JE_i,	SETE_r),
            ('ne',	JNE_i,	SETNE_r) ]:
        insn[f's{cmp}']	(R0, R1, R2		).amd64 = [ CMP_rr(R1, R2),
                                                            MOV_ri32(R0, MachineLiteral(0)),
                                                            amd64_set(R0) ]
        insn[f'b{cmp}']	(R0, R1, PCREL32S	).amd64 = [ CMP_rr(R0, R1),
                                                            amd64_br(PCREL32S) ]
        insn[f'b{cmp}z'](R0, PCREL32S		).amd64 = [ CMP_ri(R0, MachineLiteral(0)),
                                                            amd64_br(PCREL32S) ]
    # store and load

    for pinsn, amd64_op, amd64_op_rsp, amd64_op_r12 in [
            ('sb', MOV_mr8,    MOV_mr8_sp,    MOV_mr8_r12),
            ('lb', MOVZBQ_rm8, MOVZBQ_rm8_sp, MOVZBQ_rm8_r12),
            ('sd', MOV_mr,     MOV_mr_sp,     MOV_mr_r12 ),
            ('ld', MOV_rm,     MOV_rm_sp,     MOV_rm_r12 ) ]:
        insn[pinsn]    (R0, I32S, R1).amd64 = Insn.cond(
            (R1 == rsp)		>>  amd64_op_rsp(R0, I32S),
            (R1 == r12)		>>  amd64_op_r12(R0, I32S),
            Insn@'default'	>>  amd64_op(R0, I32S, R1))

    # jumps

    insn.j		(PCREL32S	).amd64	=	JMP_i(PCREL32S)
    insn.jr		(R0		).amd64	=	JMP_r(R0)
    insn.jal		(PCREL32S	).amd64	=	CALLQ_i(PCREL32S)
    insn.jalr		(R0		).amd64	=	CALLQ_r(R0)
    insn.jreturn	(		).amd64	=	RET()

    # syscall

    insn.syscall	(		).amd64	=	SYSCALL()

    # push and pop

    insn.push		(R0		).amd64 =	PUSH(R0)
    insn.pop		(R0		).amd64 =	POP(R0)

MISet.implement(prism_insns.InsnBuilder, implementations)
