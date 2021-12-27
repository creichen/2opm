#! /usr/bin/env python3
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

import unittest
from gen_assembly import *

class TestMachine:
    def __init__(self):
        rs = make_registers([
            ('mr0', '$v0'),
            ('mr1', '$a0'),
            ('mr2', '$s0'),
            ('mr3', '$gp'),
        ])
        self.REGISTERS = rs['REGISTERS']
        self.REGISTER_MAP = rs['REGISTER_MAP']
        self.mr0 = rs['mr0']
        self.mr1 = rs['mr1']
        self.mr2 = rs['mr2']
        self.mr3 = rs['mr3']
        (MISet, MI) = MachineInsnFactory('testarch')
        self.MISet = MISet
        # Fake architecture:
        #  0x81 xx xx xx xx
        #    load: mr0 := uint32(xx xx xx xx)
        #  0x8X: where:
        #    X=  reg
        #     1  mr0
        #     3  mr1
        #     5  mr2
        #     7  mr3
        self.m_li = MI('m-li', [0x81, 0x00, 0x00, 0x00, 0x00], [
            MachineFormalRegister(SingleByteEncoding.at(0, 1, 0, 2)),
            # FIXME: Use byte span encoding
            MachineFormalImmediate(ASM_ARG_IMM32U, MultiByteEncoding.span(1, 4))
        ])
        # three-argument op
        #  0xf1 0x11:
        #    add: mr0 := mr0 + mr0
        #  0x_X 0xYZ
        #    add: mrX := mrY + mrZ
        # where X,Y,Z are encoded as in 'm_li'
        self.m_add = MI('m-add', [0xf1, 0x11], [
            MachineFormalRegister(SingleByteEncoding.at(0, 1, 0, 2)),
            MachineFormalRegister(SingleByteEncoding.at(1, 1, 0, 2)),
            MachineFormalRegister(SingleByteEncoding.at(1, 5, 0, 2))
        ])

class TestInsns:
    def __init__(self):
        self.machine = TestMachine()
        self.li32u = Insn('li32u', '$r0 := %v',
                          [R(0), I32U],
                          self.machine.m_li(R(0), I32U))
        # load the number 1000
        self.thousand = Insn('thousand', '$r0 := 1000',
                             [R(0)],
                             self.machine.m_li(R(0), MachineLiteral(1000)))
        # load something into mr1
        self.la0 = Insn('la0', '$a0 := %v',
                        [I32U],
                        self.machine.m_li(self.machine.REGISTER_MAP['$a0'], I32U))

        self.add = Insn('add', ArithmeticEffect('+'),
                        [R(0), R(1)],
                        self.machine.m_add(R(0), R(0), R(1)))


def with_prln(closure):
    buf = []
    def prln(s):
        buf.append(s + '\n')
    closure(prln)
    return ''.join(buf)

class TestGenAssembly(unittest.TestCase):

    def test_range_check(self):
        self.assertTrue(ASM_ARG_IMM64S.supports_argument(PMImmediate(0, 32, True)))
        self.assertTrue(ASM_ARG_IMM64S.supports_argument(PMImmediate(0, 32, False)))

        self.assertTrue(ASM_ARG_IMM32U.supports_argument(PMImmediate(0, 8, False)))
        self.assertTrue(ASM_ARG_IMM32U.supports_argument(PMImmediate(0, 32, False)))
        self.assertFalse(ASM_ARG_IMM32U.supports_argument(PMImmediate(0, 32, True)))

        self.assertTrue(ASM_ARG_IMM32S.supports_argument(PMImmediate(0, 32, True)))
        self.assertFalse(ASM_ARG_IMM32S.supports_argument(PMImmediate(0, 32, False)))
        self.assertFalse(ASM_ARG_IMM32S.supports_argument(PMImmediate(0, 64, False)))
        self.assertFalse(ASM_ARG_IMM32S.supports_argument(PMImmediate(0, 64, False)))

    def test_simple_bit_pattern(self):
        bp = SingleByteEncoding.at(1, 2, 0, 3)

        self.assertEqual(0x1c, bp.pattern.mask_in)
        self.assertEqual(0xff ^ 0x1c, bp.pattern.mask_out)

        b = [0xff, 0xff, 0xff]
        bp.apply_to(b, 0)
        self.assertEqual([0xff, 0xe3, 0xff], b)
        self.assertEqual(0x00, eval(bp.pattern.gen_encoding('v'), {'v' : 0}))
        self.assertEqual(0x00, eval(bp.pattern.gen_decoding('v'), {'v' : b[1]}))

        self.assertEqual(None, bp.gen_encoding_at('v', 0))
        self.assertEqual(0x00, eval(bp.gen_encoding_at('v', 1), {'v' : 0}))
        self.assertEqual(None, bp.gen_encoding_at('v', 2))
        self.assertEqual(0x00, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

        bp.apply_to(b, 255)
        self.assertEqual([0xff, 0xff, 0xff], b)
        self.assertEqual(0x1c, eval(bp.pattern.gen_encoding('v'), {'v' : 255}))
        self.assertEqual(0x07, eval(bp.pattern.gen_decoding('v'), {'v' : b[1]}))

        self.assertEqual(0x1c, eval(bp.gen_encoding_at('v', 1), {'v' : 255}))
        self.assertEqual(0x07, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

        bp.apply_to(b, 1)
        self.assertEqual([0xff, 0xe7, 0xff], b)
        self.assertEqual(0x04, eval(bp.pattern.gen_encoding('v'), {'v' : 1}))
        self.assertEqual(0x01, eval(bp.pattern.gen_decoding('v'), {'v' : b[1]}))

        self.assertEqual(0x04, eval(bp.gen_encoding_at('v', 1), {'v' : 1}))
        self.assertEqual(0x01, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

    def test_joint_bit_pattern(self):
        bp = MultiByteEncoding.at((1, 2, 3), (0, 4, 3))

        b = [0xff, 0xff, 0xff]
        bp.apply_to(b, 0)
        self.assertEqual([0x8f, 0xe3, 0xff], b)
        self.assertEqual(0x00, eval(bp.gen_encoding_at('v', 0), {'v' : 0}))
        self.assertEqual(0x00, eval(bp.gen_encoding_at('v', 1), {'v' : 0}))
        self.assertEqual(0x00, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

        bp.apply_to(b, 255)
        self.assertEqual([0xff, 0xff, 0xff], b)
        self.assertEqual(0x70, eval(bp.gen_encoding_at('v', 0), {'v' : 255}))
        self.assertEqual(0x1c, eval(bp.gen_encoding_at('v', 1), {'v' : 255}))
        self.assertEqual(0x3f, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

        bp.apply_to(b, 1)
        self.assertEqual([0x8f, 0xe7, 0xff], b)
        self.assertEqual(0x00, eval(bp.gen_encoding_at('v', 0), {'v' : 1}))
        self.assertEqual(0x04, eval(bp.gen_encoding_at('v', 1), {'v' : 1}))
        self.assertEqual(0x01, eval(bp.gen_decoding(lambda i: 'v[%d]' % i), {'v' : b}))

    def test_insn_encoder_headers(self):
        insns = TestInsns()
        expectations = [
            (insns.li32u,    'void\nemit_li32u(buffer_t *buf, int r, unsigned int imm);\n'),
            (insns.thousand, 'void\nemit_thousand(buffer_t *buf, int r);\n'),
            (insns.la0,      'void\nemit_la0(buffer_t *buf, unsigned int imm);\n'),
            (insns.add,      'void\nemit_add(buffer_t *buf, int r1, int r2);\n'),
        ]
        self.maxDiff = None
        for insn, expected in expectations:
            self.assertEqual(expected, with_prln(lambda prln: insn.print_encoder_header(prln=prln)))

    def test_insn_encoders(self):
        insns = TestInsns()
        expectations = [
            (insns.li32u,    '''void
emit_li32u(buffer_t *buf, int r, unsigned int imm)
{
	const int machine_code_len = 5;
	unsigned char *data = buffer_alloc(buf, machine_code_len);
	data[0] = 0x81 | ((r << 1) & 0x06);
	data[1] = 0x00 | (imm & 0xff);
	data[2] = 0x00 | ((imm >> 8) & 0xff);
	data[3] = 0x00 | ((imm >> 16) & 0xff);
	data[4] = 0x00 | ((imm >> 24) & 0xff);
}
'''),
            (insns.thousand, '''void
emit_thousand(buffer_t *buf, int r)
{
	const int machine_code_len = 5;
	unsigned char *data = buffer_alloc(buf, machine_code_len);
	data[0] = 0x81 | ((r << 1) & 0x06);
	data[1] = 0xe8;
	data[2] = 0x03;
	data[3] = 0x00;
	data[4] = 0x00;
}
'''),
            (insns.la0,      '''void
emit_la0(buffer_t *buf, unsigned int imm)
{
	const int machine_code_len = 5;
	unsigned char *data = buffer_alloc(buf, machine_code_len);
	data[0] = 0x83;
	data[1] = 0x00 | (imm & 0xff);
	data[2] = 0x00 | ((imm >> 8) & 0xff);
	data[3] = 0x00 | ((imm >> 16) & 0xff);
	data[4] = 0x00 | ((imm >> 24) & 0xff);
}
'''),
            (insns.add,      '''void
emit_add(buffer_t *buf, int r1, int r2)
{
	const int machine_code_len = 2;
	unsigned char *data = buffer_alloc(buf, machine_code_len);
	data[0] = 0xf1 | ((r1 << 1) & 0x06);
	data[1] = 0x11 | ((r1 << 1) & 0x06) | ((r2 << 5) & 0x60);
}
'''),
        ]
        self.maxDiff = None
        for insn, expected in expectations:
            actual = with_prln(lambda prln: insn.print_encoder(prln=prln))
            if (expected != actual):
                print('[%s] expected:' % insn)
                print(expected)
                print('[%s] actual:' % insn)
                print(actual)
            self.assertEqual(expected, actual)


#     def test_machine_insn_decoders(self):
#         insns = TestInsns()
#         expectations = [
#             (insns.li32u,    '''	if (max_len >= 5 && (data[0] & 0xf9) == 0x81) {
# 		const int machine_code_len = 5;
#       .....
# 		if (file) {
# 			int r = ((data[0] & 0x06) >> 1);
# 			int imm = (data[1]) | (data[2] << 8) | (data[2] << 16) | (data[2] << 24);
# 			fprintf(file, "li32u\t%s, %x", register_names[r].mips, imm);
# 		}
# 		return machine_code_len;
# 	}
# '''),
#             (insns.thousand, '''void
# emit_thousand(buffer_t *buf, int r)
# {
# 	const int machine_code_len = 5;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0x81 | ((r << 1) & 0x06);
# 	data[1] = 0xe8;
# 	data[2] = 0x03;
# 	data[3] = 0x00;
# 	data[4] = 0x00;
# }
# '''),
#             (insns.la0,      '''void
# emit_la0(buffer_t *buf, unsigned int imm)
# {
# 	const int machine_code_len = 5;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0x83;
# 	data[1] = 0x00 | (imm & 0xff);
# 	data[2] = 0x00 | ((imm >> 8) & 0xff);
# 	data[3] = 0x00 | ((imm >> 16) & 0xff);
# 	data[4] = 0x00 | ((imm >> 24) & 0xff);
# }
# '''),
#             (insns.add,      '''void
# emit_add(buffer_t *buf, int r1, int r2)
# {
# 	const int machine_code_len = 2;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0xf1 | ((r1 << 1) & 0x06);
# 	data[1] = 0x11 | ((r1 << 1) & 0x06) | ((r2 << 5) & 0x60);
# }
# '''),
#         ]
#         self.maxDiff = None
#         for insn, expected in expectations:
#             actual = with_prln(lambda prln: insn.print_decoder('data', 'max_len', prln=prln))
#             if (expected != actual):
#                 print('[%s] expected:' % insn)
#                 print(expected)
#                 print('[%s] actual:' % insn)
#                 print(actual)
#             self.assertEqual(expected, actual)


#     def test_insn_decoders(self):
#         insns = TestInsns()
#         expectations = [
#             (insns.li32u,    '''	if (max_len >= 5 && (data[0] & 0xf9) == 0x81) {
# 		const int machine_code_len = 5;
#       .....
# 		if (file) {
# 			int r = ((data[0] & 0x06) >> 1);
# 			int imm = (data[1]) | (data[2] << 8) | (data[2] << 16) | (data[2] << 24);
# 			fprintf(file, "li32u\t%s, %x", register_names[r].mips, imm);
# 		}
# 		return machine_code_len;
# 	}
# '''),
#             (insns.thousand, '''void
# emit_thousand(buffer_t *buf, int r)
# {
# 	const int machine_code_len = 5;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0x81 | ((r << 1) & 0x06);
# 	data[1] = 0xe8;
# 	data[2] = 0x03;
# 	data[3] = 0x00;
# 	data[4] = 0x00;
# }
# '''),
#             (insns.la0,      '''void
# emit_la0(buffer_t *buf, unsigned int imm)
# {
# 	const int machine_code_len = 5;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0x83;
# 	data[1] = 0x00 | (imm & 0xff);
# 	data[2] = 0x00 | ((imm >> 8) & 0xff);
# 	data[3] = 0x00 | ((imm >> 16) & 0xff);
# 	data[4] = 0x00 | ((imm >> 24) & 0xff);
# }
# '''),
#             (insns.add,      '''void
# emit_add(buffer_t *buf, int r1, int r2)
# {
# 	const int machine_code_len = 2;
# 	unsigned char *data = buffer_alloc(buf, machine_code_len);
# 	data[0] = 0xf1 | ((r1 << 1) & 0x06);
# 	data[1] = 0x11 | ((r1 << 1) & 0x06) | ((r2 << 5) & 0x60);
# }
# '''),
#         ]
#         self.maxDiff = None
#         for insn, expected in expectations:
#             actual = with_prln(lambda prln: insn.print_decoder('data', 'max_len', prln=prln))
#             if (expected != actual):
#                 print('[%s] expected:' % insn)
#                 print(expected)
#                 print('[%s] actual:' % insn)
#                 print(actual)
#             self.assertEqual(expected, actual)



if __name__ == '__main__':
    unittest.main()
