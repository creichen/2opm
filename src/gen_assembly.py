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

'''
General-purpose assembly code management (intended to be cross-platform).

- Machine*: native (amd64 etc.) machine instructions
  - Encoded instructions: ready to execute
  - Decoded instructions: disassembled at the machine level
- PM*: 2OPM instructions
'''

# prefix for the generated C code functions
LIB_PREFIX = ''


class BitEncoding:
    '''
    Represents, for a single byte, the mapping between encoded and decoded instructions.

    encoded_bitpos: bit offset into the encoded byte (lsb = 0)
    decoded_bitpos: bit offset into the decided number (lsb = 0)
    bits_nr: number of bits to encode starting at bitid (inclusive)
    '''
    def __init__(self, encoded_bitpos, decoded_bitpos, bits_nr):
        self.encoded_bitpos = encoded_bitpos
        self.decoded_bitpos = decoded_bitpos
        self.bits_nr = bits_nr

    def gen_encoding(self, varname):
        '''
        Generates C code for extracting relevant bits from `varname', starting at its `bitoffset'
        '''
        total_rightshift = self.decoded_bitpos - self.encoded_bitpos
        body = BitEncoding.gen_shr(varname, total_rightshift)

        return '%s & 0x%02x' % (body, self.mask_in)

    @property
    def mask_in(self):
        '''
        Encoded byte: mask for the bits included in this bit pattern
        '''
        mask = 0
        for i in range(0, self.bits_nr):
            mask = ((mask << 1) | 1)

        mask = mask << self.encoded_bitpos
        return mask

    @property
    def mask_out(self):
        return 0xff ^ self.mask_in

    @staticmethod
    def gen_shr(body, total_rightshift):
        if total_rightshift > 0:
            body = '(' + body + ' >> ' + str(total_rightshift) + ')'
        elif total_rightshift < 0:
            body = '(' + body + ' << ' + str(-total_rightshift) + ')'
        return body

    def gen_decoding(self, byte):
        '''C code for decoding the bit pattern from a given byte'''
        return BitEncoding.gen_shr('(%s & 0x%02x)' % (byte, self.mask_in), self.encoded_bitpos - self.decoded_bitpos)



class ByteEncoding:
    '''Common supertype for Single and MultiByteEncoding'''
    def __init__(self):
        pass


class SingleByteEncoding(ByteEncoding):
    '''
    SingleByteEncoding: BitEncoding plus byte position and bit shift.
    '''

    def __init__(self, byte_offset, bit_pattern : BitEncoding):
        '''
        byte_offset: which byte the BitEncoding is valid for
        '''
        ByteEncoding.__init__(self)

        self.byte_pos = byte_offset
        self.pattern = bit_pattern

    def apply_to(self, bytelist, number):
        '''
        Update the bytelist to overwrite it with the specified number, encoded into the bit pattern
        '''
        bytelist[self.byte_pos] = ((bytelist[self.byte_pos] & self.pattern.mask_out)
                                      | (self.pattern.mask_in & ((number >> self.pattern.decoded_bitpos) << self.pattern.encoded_bitpos)))

    @property
    def bits_nr(self):
        return self.pattern.bits_nr

    @property
    def encode_pos(self):
        return self.pattern.encode_pos

    @property
    def decode_pos(self):
        return self.pattern.encode_pos

    @property
    def mask_in(self):
        return self.pattern.mask_in

    @property
    def mask_out(self):
        return self.pattern.mask_out

    @staticmethod
    def at(byte_offset, encoded_bitpos, decoded_bitpos, bits_nr):
        return SingleByteEncoding(byte_offset, BitEncoding(encoded_bitpos, decoded_bitpos, bits_nr))

    def gen_encoding_at(self, src, offset):
        '''
        Returns part of the encoding code for the value "src", for output byte at "offset".

        If the current ByteEncoding does not contribute to that byte, return None.
        '''
        return None if offset != self.byte_pos else self.pattern.gen_encoding(src)

    def gen_decoding(self, access):
        '''
        Returns decoding code for this byte pattern.

        @param access A function that maps a byte offset (int) to a string
               that represents that byte in the generated code.

        If the current ByteEncoding does not contribute to that byte, return None.
        '''
        return self.pattern.gen_decoding(access(self.byte_pos))


class MultiByteEncoding(ByteEncoding):
    '''
    Combination of multiple SingleByteEncoding objects that together encode a number across multiple patterns (specified in order)
    '''
    def __init__(self, *patterns):
        ByteEncoding.__init__(self)
        self.bit_patterns = list(patterns)
        self.bit_patterns.reverse()
        # self.atbit = dict()

        bitoffset = 0
        for bp in self.bit_patterns:
            assert isinstance(bp, SingleByteEncoding)
            assert not isinstance(bp, MultiByteEncoding)

            # if bp.byte_pos in self.atbit:
            #     self.atbit[bp.byte_pos].append((bp, bitoffset))
            # else:
            #     self.atbit[bp.byte_pos] = [(bp, bitoffset)]
            # bitoffset += bp.bits_nr

    def str_extract(self, varname, bitoffset):
        offset = 0
        for pat in self.bit_patterns:
            pat.str_extract(varname, offset)
            offset += pat.bits_nr

    def apply_to(self, bytelist, number):
        for pat in self.bit_patterns:
            pat.apply_to(bytelist, number)

    def gen_encoding_at(self, src, offset):
        results = []
        for p in self.bit_patterns:
            r = p.gen_encoding_at(src, offset)
            if r != None:
                results.append(r)
        if results == []:
            return None
        return ' | '.join(results)

    def gen_decoding(self, access):
        results = []
        bitoffset = 0
        for bp in self.bit_patterns:
            results.append(bp.gen_decoding(access))
            bitoffset += bp.bits_nr
        return ' | '.join(results)

    @staticmethod
    def at(*offsets):
        '''
        offsets: list[tuple(byte_offset, enc_bitpos, bits_nr)]
        '''
        patterns = []
        decode_bitpos = 0
        for byte_offset, enc_bitpos, bits_nr in offsets:
            patterns.append(SingleByteEncoding.at(byte_offset, enc_bitpos, decode_bitpos, bits_nr))
            decode_bitpos += bits_nr
        return MultiByteEncoding(*patterns)

# ================================================================================
# Argument types

class MachineArgType:
    def __init__(self, test_category : str, name_hint : str, asm_arg_type : str, gen_c_type : str):
        self._test_category = test_category
        self._name_hint = name_hint
        self._asm_arg_type = 'ASM_ARG_' + asm_arg_type
        self._gen_c_type = gen_c_type

    @property
    def hint(self):
        return self._name_hint

    @property
    def asm_arg(self):
        return self._asm_arg_type

    @property
    def c_type(self):
        return self._gen_c_type

    @property
    def test_category(self):
        '''
        returns "r" (register), "i" (immediate) or "a" (address), used for testing
        '''
        return self._test_category

    def supports_argument(self, arg):
        return False

    def __str__(self):
        return self.asm_arg


class MachineArgTypeReg(MachineArgType):
    def __init__(self):
        MachineArgType.__init__(self, 'r', 'r', 'REG', 'int')

    def supports_argument(self, arg):
        return type(arg.mtype) is MachineArgTypeReg


class MachineArgTypeLiteral(MachineArgType):
    def __init__(self, bits, signed, ctype):
        MachineArgType.__init__(self, 'i', 'imm', 'IMM%d%s' % (bits, 'S' if signed else 'U'), ctype)
        range = (1 << bits)
        if signed:
            self.value_min = - (range >> 1)
            self.value_max = (range >> 1) - 1
        else:
            self.value_min = 0
            self.value_max = range - 1

    def supports_argument(self, arg):
        if arg.is_abstract:
            return type(arg.mtype) is MachineArgTypeLiteral
        if arg.mtype is not None and (not isinstance(arg.mtype, MachineArgTypeLiteral) and not isinstance(arg.mtype, PMLiteral)):
            print(arg.mtype)
            return False
        return arg.value >= self.value_min and arg.value <= self.value_max


ASM_ARG_REG = MachineArgTypeReg()
ASM_ARG_IMM8U = MachineArgTypeLiteral(8, False,   'unsigned char')
ASM_ARG_IMM32U = MachineArgTypeLiteral(32, False, 'unsigned int')
ASM_ARG_IMM32S = MachineArgTypeLiteral(32, True,  'signed int')
ASM_ARG_IMM64U = MachineArgTypeLiteral(64, False, 'unsigned long long')
ASM_ARG_IMM64S = MachineArgTypeLiteral(64, True,  'signed long long')

# ================================================================================
# Parameters

class MachineActualArg:
    '''Actual parameter to a native instruction.  Can be a formal 2OPM argument or a hardwired value.'''

    def __init__(self, abstract : bool, mtype):
        self._is_abstract = abstract
        self._type = mtype

    @property
    def is_abstract(self):
        return self._is_abstract

    @property
    def mtype(self):
        return self._type


class MachineLiteral(MachineActualArg):
    '''Literal number parameter, for MachineImmediate formals'''
    def __init__(self, number : int, mtype = None):
        MachineActualArg.__init__(self, abstract = (number == None), mtype = mtype)
        self.value = number

    def __str__(self):
        return 'literal(%d)' % (self.value)


class MachineRegister(MachineActualArg):
    '''Literal register number, for MachineFormalRegister formals'''
    def __init__(self, name : str, name2opm : str, num : int):
        MachineActualArg.__init__(self, abstract = False, mtype = ASM_ARG_REG)
        self.num = num
        self.name = name
        self.name2opm = name2opm

    def __str__(self):
        return '%s[%d]' % (self.name, self.num)

# Also see PMRegister and PMLiteral

class MachineFormalArg:
    '''
    Represents a formal parameter to a machine instruction, including C code generation
    and testing, if any.
    '''

    def __init__(self, arg_type : MachineArgType):
        self._arg_type = arg_type

    @property
    def mtype(self):
        '''
        Returns the permitted argument type
        '''
        return self._arg_type

    def supports_argument(self, actual, message):
        if not self.mtype.supports_argument(actual):
            raise Exception('Type error: Parameter %s unsuitable for formal %s in %s' % (self, actual, message))

    def try_inline(self, machine_code : list[int], actual : MachineActualArg):
        '''
        Attempts to inline the actual parameter into the machine code.
        Returns True on success.
        '''
        return False

    def __str__(self):
        return '#:%s' % self.mtype

    # def getExclusiveRegion(self):
    #     '''
    #     Determines whether the argument fully determines the contents of a particular sequence of bytes in this instruction.

    #     @return None or (min_inclusive, max_inclusive)
    #     '''
    #     return None

    # def inExclusiveRegion(self, offset):
    #     exreg = self.getExclusiveRegion()
    #     if exreg is not None:
    #         (min_v, max_v) = exreg
    #         return offset >= min_v and offset <= max_v

    # def maskOut(self, offset):
    #     if self.inExclusiveRegion(offset):
    #         return 0x00
    #     return 0xff

    # def getBuilderFor(self, offset):
    #     return None

    # def printCopyToExclusiveRegion(self, dataptr):
    #     pass

    # def printDisassemble(self, dataptr, offset_shift, p):
    #     '''
    #     prints C code to diassemble this particular argument

    #     @param p: print function
    #     @param offset_shift: Tatsaechliche Position ist offset_shift + eigenes-offset; negative Positionen sind ungueltig
    #     @return a tuple ([printf format strings], [args to format strings])
    #     '''
    #     return ([], [])

    # def isDisabled(self):
    #     return False

    # def genLatex(self, m):
    #     '''
    #     Generates LaTeX description.  Updates map `m' if needed.  In m:
    #     'r' keeps the register count (0 initially)
    #     'v' stores the desired representation for the immediate arg
    #     '''
    #     pass

    # def getType(self):
    #     '''Returns the type (ASM_ARG_*) for reflection purposes'''
    #     pass

    # def supports_argument(self, arg):
    #     '''Confirms that the specified arg is of a valid type'''
    #     raise Exception('Abstract "supports_argument" operation won\'t accept any arguments')


class MachineFormalImmediate(MachineFormalArg):
    MAPPING = {
        (8, 'u'): ASM_ARG_IMM8U,
        (32, 'u'): ASM_ARG_IMM32U,
        (32, 's'): ASM_ARG_IMM32S,
        (64, 'u'): ASM_ARG_IMM64U,
        (64, 's'): ASM_ARG_IMM64S,
    }
    '''
    Represents an immediate value as parameter.

    name_lookup: should this number be looked up in the address store when debugging, to check for special meanings?
    '''
    def __init__(self, arg_type, pattern, name_lookup=True, format_prefix=''):
        MachineFormalArg.__init__(self, arg_type)
        self.pattern = pattern
        self.name_lookup = name_lookup
        self.format_prefix = format_prefix

    def try_inline(self, machine_code, arg):
        if arg.is_abstract:
            return False
        self.pattern.apply_to(machine_code, arg.value)
        return True

    # def getExclusiveRegion(self):
    #     return (self.bytenr, self.bytenr + self.bytelen - 1)

    # def printCopyToExclusiveRegion(self, p, dataptr):
    #     p('memcpy(%s + %d, &%s, %d);' % (dataptr, self.bytenr, self.strName(), self.bytelen))

    # def printDisassemble(self, dataptr, offset_shift, p):
    #     if (self.bytenr + offset_shift < 0):
    #         return
    #     p('%s %s;' % (self.ctype, self.strName()))
    #     p('memcpy(&%s, %s + %d, %d);' % (self.strName(), dataptr, self.bytenr + offset_shift, self.bytelen))
    #     maxsize = 128
    #     p('char %s_buf[%d];' % (self.strName(), maxsize))
    #     if (self.name_lookup):
    #         p('if (debug_address_lookup((void *) %s, &addr_prefix)) {' % self.strName())
    #         p('\tsnprintf(%s_buf, %d, "%s%%-10%s\t; %%s%%s", %s, addr_prefix, debug_address_lookup((void *) %s, NULL));' % (
    #             self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName(), self.strName()))
    #         p('} else {')
    #         p('\tsnprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
    #         p('}')
    #     else:
    #         p('snprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
    #     return (['%s'], ['%s_buf' % self.strName()])

    # def genLatex(self, m):
    #     name = self.docname + str(self.bytelen * 8)
    #     assert 'v' not in m
    #     m['v'] = name
    #     return name


class MachineFormalRegister(MachineFormalArg):
    '''
    Represents a register parameter to an Insn and describes how the register number is encoded.
    '''
    def __init__(self, pattern):
        MachineFormalArg.__init__(self, ASM_ARG_REG)
        assert isinstance(pattern, ByteEncoding)
        self.byte_pattern = pattern

    def try_inline(self, machine_code, arg):
        if arg.is_abstract:
            return False
        self.byte_pattern.apply_to(machine_code, arg.num)
        return True

#     def getBuilderFor(self, offset):
#         if offset in self.atbit:
#             pats = self.atbit[offset]
#             results = []
#             name = self.strName()
#             for (pat, bitoffset) in pats:
#                 results.append(pat.strExtract(name, bitoffset))
#             return ' | '.join(results)
#         return None

#     def printDisassemble(self, dataptr, offset_shift, p):
#         decoding = []
#         bitoffset = 0
#         for pat in self.bit_patterns:
#             offset = pat.byte_pos + offset_shift
#             if (offset >= 0):
#                 decoding.append('(' + pat.str_decode(dataptr + '[' + str(offset) + ']') + ('<< %d)' % bitoffset))
#             bitoffset += pat.bits_nr
#         p('int %s = %s;' % (self.strName(), ' | ' .join(decoding)))
#         return (['%s'], ['register_names[' + self.strName() + '].mips'])

#     def genLatex(self, m):
#         n = m['r']
#         m['r'] = n + 1
#         return make_anonymous_regnames_subscript('$r' + str(n)) # '\\texttt{\\$r' + str(n) + '}'


# ================================================================================
# Machine assembly

class MachineAssembly:
    '''Sequence of machine instructions for a specific architecture, possibly parameterised'''
    def __init__(self):
        pass

    @property
    def arch(self):
        raise Exception('Abstract')

    def generate(self):
        raise Exception('Abstract')

    def __add__(self, rhs):
        return MachineAssemblySeq(self, rhs)

    def __radd__(self, rhs):
        return MachineAssemblySeq(self, rhs)


class MachineInsn(MachineAssembly):
    '''A single native machine instruction'''
    def __init__(self, architecture : str, name : str, machine_code : list[int], formals : list[MachineFormalArg], actuals : list[MachineActualArg]):
        MachineAssembly.__init__(self)
        machine_code = list(machine_code) # duplicate so we can overwrite below
        self.architecture = architecture
        self.name = name
        self.formals = formals
        self.actuals = actuals
        assert len(formals) == len(actuals)
        self.pm_formals = []

        for formal, actual in zip(formals, actuals):
            formal.supports_argument(actual, self)
            if not formal.try_inline(machine_code, actual):
                self.pm_formals.append((actual, formal))

        self.machine_code = machine_code

    @property
    def arch(self):
        return self.architecture

    @property
    def parameters(self):
        '''Order by actuals'''
        return [actual.for_formals(self.formals) for actual in self.actuals]

    def generate(self):
        raise Exception("FIXME: use self.unfilled_arguments instead of parameters, somehow")
        return (self.machine_code, self.parameters)

    def __str__(self):
        return '%s[%s/%s]' % (self.name,
                              ', '.join(str(f) for f in self.formals),
                              ', '.join(str(a) for a in self.actuals))


class MachineAssemblySeq(MachineAssembly):
    '''Sequence of machine instructions for a specific architecture'''
    def __init__(self, asms):
        MachineAssembly.__init__(self)
        seq = []
        arch = asms[0].arch

        for asm in asms:
            if type(asm) is MachineAssemblySeq:
                seq += asm.seq
            else:
                assert asm.arch == arch
                seq.append(asm)

        self.seq = seq
        self.architecture = arch

    @property
    def arch(self):
        return self.architecture

    def generate(self):
        offset = 0
        machine_code = []
        parameters = []

        for asm in self.seq:
            asm_machine_code, asm_regs = asm.generate()
            machine_code += asm_machine_code
            # while len(parameters) < len(asm_regs):
            #     parameters.append([])
            raise "not implemented yet"
            # for parameter in parameters:
            #     parameters
            # for p in parameters:
            # offset += len(asm_machine_code)

    def __str__(self):
        return '<%s>' % ('+'.join(str(s) for s in self.seq))

# class Arg:
#     '''
#     Represents a formal parameter to a machine instruction.
#     '''

#     def setName(self, name):
#         self.name = name

#     def strName(self):
#         return self.name

#     def strGenericName(self):
#         '''
#         Returns a string that gives human readers a hint towards the type of the parameter
#         '''
#         return None

#     def getExclusiveRegion(self):
#         '''
#         Determines whether the argument fully determines the contents of a particular sequence of bytes in this instruction.

#         @return None or (min_inclusive, max_inclusive)
#         '''
#         return None

#     def inExclusiveRegion(self, offset):
#         exreg = self.getExclusiveRegion()
#         if exreg is not None:
#             (min_v, max_v) = exreg
#             return offset >= min_v and offset <= max_v

#     def maskOut(self, offset):
#         if self.inExclusiveRegion(offset):
#             return 0x00
#         return 0xff

#     def getBuilderFor(self, offset):
#         return None

#     def getKind(self):
#         '''returns "r" (register), "i" (immediate) or "a" (address), used for testing '''
#         raise Exception()

#     def printCopyToExclusiveRegion(self, dataptr):
#         pass

#     def printDisassemble(self, dataptr, offset_shift, p):
#         '''
#         prints C code to diassemble this particular argument

#         @param p: print function
#         @param offset_shift: Tatsaechliche Position ist offset_shift + eigenes-offset; negative Positionen sind ungueltig
#         @return a tuple ([printf format strings], [args to format strings])
#         '''
#         return ([], [])

#     def isDisabled(self):
#         return False

#     def genLatex(self, m):
#         '''
#         Generates LaTeX description.  Updates map `m' if needed.  In m:
#         'r' keeps the register count (0 initially)
#         'v' stores the desired representation for the immediate arg
#         '''
#         pass

#     def getType(self):
#         '''Returns the type (ASM_ARG_*) for reflection purposes'''
#         pass

#     def supports_argument(self, arg):
#         '''Confirms that the specified arg is of a valid type'''
#         raise Exception('Abstract "supports_argument" operation won\'t accept any arguments')

#     def try_inline(self, machine_code, arg):
#         return None


# class PCRelative(Arg):
#     '''
#     Represents an address parameter to an Insn and describes how the register number is encoded.
#     '''

#     def __init__(self, byte, width, delta):
#         self.byte = byte
#         self.width = width
#         self.delta = delta

#     def getExclusiveRegion(self):
#         return (self.byte, self.byte + self.width - 1)

#     def strGenericName(self):
#         return 'label'

#     def strType(self):
#         return 'label_t *'

#     def getKind(self):
#         return 'a'

#     def printCopyToExclusiveRegion(self, p, dataptr):
#         p('%s->label_position = %s + %d;' % (self.strName(), dataptr, self.byte))
#         p('%s->base_position = %s + machine_code_len;' % (self.strName(), dataptr))
#         #p('int %s_offset = (char *)data + %d - (char *)%s;' % (self.strName(), self.delta, self.strName()))
#         #p('memcpy(%s + %d, &%s_offset, %d);' % (dataptr, self.byte, self.strName(), self.width))

#     def printDisassemble(self, dataptr, offset_shift, p):
#         if (self.byte + offset_shift < 0):
#             return
#         p('int relative_%s;'% self.strName())
#         p('memcpy(&relative_%s, data + %d, %d);' % (self.strName(), self.byte, self.width))
#         p('unsigned char *%s = data + relative_%s + machine_code_len;' % (self.strName(), self.strName()))

#         maxsize = 128
#         p('char %s_buf[%d];' % (self.strName(), maxsize))
#         if True:
#             p('if (debug_address_lookup((void *) %s, &addr_prefix)) {' % self.strName())
#             p('\tsnprintf(%s_buf, %d, "%%-10%s\t; %%s%%s", %s, addr_prefix, debug_address_lookup((void *) %s, NULL));' % (
#                 self.strName(), maxsize, 'p', self.strName(), self.strName()))
#             p('} else {')
#             p('\tsnprintf(%s_buf, %d, "%%%s", %s);' % (self.strName(), maxsize, 'p', self.strName()))
#             p('}')
#         else:
#             p('snprintf(%s_buf, %d, "%%%s", %s);' % (self.strName(), maxsize, 'p', self.strName()))
#         return (['%s'], ['%s_buf' % self.strName()])
#         # return (["%p"], [self.strName()])

#     def genLatex(self, m):
#         return 'addr'

#     def getType(self):
#         return 'ASM_ARG_LABEL'


# def make_anonymous_regnames_subscript(descr, anonymous_regnames = 4):
#     for c in range(0, anonymous_regnames):
#         descr = descr.replace('$r' + str(c), '$\\texttt{\\$r}_{' + str(c) + '}$')
#     return descr


# class Reg(Arg):
#     '''
#     Represents a register parameter to an Insn and describes how the register number is encoded.
#     '''
#     def __init__(self, bitpatterns):
#         assert type(bitpatterns) is list
#         self.bit_patterns = list(bitpatterns)
#         self.bit_patterns.reverse()

#     def getBuilderFor(self, offset):
#         if offset in self.atbit:
#             pats = self.atbit[offset]
#             results = []
#             name = self.strName()
#             for (pat, bitoffset) in pats:
#                 results.append(pat.strExtract(name, bitoffset))
#             return ' | '.join(results)
#         return None

#     def getKind(self):
#         return 'r'

#     def strGenericName(self):
#         return 'r'

#     def strType(self):
#         return 'int'

#     def printDisassemble(self, dataptr, offset_shift, p):
#         decoding = []
#         bitoffset = 0
#         for pat in self.bit_patterns:
#             offset = pat.byte_pos + offset_shift
#             if (offset >= 0):
#                 decoding.append('(' + pat.str_decode(dataptr + '[' + str(offset) + ']') + ('<< %d)' % bitoffset))
#             bitoffset += pat.bits_nr
#         p('int %s = %s;' % (self.strName(), ' | ' .join(decoding)))
#         return (['%s'], ['register_names[' + self.strName() + '].mips'])

#     def genLatex(self, m):
#         n = m['r']
#         m['r'] = n + 1
#         return make_anonymous_regnames_subscript('$r' + str(n)) # '\\texttt{\\$r' + str(n) + '}'

#     def getType(self):
#         return 'ASM_ARG_REG'

#     def supports_argument(self, arg):
#         if not isinstance(arg, AbstractRegister):
#             raise Exception('Register parameter required, but was passed %s' % type(arg))

#     def try_inline(self, machine_code, arg):
#         return None



# class JointReg(Arg):
#     '''
#     Multiple destinations for a single register argument (no exclusive range)
#     '''
#     def __init__(self, subs):
#         self.subs = subs

#     def setName(self, name):
#         self.name = name
#         for n in self.subs:
#             n.setName(name)

#     def getExclusiveRegion(self):
#         return None

#     def getBuilderFor(self, offset):
#         builders = []
#         for n in self.subs:
#             b = n.getBuilderFor(offset)
#             if b is not None:
#                 builders.append(b)
#         if builders == []:
#             return None
#         return ' | '.join('(%s)' % builder for builder in builders)

#     def getKind(self):
#         return 'r'

#     def maskOut(self, offset):
#         mask = 0xff
#         for n in self.subs:
#             mask = mask & n.maskOut(offset)
#         return mask

#     def strGenericName(self):
#         return 'r'

#     def strType(self):
#         return 'int'

#     def printDisassemble(self, dataptr, offset_shift, p):
#         return self.subs[0].printDisassemble(dataptr, offset_shift, p)

#     def genLatex(self, m):
#         return self.subs[0].genLatex(m)

#     def getType(self):
#         return self.subs[0].getType()


# class Imm(Arg):
#     '''
#     Represents an immediate value as parameter.

#     name_lookup: should this number be looked up in the address store to check for special meanings?
#     '''
#     def __init__(self, ctype, docname, cformatstr, bytenr, bytelen, name_lookup=True, format_prefix=''):
#         self.ctype = ctype
#         self.docname = docname
#         self.cformatstr = cformatstr
#         self.bytenr = bytenr
#         self.bytelen = bytelen
#         self.name_lookup = name_lookup
#         self.format_prefix = format_prefix

#     def getKind(self):
#         return 'i'

#     def getExclusiveRegion(self):
#         return (self.bytenr, self.bytenr + self.bytelen - 1)

#     def strGenericName(self):
#         return 'imm'

#     def strType(self):
#         return self.ctype

#     def printCopyToExclusiveRegion(self, p, dataptr):
#         p('memcpy(%s + %d, &%s, %d);' % (dataptr, self.bytenr, self.strName(), self.bytelen))

#     def printDisassemble(self, dataptr, offset_shift, p):
#         if (self.bytenr + offset_shift < 0):
#             return
#         p('%s %s;' % (self.ctype, self.strName()))
#         p('memcpy(&%s, %s + %d, %d);' % (self.strName(), dataptr, self.bytenr + offset_shift, self.bytelen))
#         maxsize = 128
#         p('char %s_buf[%d];' % (self.strName(), maxsize))
#         if (self.name_lookup):
#             p('if (debug_address_lookup((void *) %s, &addr_prefix)) {' % self.strName())
#             p('\tsnprintf(%s_buf, %d, "%s%%-10%s\t; %%s%%s", %s, addr_prefix, debug_address_lookup((void *) %s, NULL));' % (
#                 self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName(), self.strName()))
#             p('} else {')
#             p('\tsnprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
#             p('}')
#         else:
#             p('snprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
#         return (['%s'], ['%s_buf' % self.strName()])

#     def genLatex(self, m):
#         name = self.docname + str(self.bytelen * 8)
#         assert 'v' not in m
#         m['v'] = name
#         return name

#     def getType(self):
#         return 'ASM_ARG_IMM' + str(self.bytelen * 8) + self.docname.upper()

# class DisabledArg(Arg):
#     '''
#     Disables an argument.  The argument will still be pretty-print for disassembly (with the provided
#     default value) but won't be decoded or encoded.
#     '''
#     def __init__(self, arg, defaultvalue):
#         self.arg = arg
#         self.arg.setName(defaultvalue)

#     def getExclusiveRegion(self):
#         return None

#     def strGenericName(self):
#         return self.arg.strGenericName()

#     def printDisassemble(self, d, o, p):
#         def skip(s):
#             pass
#         return self.arg.printDisassemble(d, o, skip)

#     def isDisabled(self):
#         return True

#     def genLatex(self, m):
#         return self.arg.genLatex(m)

def mkp(indent):
    '''Helper for indented printing'''
    def p(s):
        print(('\t' * indent) + s)
    return p


# def ImmInt(offset):
#     return Imm('int', 's', 'd', offset, 4, name_lookup = False)

# def ImmUInt(offset):
#     return Imm('unsigned int', 'u', 'x', offset, 4, name_lookup = False, format_prefix='0x')

# def ImmByte(offset):
#     return Imm('unsigned char', 'u', 'x', offset, 1, name_lookup = False, format_prefix='0x')

# def ImmLongLong(offset):
#     return Imm('long long', 's', 'llx', offset, 8, format_prefix='0x')

# def ImmReal(offset):
#     return Imm('double', 'f', 'f', offset, 8, name_lookup = False)


def make_registers(reg_specs : list[tuple[str, str]]):
    count = 0
    module = {}
    regmap = {}
    regs = []
    for regnative, reg2opm in reg_specs:
        reg = MachineRegister(regnative, reg2opm, count)
        module[regnative] = reg
        regs.append(reg)
        regmap[reg2opm] = reg
        count += 1
    module['REGISTERS'] = regs
    module['REGISTER_MAP'] = regmap
    return module


def MachineInsnFactory(architecture : str):
    '''Factory for abstract instructions for one architecture'''
    def AbstractInsn(name, machine_code, formals):
        '''Factory for concrete uses of one machine instruction'''
        def make(*actuals):
            return MachineInsn(architecture, name, machine_code, formals, actuals)
        return make
    return AbstractInsn


# ================================================================================
# 2OPM assembly


# ----------------------------------------
# 2OPM Registers

class PMMachineArg(MachineActualArg):
    '''2OPM parameter, passed to code gen'''
    def __init__(self, pmid : int, mtype):
        MachineActualArg.__init__(self, abstract=True, mtype=mtype)
        self.pmid = pmid

    def __hash__(self):
        return hash((type(self), self.pmid))

    def __eq__(self, other):
        return type(other) == type(self) and other.pmid == self.pmid

    def __str__(self):
        return '$%s%d:%s' % (self.mtype.hint, self.pmid, self.mtype)


class PMLiteral(PMMachineArg, MachineLiteral):
    '''Literal number that is passed during 2OPM codegen'''
    def __init__(self, pmid : int, bits : int, signed : bool):
        PMMachineArg.__init__(self, pmid=pmid, mtype=MachineFormalImmediate.MAPPING[(bits, 's' if signed else 'u')])


class PMRegister(PMMachineArg):
    '''Literal register ID that is passed during 2OPM codegen'''
    def __init__(self, pmid : int):
        PMMachineArg.__init__(self, pmid=pmid, mtype=ASM_ARG_REG)


# PM ops take at most one literal parameter, so the following suffices:
L8U = PMLiteral(0, 8, False)
L32U = PMLiteral(0, 32, False)
L32S = PMLiteral(0, 32, True)
L64U = PMLiteral(0, 64, False)
L64S = PMLiteral(0, 64, True)

# Use as R(0), R(1), R(2) etc. to refer to distinct formal 2OPM parameters
R = PMRegister


# ----------------------------------------
# 2OPM Instruction effect descriptions


class Effect(object):
    def __init__(self, text):
        self.text = text

    def getDescription(self):
        return self.text

class ArithmeticEffect(Effect):
    def __init__(self, c_operator, plaintext = None, immediate = False):
        if plaintext is None:
            plaintext = c_operator
        arg = '$r1'
        if immediate:
            arg = '%a'
        Effect.__init__(self, '$r0 := $r0 ' + plaintext + ' ' + arg)
        self.c_operator = c_operator

def ArithmeticImmediateEffect(operand, plaintext = None):
    return ArithmeticEffect(operand, plaintext, True)


# ----------------------------------------
# 2OPM Instructions


class Insn:
    emit_prefix = LIB_PREFIX + "emit_"

    def __init__(self, name, descr, args, machine_code, test=None):
        self.name = name
        self.descr = descr
        self.function_name = name
        self.is_static = False
        self.machine_code = machine_code
        assert isinstance(machine_code, MachineAssembly)
        self.args = args
        assert type(args) is list
        self.format_string = None # optional format string override
        self.test = test
        self.arg_name = {}

        arg_type_counts = {}
        for arg in self.args:
            if arg is not None:
                n = arg.mtype.hint
                if n not in arg_type_counts:
                    arg_type_counts[n] = 1
                else:
                    arg_type_counts[n] += 1

        arg_type_multiplicity = dict(arg_type_counts)

        # name the arguments
        revargs = list(args)
        revargs.reverse()
        for arg in revargs:
            if arg is not None:
                n = arg.mtype.hint
                if n is None:
                    raise Exception('Cannot stringify arg %s' % arg)
                if arg_type_multiplicity[n] > 1:
                    self.arg_name[arg] = n + str(arg_type_counts[n])
                    arg_type_counts[n] -= 1
                else:
                    self.arg_name[arg] = n # only one of these here

    def argname(self, arg):
        return self.arg_name[arg]

    # def allEncodings(self):
    #     return [self]

    # def getArgs(self):
    #     return self.args

    def printHeader(self, trail=';', prln=print):
        arglist = []
        for arg in self.args:
            arglist.append(arg.mtype.c_type + ' ' + self.argname(arg))
        if self.is_static:
            prln('static void')
        else:
            prln('void')
        prln(Insn.emit_prefix + self.function_name + '(' + ', '.join(["buffer_t *buf"] + arglist) + ')' + trail)

    # def machineCodeLen(self):
    #     return '%d' % len(self.machine_code)

    # def prepareMachineCodeLen(self, p):
    #     pass

    # def postprocessMachineCodeLen(self, p):
    #     pass

    # def initialMachineCodeOffset(self):
    #     return 0

    # def printDataUpdate(self, p, offset, machine_code_byte, spec):
    #     p('data[%d] = 0x%02x%s;' % (offset, machine_code_byte, spec))

    # def getConstructionBitmaskBuilders(self, offset):
    #     builders = []
    #     build_this_byte = True
    #     for arg in self.args:
    #         if arg is not None:
    #             if arg.inExclusiveRegion(offset):
    #                 return None

    #             builder = arg.getBuilderFor(offset)
    #             if builder is not None:
    #                 builders.append('(' + builder + ')')
    #     return builders

    # def printOffsetCalculatorBranch(self, tabs, argarg):
    #     al = []
    #     for arg in self.args:
    #         exclusive_region = arg.getExclusiveRegion()
    #         if (exclusive_region):
    #             al.append('%d' % exclusive_region[0])
    #         else:
    #             al.append('-1')

    #     print((tabs + 'return ({arg} < 0 || {arg} >= {max})?-1: ((int[]){{ {offsets} }})[{arg}];'
    #            .format(arg=argarg, max=len(self.args),
    #                    offsets=', '.join(al))))

    # def printGenerator(self):
    #     self.printHeader(trail='')
    #     print('{')
    #     p = mkp(1)
    #     self.prepareMachineCodeLen(p)
    #     p('const int machine_code_len = %s;' % self.machineCodeLen())
    #     p('unsigned char *data = buffer_alloc(buf, machine_code_len);')
    #     self.postprocessMachineCodeLen(p)

    #     # Basic machine code generation: copy from machine code string and or in any suitable arg bits
    #     offset = self.initialMachineCodeOffset()
    #     for byte in self.machine_code:
    #         builders = self.getConstructionBitmaskBuilders(offset)
    #         if builders is not None:
    #             if len(builders) > 0:
    #                 builders = [''] + builders # add extra ' | ' to beginning
    #             self.printDataUpdate(p, offset, byte, ' | '.join(builders))

    #         offset += 1

    #     for arg in self.args:
    #         if arg is not None:
    #             if arg.getExclusiveRegion() is not None:
    #                 arg.printCopyToExclusiveRegion(p, 'data')

    #     print('}')

    # def printTryDisassemble(self, data_name, max_len_name):
    #     self.printTryDisassembleOne(data_name, max_len_name, self.machine_code, 0)

    # def setFormat(self, string):
    #     self.format_string = string
    #     return self

    # def printTryDisassembleOne(self, data_name, max_len_name, machine_code, offset_shift):
    #     checks = []

    #     offset = offset_shift
    #     for byte in machine_code:
    #         bitmask = 0xff
    #         for arg in self.args:
    #             if arg is not None:
    #                 bitmask = bitmask & arg.maskOut(offset)

    #         if bitmask != 0:
    #             if bitmask == 0xff:
    #                 checks.append('data[%d] == 0x%02x' % (offset - offset_shift, byte))
    #             else:
    #                 checks.append('(data[%d] & 0x%02x) == 0x%02x' % (offset - offset_shift, bitmask, byte))
    #         offset += 1

    #     assert len(checks) > 0

    #     p = mkp(1)
    #     p(('if (%s >= %d && ' % (max_len_name, len(machine_code))) + ' && '.join(checks) + ') {')
    #     pp = mkp(2)

    #     pp('const int machine_code_len = %d;' % len(machine_code));
    #     formats = []
    #     format_args = []
    #     for arg in self.args:
    #         if arg is not None:
    #             (format_addition, format_args_addition) = arg.printDisassemble('data', -offset_shift, pp)
    #             formats = formats + format_addition
    #             format_args = format_args + format_args_addition
    #     pp('if (file) {');
    #     if len(formats) == 0:
    #         pp('\tfprintf(file, "%s");' % self.name)
    #     else:
    #         format_string = ', '.join(formats)
    #         if self.format_string is not None:
    #             format_string = self.format_string % tuple(formats)
    #         pp(('\tfprintf(file, "%s\\t' % self.name) + format_string + '", ' + ', '.join(format_args) + ');');
    #     pp('}')
    #     pp('return machine_code_len;')
    #     p('}')

    # def genLatexTable(self):
    #     '''Returns list with the following elements (as LaTeX): [insn-name, args, short description]'''

    #     args = []
    #     m = { 'r' : 0 }
    #     for a in self.args:
    #         args.append(a.genLatex(m))

    #     valstr = m['v'] if 'v' in m else '?'

    #     descr = self.descr

    #     if type(descr) is not str:
    #         descr = self.descr.getDescription()

    #     descr = (descr
    #              .replace('\\', '\\')
    #              .replace('%v', '\\texttt{' + valstr + '}')
    #              .replace('%a', '\\texttt{addr}'))

    #     anonymous_regnames = 4

    #     regnames = ['pc', 'sp', 'gp', 'fp']
    #     for (pfx, count) in [('a', 6), ('v', 1), ('t', 2), ('s', 4)]:
    #         for c in range(0, count + 1):
    #             regnames.append(pfx + str(c))

    #     for r in regnames:
    #         descr = descr.replace('$' + r, '\\texttt{\\$' + r + '}')

    #     descr = (descr
    #              .replace('$$', '$')
    #              .replace('_', '\\_'))

    #     descr = make_anonymous_regnames_subscript(descr)

    #     name = '\\textcolor{dblue}{\\textbf{\\texttt{' + self.name.replace('_', '\\_') + '}}}'

    #     return [name, ', '.join(args), descr]


# class NewInsn(Insn):
#     emit_prefix = LIB_PREFIX + "emit_"

#     def __init__(self, name, descr, implementation, test=None):
#         machine_code, args = implementation.generate()
#         Insn.__init__(self, name, descr, machine_code, args, test=test)

