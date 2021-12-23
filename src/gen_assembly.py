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

'''General-purpose assembly code management (intended to be cross-platform).

Overview
========

The classes here generate C code (plus documentation) suitabley for
working with 2OPM.

- Insn: 2OPM instruction
        May consist of multiple MachineInsnInstances.
  Parameters map directly to machine instruction parameters:
  - PMRegister
  - PMLiteral
- MachineInsnInstance: Native machine instruction.
  - MachineInsn: Machine insn without any actuals passed in
  - MachineArgType: argument types for machine instructions (register, integer, address), and how to represent them in C.
  - MachineFormalArg: formal argument to machine instruction (type + encoding)
  - MachineActualArg: actual machine argument
    - can be fixed within an Insn:
      - MachineRegister
      - MachineLiteral
    - or map to an Insn parameter:
      - PMRegister
      - PMLiteral
- ByteEncoding: maps an integer to a (possibly noncontiguous) range of bits in a byte sequence.
                 Used to encode parameters to machine instructions.
- MachineInsnSet: Full set of machine instruction templates
- InsnSet: Full set of 2opm instructions


Design goals
============
- generate efficient C code for emitting 2OPM instructions natively
- generate C code for 2OPM disassembly
- generate LaTeX documentation for code
- enable testing of generated 2OPM instructions
- support 2OPM insns that must be built from multiple machine insns
  (rationale: needd in practice, e.g., amd64 "shift" operations need
  the shift number stored in a specific register, requiring additional
  "swap" instructions before and after)
- support 2OPM insns that may use different machine insns depending on their actual parameters
  (rationale: needed in practice; supporting division/remainder
  computation on amd64 without fixing registers in a nonportable way
  requires different "swap" instruction sequences, depending on parameters)
- support cross-platform code-gen, including evolving insn set if needed
- support multiple machine insn encodings for same insn (at least in principle)
  (rationale: reduce code size; this is lower priority.)


Facilities found here
=====================

Instruction encoding
--------------------
- generate C function ('emit_<INSN>(...)') that emits the specified instruction
- Insn.print_encoder
  - relies on MachineInsnInstance to handle per-insn encoding

Instruction decoding
--------------------
- operates at MachineInsn level
- MachineInsn.decoder_signature : significant bits to identify MachineInsn
- MachineInsnSet:
  - emits 'disassemble_native()'
  - which generates "token stream" of decoded instructions
- InsnSet:
  - emits 'disassemble_one()'
  - which uses 'disassemble_native()' on a ringbuffer to parse machine insns into 2opm insns
  - uses "most specific match" rule to disambiguate

'''

# prefix for the generated C code functions
LIB_PREFIX = ''


# ================================================================================
# Code emitter tools

def mkp(indent, prln=print):
    '''Helper for indented printing'''
    def p(s):
        prln(('\t' * indent) + s)
    return p


# ================================================================================
# ByteEncoding and its helpers

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

    @staticmethod
    def span(byte_start, byte_length):
        return MultiByteEncoding.at(*[(n + byte_start, 0, 8) for n in range(0, byte_length)])


# ================================================================================
# Argument types

class MachineArgType:
    ALL = []

    def __init__(self, test_category : str, name_hint : str, asm_arg_type : str, gen_c_type : str):
        self._test_category = test_category
        self._name_hint = name_hint
        self._asm_arg_type = 'ASM_ARG_' + asm_arg_type
        self._short_arg_type = asm_arg_type
        self._gen_c_type = gen_c_type
        MachineArgType.ALL.append(self)

    @property
    def hint(self):
        return self._name_hint

    @property
    def asm_arg(self):
        return self._asm_arg_type

    @property
    def c_union_field(self):
        '''
        Name to use for fields in C unions for values of this type
        '''
        return self._short_arg_type.lower()

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
ASM_ARG_IMM8U = MachineArgTypeLiteral(8, False,   'unsigned char')# x
ASM_ARG_IMM32U = MachineArgTypeLiteral(32, False, 'unsigned int')# x
ASM_ARG_IMM32S = MachineArgTypeLiteral(32, True,  'signed int')# d
ASM_ARG_IMM64U = MachineArgTypeLiteral(64, False, 'unsigned long long')# llx
ASM_ARG_IMM64S = MachineArgTypeLiteral(64, True,  'signed long long')# lld

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

    def __init__(self, pattern : ByteEncoding, arg_type : MachineArgType):
        self._arg_type = arg_type
        self._pattern = pattern

    @property
    def mtype(self):
        '''
        Returns the permitted argument type
        '''
        return self._arg_type

    @property
    def pattern(self) -> ByteEncoding:
        '''
        Returns the machine code byte pattern
        '''
        return self._pattern

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
        MachineFormalArg.__init__(self, pattern, arg_type)
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
        MachineFormalArg.__init__(self, pattern, ASM_ARG_REG)
        assert isinstance(pattern, ByteEncoding)

    def try_inline(self, machine_code, arg):
        if arg.is_abstract:
            return False
        self.pattern.apply_to(machine_code, arg.num)
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


class MachineInsnDecoderSignature:
    def __init__(self, machine_code, formals):
        self.length = len(machine_code)
        self.machine_code = machine_code
        self.mask = [0xff] * self.length
        for formal in formals:
            formal.pattern.apply_to(self.mask, 0)
        significant = self.length
        while self.mask[significant - 1] == 0:
            significant -= 1
        self.significant_bytes = significant
        self.formals = formals

    def c_joined_string(self, bytelist):
        '''
        Mask must be little-endian
        '''
        l = bytelist[:self.significant_bytes]
        return '0x%sLLU' % (''.join('%02x' % l[i] for i in range(self.significant_bytes - 1, -1, -1)))

    @property
    def c_mask_string(self):
        return self.c_joined_string(self.mask)

    @property
    def c_code_string(self):
        return self.c_joined_string(self.machine_code)


class MachineInsn:
    '''
    An abstract machine instruction
    '''
    def __init__(self, architecture : str, name : str, machine_code : list[int], formals : list[MachineFormalArg]):
        self.name = name
        self.architecture = architecture
        self.machine_code = machine_code
        self.formals = formals

    @property
    def decoder_signature(self) -> MachineInsnDecoderSignature:
        return MachineInsnDecoderSignature(self.machine_code, self.formals)

    def __call__(self, *actuals):
        return MachineInsnInstance(template=self, actuals=actuals)


class MachineInsnInstance(MachineAssembly):
    '''A single native machine instruction'''
    def __init__(self, template : MachineInsn, actuals : list[MachineActualArg]):
        MachineAssembly.__init__(self)
        self.template = template
        machine_code = list(template.machine_code) # duplicate so we can overwrite below
        self.actuals = actuals
        assert len(self.formals) == len(actuals)
        self.pm_formals = []

        for formal, actual in zip(self.formals, actuals):
            formal.supports_argument(actual, self)
            if not formal.try_inline(machine_code, actual):
                self.pm_formals.append((actual, formal))

        self.machine_code = machine_code

    @property
    def arch(self):
        return self.template.architecture

    @property
    def name(self):
        return self.template.name

    @property
    def formals(self):
        return self.template.formals

    @property
    def parameters(self):
        '''Order by actuals'''
        return [actual.for_formals(self.formals) for actual in self.actuals]

    def generate_encoding_at(self, offset, arg_encode):
        '''
        @param offset : int  byte offset to encode at
        @param arg_encode : PMArgument -> string  map 2OPM args to C expressions
        '''
        encoders_p = [f.pattern.gen_encoding_at(arg_encode(a), offset) for (a, f) in self.pm_formals]
        encoders = ['(%s)' % e for e in encoders_p if e is not None]
        encoders = ['0x%02x' % (self.machine_code[offset])] + encoders
        return ' | '.join(encoders)

    def __str__(self):
        return '%s[%s/%s]' % (self.name,
                              ', '.join(str(f) for f in self.formals),
                              ', '.join(str(a) for a in self.actuals))

    def __len__(self):
        return len(self.machine_code)

    def __iter__(self):
        yield self


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

    def __iter__(self):
        for mi in self.seq:
            yield mi

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

    def __len__(self):
        total = 0
        for mc in self.seq:
            total += len(mc)

        return total


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
    '''
    Factory for abstract instructions for one architecture

    Returns (MachineInsnSet, (name, list[int], list[formals]) -> MachineInsn)
    '''
    mset = MachineInsnSet(architecture, [])
    def make(name, machine_code, formals):
        '''Factory for MachineInsns'''
        insn_template = MachineInsn(architecture, name, machine_code, formals)
        mset.append(insn_template)
        return insn_template
    return (mset, make)


# ----------------------------------------
class MachineInsnSet:
    '''
    Set of machine assembly instructions.
    '''
    def __init__(self, arch : str, machine_insns : list[MachineInsn]):
        self.templates : list[tuple(MachineInsn, int)] = list(zip(machine_insns, range(0, len(machine_insns))))
        self.arch = arch

    def append(self, insn):
        self.templates.append((insn, len(self.templates)))

    @property
    def c_machine_arg_t(self):
        return '%s%s_machine_arg_t' % (LIB_PREFIX, self.arch)

    @property
    def c_machine_insn_info_t(self):
        return '%smachine_insn_info_t' % (LIB_PREFIX)

    @property
    def c_MACHINE_ARG_BUF_MASK(self):
        return ('%s%s_machine_arg_buf_mask' % (LIB_PREFIX, self.arch)).upper()

    def c_MACHINE_INSN(self, insn, insn_nr):
        return ('%s%s_machine_insn_%d_%s' % (LIB_PREFIX, self.arch, insn_nr, insn.name)).upper()

    def print_decoder_header(self, machine_arg_buf_mask, prln=print):
        for (it, itn) in self.templates:
            prln(f'#define {self.c_MACHINE_INSN(it, itn)}\t{itn}')

        buf_args = '\n'.join('\t\t%s %s;' % (mt.c_type, mt.c_union_field) for mt in MachineArgType.ALL)
        prln(f'''
#define {self.c_MACHINE_ARG_BUF_MASK} 0x{"%04x" % machine_arg_buf_mask}

typedef struct {{
	short insn;
	unsigned short size;
}} {self.c_machine_insn_info_t};

/**
 * Ring buffer for storing decoded arguments to machine instructions
 */
typedef struct {{
	size_t write_offset;
        size_t read_offset;
        union {{
{buf_args}
        }} buf[{machine_arg_buf_mask + 1}];
}} {self.c_machine_arg_t};
''')
        self.print_decoder_header_function(prln=prln)

    def print_decoder_header_function(self, trail=';', prln=print):
        prln(f'''machine_insn_info_t
{LIB_PREFIX}disassemble_native(unsigned char* code, size_t max_len, {self.c_machine_arg_t}* args){trail}''')

    def print_decoder(self, prln=print):
        self.print_decoder_header_function(trail='', prln=prln)
        max_bytes = self.max_significant_bytes

        prln(f'''{{
        const size_t bytes_nr = max_len > {max_bytes} ? {max_bytes} : max_len;
	uint64_t pattern = 0;

        for (int i = 0; i < bytes_nr; ++i) {{
        	pattern |= code[i] << (i << 3);
        }}

	switch (bytes_nr) {{
	default:''')

        p = mkp(1, prln)
        pp = mkp(2, prln)
        ppp = mkp(3, prln)

        last_size = -1

        for tinsn, tinsn_index in self.ordered_decoder_signatures:
            decoder = tinsn.decoder_signature
            if decoder.length != last_size:
                p('case %d:' % decoder.length)
                last_size = decoder.length

            pp(f'if ((pattern & {decoder.c_mask_string}) == {decoder.c_code_string}) {{');
            for formal in decoder.formals:
                field = formal.mtype.c_union_field
                mtype = formal.mtype.c_type
                ppp(f'args->buf[args->write_offset].{field} = {formal.pattern.gen_decoding(lambda i: f"(({mtype})code[%d])" % i)};')
                ppp(f'args->write_offset = (args->write_offset + 1) & {self.c_MACHINE_ARG_BUF_MASK};');
            MACHINE_INSN = self.c_MACHINE_INSN(tinsn, tinsn_index)
            ppp(f'return ({self.c_machine_insn_info_t}) {{ .insn = {MACHINE_INSN}, .size = {decoder.length} }};')
            pp('}')

        prln(f'''	}}
	// failure
	return ({self.c_machine_insn_info_t}) {{ .insn = -1, .size = 0 }};
}}''')

    @property
    def max_significant_bytes(self):
        '''
        Maximum number of significant bytes needed to check the presence of any instruction.
        '''
        result = 0
        for it, _ in self.templates:
            result = max(result, it.decoder_signature.significant_bytes)
        if result > 8:
            raise Exception('Max significant bytes for decoding insns is %d, but max of 8 is supported.  You will probably have to change how we do decoding to fix this...' % result)
        return result

    @property
    def ordered_decoder_signatures(self) -> list[tuple[MachineInsn, int]]:
        '''
        Returns list of (MachineInsn, int) suitable for c_MACHINE_INSN, and ordered in
        descending order of total encoding size.
        '''
        # def keyfn(p):(mi, _)):
        # return -mi.decoder_signature.length
        return sorted(self.templates, key=lambda mi: -mi[0].decoder_signature.length)


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
    '''
    2OPM instruction, which is then mapped to machine instructions
    '''
    emit_prefix = LIB_PREFIX + "emit_"

    def __init__(self, name, descr, args, machine_code, test=None):
        self.name = name
        self.descr = descr
        self.function_name = name
        self.is_static = False
        self.machine_code : MachineAssembly = machine_code
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

    @property
    def machine_insns_args_nr(self):
        '''
        Total number of arguments passed to MachineInsnInstances that make up
        this Insn
        '''
        return sum(len(minsn.formals) for minsn in self.machine_code)

    def argname(self, arg):
        return self.arg_name[arg]

    # def allEncodings(self):
    #     return [self]

    # def getArgs(self):
    #     return self.args

    def print_encoder_header(self, trail=';', prln=print):
        arglist = []
        for arg in self.args:
            arglist.append(arg.mtype.c_type + ' ' + self.argname(arg))
        if self.is_static:
            prln('static void')
        else:
            prln('void')
        prln(Insn.emit_prefix + self.function_name + '(' + ', '.join(["buffer_t *buf"] + arglist) + ')' + trail)

    @property
    def machine_code_len(self):
        return len(self.machine_code)

    # def prepareMachineCodeLen(self, p):
    #     pass

    # def postprocessMachineCodeLen(self, p):
    #     pass

    # def initialMachineCodeOffset(self):
    #     return 0

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

    def print_encoder(self, prln=print):
        self.print_encoder_header(trail='', prln=prln)
        prln('{')
        p = mkp(1, prln)
        # self.prepareMachineCodeLen(p)
        p('const int machine_code_len = %d;' % self.machine_code_len)
        p('unsigned char *data = buffer_alloc(buf, machine_code_len);')
        # self.postprocessMachineCodeLen(p)

        # Basic machine code generation: copy from machine code string and or in any suitable arg bits
        for offset in range(0, self.machine_code_len):
            p('data[%d] = %s;' % (offset, self.machine_code.generate_encoding_at(offset, self.argname)))
        # offset = 0
        # for byte in self.machine_code:
        #     builders = self.getConstructionBitmaskBuilders(offset)
        #     if builders is not None:
        #         if len(builders) > 0:
        #             builders = [''] + builders # add extra ' | ' to beginning
        #         self.print_data_update(p, offset, byte, ' | '.join(builders))

        #     offset += 1

        # for arg in self.args:
        #     if arg is not None:
        #         if arg.getExclusiveRegion() is not None:
        #             arg.print_copy_to_exclusive_region(p, 'data')

        prln('}')

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

    # def print_decoder(self, data_name, max_len_name, machine_code, offset_shift, prln=print):
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

    #     p = mkp(1, prln=prln)
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

def smallest_mask_for(n):
    '''
    Smallest bitmas that covers n (assuming no more than 64 bit)
    '''
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    return n


class InsnSet:
    '''
    2opm instruction set
    '''
    def __init__(self, *insns):
        self._insns = insns

    @property
    def insns(self):
        return self._insns

    def __iter__(self):
        for i in self.insns:
            yield i

    def print_disassembler(self, mi_set : MachineInsnSet, prln=print):
        max_machine_args_nr = max(insn.machine_insns_args_nr for insn in self)

        machine_arg_buf_mask = smallest_mask_for(max_machine_args_nr)
        mi_set.print_decoder_header(machine_arg_buf_mask, prln=prln)
        mi_set.print_decoder(prln=prln)
