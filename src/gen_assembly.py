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
  - PMImmediate
  - PMPCRelative
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
      - PMImmediate
- ByteEncoding: maps an integer to a (possibly noncontiguous) range of bits in a byte sequence.
                 Used to encode parameters to machine instructions.
- MachineInsnSet: Full set of machine instructions
- InsnSet: Full set of 2opm instructions

Concepts:
- Exclusive region: a byte span that is exclusively occupied by an argument to a machine instruction.
  The encoder and decoder may treat those regions specially for performance and/or to support
  relocation.


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
    p.indent = lambda: mkp(indent + 1, prln=prln)
    return p

def make_prln():
    buffer = []
    def prln(s):
        buffer.append(s)
    def is_empty():
        return buffer == []
    def print_all(p):
        for l in buffer:
            p(l)
    prln.is_empty = is_empty
    prln.print_all = print_all
    return prln


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
        self.span = None
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
    def __init__(self, *patterns, span=None):
        ByteEncoding.__init__(self)
        self.bit_patterns = list(patterns)
        self.bit_patterns.reverse()
        self.span = span
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
    def at(*offsets, span=None):
        '''
        offsets: list[tuple(byte_offset, enc_bitpos, bits_nr)]
        '''
        patterns = []
        decode_bitpos = 0
        for byte_offset, enc_bitpos, bits_nr in offsets:
            patterns.append(SingleByteEncoding.at(byte_offset, enc_bitpos, decode_bitpos, bits_nr))
            decode_bitpos += bits_nr
        return MultiByteEncoding(*patterns, span=span)

    @staticmethod
    def span(byte_start, byte_length):
        return MultiByteEncoding.at(*[(n + byte_start, 0, 8) for n in range(0, byte_length)], span=(byte_start, byte_length))


# ================================================================================
# Argument types

class MachineArgType:
    ALL = []

    def __init__(self, kind : str, name_hint : str, asm_arg_type : str, gen_c_type : str):
        self._kind = kind
        self._name_hint = name_hint
        self._asm_arg_type = 'ASM_ARG_' + asm_arg_type
        self._short_arg_type = asm_arg_type
        self._gen_c_type = gen_c_type
        MachineArgType.ALL.append(self)

    def _compute_range(self, bits, signed):
        range = (1 << bits)
        if signed:
            self.value_min = - (range >> 1)
            self.value_max = (range >> 1) - 1
        else:
            self.value_min = 0
            self.value_max = range - 1

    def range_within(self, other):
        '''
        Check whether the own range is contained within the other argument's range
        '''
        return self.value_min >= other.value_min and self.value_max <= other.value_max

    @property
    def supports_exclusive_region(self):
        '''
        This machine type is encoded in a contiguous range of native-endian
        bytes and can be copied efficiently with memcpy instead of bytewise
        transfer
        '''
        return False

    @property
    def hint(self):
        return self._name_hint

    @property
    def asm_arg(self):
        return self._asm_arg_type

    def gen_literal(self, value) -> str:
        '''
        Translate value (e.g. Python 'int') to its literal C representation
        '''
        return self.c_format_str % value

    @property
    def c_format_str(self):
        '''
        C sprintf-style format string for values of this type
        '''
        return '%d'

    def c_format_expr(self, c_var:str):
        '''
        C sprintf-style parameter, must match the format string
        '''
        return c_var

    @property
    def c_union_field(self):
        '''
        Name to use for fields in C unions for values of this type
        '''
        return self._short_arg_type.lower()

    @property
    def c_type(self):
        '''
        Type used for instruction encoding
        '''
        return self._gen_c_type

    @property
    def c_decode_type(self):
        '''
        Type used for instruction decoding (default: same as c_type)
        '''
        return self.c_type

    @property
    def kind(self):
        '''
        returns "r" (register), "i" (immediate) or "a" (address), used for testing
        '''
        return self._kind

    def print_prepare_c_format(self, c_var:str, c_expr:str, prln=print):
        '''
        2OPM disassembly level:
        Emits  preprocessing code that is guaranteed to be run before c_format_expr and c_format_str are used.
        c_var: Locally unique variable name (prefix)
        c_expr: Expression that reads the disassembled machine instruction's argument
        '''
        prln(f'const {self.c_type} {c_var} = {c_expr};')

    def supports_argument(self, arg):
        return False

    def gen_decoding(self, minsni, pattern, c_byte_ref_fn):
        def byte_ref(i):
            return f'(({self.c_decode_type}){c_byte_ref_fn(i)})'
        return pattern.gen_decoding(byte_ref)

    def __str__(self):
        return self.asm_arg


class MachineArgTypeReg(MachineArgType):
    def __init__(self):
        MachineArgType.__init__(self, 'r', 'r', 'REG', 'int')

    def supports_argument(self, arg):
        return type(arg.mtype) is MachineArgTypeReg

    def gen_literal(self, value) -> str:
        return '0x%x' % value

    @property
    def c_format_str(self):
        return '%s'

    def c_format_expr(self, c_var:str):
        '''
        C sprintf-style parameter, must match the format string
        '''
        return f'register_names[{c_var}].mips'


class MachineArgTypeImmediate(MachineArgType):
    def __init__(self, bits, signed, ctype : str, c_format_str : str, c_literal_format_str : str):
        '''
        ctype: C type to use
        c_format_str: what to pass to sprintf() etc. to format the corresponding values
        c_literal_format_str: how to format such a value from Python to C source code
        '''
        MachineArgType.__init__(self, 'i', 'imm', 'IMM%d%s' % (bits, 'S' if signed else 'U'), ctype)
        self._compute_range(bits, signed)
        self._literal_format_str = c_literal_format_str
        self._format_str = c_format_str
        self.bits = bits

    @property
    def c_format_str(self):
        return self._format_str

    def gen_literal(self, value):
        return self._literal_format_str % value

    def supports_argument(self, arg):
        if arg.is_abstract:
            return (type(arg.mtype) is MachineArgTypeImmediate
                    and arg.mtype.range_within(self))
        if arg.mtype is not None and (not isinstance(arg.mtype, MachineArgTypeImmediate) and not isinstance(arg.mtype, PMImmediate)):
            return False
        return arg.value >= self.value_min and arg.value <= self.value_max

    @property
    def supports_exclusive_region(self):
        return True

    def print_generate_exclusive(self,
                                 region : tuple[int, int],
                                 c_argname : str,
                                 c_code : str,
                                 prln=print):
        '''
        @param region: (offset, length) relative to c_code
        @param c_argname: parameter to 'emit_*(...)' that contains the argument to write
        @param c_code: first (offset zero) byte pointer (unsigned char*) to the generated code
        '''
        offset = region[0]
        assert self.bits == region[1] * 8
        prln(f'memcpy({c_code} + {offset}, &({c_argname}), {region[1]});')


class MachineArgTypePCRelative(MachineArgType):
    '''
    Jump label that is relative to the end of the current instruction
    '''
    def __init__(self, bits, signed):
        MachineArgType.__init__(self, 'a', 'label', 'PCREL%d%s' % (bits, 'S' if signed else 'U'), 'label_t*')
        self._compute_range(bits, signed)
        self._bits = bits
        self._c_label_size_t = ('int%d_t' % bits) if signed else ('uint%d_t' % bits)

    def gen_literal(self, value):
        raise Exception('PCRelative literals not currently supported')

    def supports_argument(self, arg):
        if arg.is_abstract:
            return type(arg.mtype) is MachineArgTypePCRelative and arg.mtype.range_within(self)
        return False

    @property
    def c_union_field(self):
        return 'label'

    def gen_decoding(self, minsn, pattern, c_byte_ref_fn):
        first_byteref = c_byte_ref_fn(pattern.span[0])
        return f'&({c_byte_ref_fn(0)}) + decode_{self._c_label_size_t}(&{first_byteref}) + {len(minsn.machine_code)}'

    @property
    def c_decode_type(self):
        return 'void*'

    @property
    def supports_exclusive_region(self):
        return True

    @property
    def c_format_str(self):
        return '%s'

    def c_format_expr(self, c_var:str):
        '''
        C sprintf-style parameter, must match the format string
        '''
        return f'{c_var}_buf'

    def print_generate_exclusive(self,
                                 region : tuple[int, int],
                                 c_argname : str,
                                 c_code : str,
                                 prln=print):
        '''
        @param region: (offset, length) relative to c_code
        @param c_argname: parameter to 'emit_*(...)' that contains the argument to write
        @param c_code: first (offset zero) byte pointer (unsigned char*) to the generated code
        '''
        offset = region[0]
        assert self._bits == region[1] * 8
        prln(f'{c_argname}->label_position = {c_code} + {offset};')
        prln(f'{c_argname}->base_position = data + machine_code_len;')

    def print_prepare_c_format(self, c_var:str, c_expr:str, prln=print):
        p = prln

        p(f'char *{c_var}_addr_prefix;')
        p(f'unsigned char *{c_var} = {c_expr};')
        p(f'char {c_var}_buf[128];')
        p(f'if (debug_address_lookup((void *) {c_var}, &{c_var}_addr_prefix)) {{')
        p(f'\tsnprintf({c_var}_buf, 128, "%-10p ; %s%s", {c_var}, {c_var}_addr_prefix, debug_address_lookup((void *) {c_var}, NULL));')
        p(f'}} else {{')
        p(f'\tsnprintf({c_var}_buf, 128, "%p", {c_var});')
        p(f'}}')



ASM_ARG_REG = MachineArgTypeReg()
ASM_ARG_PCREL32S = MachineArgTypePCRelative(32, True)
ASM_ARG_IMM8U = MachineArgTypeImmediate(8, False,   'uint8_t', '%" PRId8 "', '0x%02xU')
ASM_ARG_IMM32U = MachineArgTypeImmediate(32, False, 'uint32_t', '0x%" PRIx32 "', '0x%08xU')
ASM_ARG_IMM32S = MachineArgTypeImmediate(32, True,  'int32_t', '%" PRId32 "', '%d')
ASM_ARG_IMM64U = MachineArgTypeImmediate(64, False, 'uint64_t', '0x%" PRIx64 "', '0x%016xLLU')
ASM_ARG_IMM64S = MachineArgTypeImmediate(64, True,  'int64_t', '%" PRId64 "', '%dLL')

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

    @property
    def insn_decoder_constraint(self):
        '''
        returns None, int (explicit value), or PMMachineArg
        '''
        return None


class MachineLiteral(MachineActualArg):
    '''Literal number parameter, for MachineImmediate formals'''
    def __init__(self, number : int, mtype = None):
        MachineActualArg.__init__(self, abstract = (number == None), mtype = mtype)
        self.value = number

    def __str__(self):
        return 'literal(%d)' % (self.value)

    @property
    def insn_decoder_constraint(self):
        return int(self.value)


class MachineRegister(MachineActualArg):
    '''Literal register number, for MachineFormalRegister formals'''
    def __init__(self, name : str, name2opm : str, num : int):
        MachineActualArg.__init__(self, abstract = False, mtype = ASM_ARG_REG)
        self.num = num
        self.name = name
        self.name2opm = name2opm

    def __str__(self):
        return '%s[%d]' % (self.name, self.num)

    @property
    def insn_decoder_constraint(self):
        return int(self.num)


# Also see PMRegister and PMImmediate

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

    @property
    def byte_span(self) -> tuple[int, int]:
        '''
        returns None or (offset, length)
        '''
        return self.pattern.span

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

    def print_decode(self, minsn, c_dest:str, c_byte_ref, prln=print):
        decoding = self.mtype.gen_decoding(minsn, self.pattern, c_byte_ref)
        prln(f'{c_dest} = {decoding};')

    @property
    def exclusive_region(self):
        if self.mtype.supports_exclusive_region:
            return self.pattern.span

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

    @property
    def machine_insns(self):
        '''
        Returns all MachineInsnInstances within (might be the same as [self]
        '''
        raise Exception('Not Implemented')


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

    def joined_number(self, bytelist):
        '''
        Little-endian representation for incremental matching
        '''
        l = bytelist[:self.significant_bytes]
        l.reverse()
        v = 0
        for b in l:
            v <<= 8
            v |= b
        return (v, '0x%xLLU')
        #% (self.significant_bytes, ''.join('%02x' % l[i] for i in range(self.significant_bytes - 1, -1, -1)))

    @property
    def mask_and_format(self) -> tuple[int, str]:
        return self.joined_number(self.mask)

    @property
    def code_and_format(self) -> tuple[int, str]:
        return self.joined_number(self.machine_code)


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
        return MachineInsnInstance(insn=self, actuals=actuals)


class MachineInsnInstance(MachineAssembly):
    '''A single native machine instruction'''
    def __init__(self, insn : MachineInsn, actuals : list[MachineActualArg]):
        MachineAssembly.__init__(self)
        self._insn = insn
        machine_code = list(insn.machine_code) # duplicate so we can overwrite below
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
        return self._insn.architecture

    @property
    def insn(self):
        return self._insn

    @property
    def name(self):
        return self._insn.name

    @property
    def formals(self):
        return self._insn.formals

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

    @property
    def machine_insns(self):
        return [self]


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

    @property
    def machine_insns(self):
        return self.seq

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
        insn = MachineInsn(architecture, name, machine_code, formals)
        mset.append(insn)
        return insn
    return (mset, make)


# ----------------------------------------
class MachineInsnSet:
    '''
    Set of machine assembly instructions.
    '''
    def __init__(self, arch : str, machine_insns : list[MachineInsn]):
        self.insns : list[tuple(MachineInsn, int)] = list(zip(machine_insns, range(1, 1 + len(machine_insns))))
        self.insn_ids = {}
        for insn, nr in self.insns:
            self.insn_ids[insn] = nr
        self.arch = arch

    def append(self, insn):
        nr = 1 + len(self.insns)
        self.insn_ids[insn] = nr
        self.insns.append((insn, nr))

    @property
    def c_arch_prefix(self):
        return '%s%s_' % (LIB_PREFIX, self.arch)

    @property
    def c_machine_arg_t(self):
        return '%smachine_arg_t' % self.c_arch_prefix

    @property
    def c_machine_insn_info_t(self):
        return '%smachine_insn_info_t' % self.c_arch_prefix

    @property
    def c_disassemble_native_fn(self):
        return '%sdisassemble_native' % self.c_arch_prefix

    @property
    def c_MACHINE_ARG_BUF_MASK(self):
        return ('%smachine_arg_buf_mask' % self.c_arch_prefix).upper()

    def c_MACHINE_INSN(self, insn, insn_nr=None):
        if insn_nr is None:
            insn_nr = self.insn_ids[insn]
        return ('%smachine_insn_%d_%s' % (self.c_arch_prefix, insn_nr, insn.name)).upper()

    def print_decoder_header(self, machine_arg_buf_mask, prln=print):
        for (insn, insn_id) in self.insns:
            prln(f'#define {self.c_MACHINE_INSN(insn)}\t{insn_id}')

        buf_args = '\n'.join('\t\t%s %s;' % (mt.c_decode_type, mt.c_union_field) for mt in MachineArgType.ALL)
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
        #self.print_decoder_header_function(prln=prln)

    def print_decoder_header_function(self, trail=';', prln=print):
        prln(f'''{self.c_machine_insn_info_t}
{self.c_disassemble_native_fn}(unsigned char* code, size_t max_len, {self.c_machine_arg_t}* args){trail}''')

    def print_decoder(self, prln=print):
        self.print_decoder_header_function(trail='', prln=prln)
        max_bytes = self.max_significant_bytes

        prln(f'''{{
        const size_t bytes_nr = max_len > {max_bytes} ? {max_bytes} : max_len;
	uint64_t pattern = 0;

        for (int i = 0; i < bytes_nr; ++i) {{
        	pattern |= code[i] << (i << 3);
        }}

	switch (max_len) {{
	default:''')

        p = mkp(1, prln)
        pp = mkp(2, prln)
        ppp = mkp(3, prln)

        last_size = self.ordered_decoder_signatures[0][0].decoder_signature.length

        for tinsn, tinsn_index in self.ordered_decoder_signatures:
            decoder = tinsn.decoder_signature
            while decoder.length != last_size:
                last_size -= 1
                p('case %d:' % last_size)

            (mask, mask_format) = decoder.mask_and_format
            (code, code_format) = decoder.code_and_format

            assert (mask & code) == code, ("(mask:0x%x & code:0x%x) yields diff of 0x%x in machine insn %s"
                                           % (mask, code, ~mask & code, tinsn.name))

            c_mask = mask_format % mask
            c_code = code_format % code

            pp(f'if ((pattern & {c_mask}) == {c_code}) {{');
            for formal in decoder.formals:
                field = formal.mtype.c_union_field
                mtype = formal.mtype.c_type
                formal.print_decode(tinsn,
                                    c_dest=f'args->buf[args->write_offset].{field}',
                                    c_byte_ref=(lambda i: 'code[%d]' % i),
                                    prln=ppp)
                #(f'args->buf[args->write_offset].{field} = {formal.pattern.gen_decoding(lambda i: f"(({mtype})code[%d])" % i)};')
                ppp(f'args->write_offset = (args->write_offset + 1) & {self.c_MACHINE_ARG_BUF_MASK};');
            MACHINE_INSN = self.c_MACHINE_INSN(tinsn, tinsn_index)
            ppp(f'return ({self.c_machine_insn_info_t}) {{ .insn = {MACHINE_INSN}, .size = {decoder.length} }};')
            pp('}')

        while 0 < last_size:
            last_size -= 1
            p('case %d:' % last_size)
        p('break;')
        p(f'''}}
	// failure
	return ({self.c_machine_insn_info_t}) {{ .insn = -1, .size = 0 }};
}}''')

    @property
    def max_significant_bytes(self):
        '''
        Maximum number of significant bytes needed to check the presence of any instruction.
        '''
        result = 0
        for insn, _ in self.insns:
            result = max(result, insn.decoder_signature.significant_bytes)
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
        return sorted(self.insns, key=lambda mi: -mi[0].decoder_signature.length)


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

    @property
    def insn_decoder_constraint(self):
        return self

    @property
    def kind(self):
        return self.mtype.kind

    def gen_LaTeX(self, m):
        '''
        Generates LaTeX description.  Updates map `m' if needed.  In m:
        'r' keeps the register count (0 initially)
        'v' stores the desired representation for the immediate arg
        '''
        pass


class PMImmediate(PMMachineArg, MachineLiteral):
    '''Literal number that is passed during 2OPM codegen'''
    def __init__(self, pmid : int, bits : int, signed : bool):
        self._docname = 's' if signed else 'u'
        PMMachineArg.__init__(self, pmid=pmid, mtype=MachineFormalImmediate.MAPPING[(bits, self._docname)])

    def gen_LaTeX(self, m):
        name = self._docname + str(self.mtype.bits)
        assert 'v' not in m
        m['v'] = name
        return name


class PMRegister(PMMachineArg):
    '''Literal register ID that is passed during 2OPM codegen'''
    def __init__(self, pmid : int):
        PMMachineArg.__init__(self, pmid=pmid, mtype=ASM_ARG_REG)

    def gen_LaTeX(self, m):
        n = m['r']
        m['r'] = n + 1
        return PMRegister.make_anonymous_regnames_subscript('$r' + str(n)) # '\\texttt{\\$r' + str(n) + '}'

    @staticmethod
    def make_anonymous_regnames_subscript(descr, anonymous_regnames = 4):
        for c in range(0, anonymous_regnames):
            descr = descr.replace('$r' + str(c), '$\\texttt{\\$r}_{' + str(c) + '}$')
        return descr


class PMPCRelative(PMMachineArg):
    '''PC-Relative Branch addres that is passed during 2OPM codegen'''
    def __init__(self, pmid : int):
        PMMachineArg.__init__(self, pmid=pmid, mtype=ASM_ARG_PCREL32S)

    def gen_LaTeX(self, m):
        return 'addr'

# PM ops take at most one literal parameter, so the following suffices:
I8U = PMImmediate(0, 8, False)
I32U = PMImmediate(0, 32, False)
I32S = PMImmediate(0, 32, True)
I64U = PMImmediate(0, 64, False)
I64S = PMImmediate(0, 64, True)

# Use as R(0), R(1), R(2) etc. to refer to distinct formal 2OPM parameters
R = PMRegister
PCREL32S = PMPCRelative(0)


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

    def __init__(self, name : str, descr,
                 args : list[PMMachineArg],
                 machine_code : MachineAssembly,
                 test=None):
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
        self.arg_index = {}

        arg_index_count = 0
        arg_type_counts = {}
        for arg in self.args:
            if arg is not None:
                self.arg_index[arg] = arg_index_count

                n = arg.mtype.hint
                if n not in arg_type_counts:
                    arg_type_counts[n] = 1
                else:
                    arg_type_counts[n] += 1
            arg_index_count += 1

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
    def assembly(self):
        return self.machine_code

    def arg_in_minsn(self, arg) -> list[tuple[MachineInsnInstance, int, MachineFormalArg]]:
        '''
        Results are:
        (minsn, offset-of-minsn-start (bytes), formal-arg-in-minsn)
        '''
        offset = 0
        results = []
        for minsn_instance in self.assembly.machine_insns:
            for arg2, minsn_formal in minsn_instance.pm_formals:
                if arg == arg2:
                    results.append((minsn_instance, offset, minsn_formal))
            offset += len(minsn_instance)
        return results

    @property
    def exclusive_regions(self) -> list[PMMachineArg, tuple[int, int], tuple[MachineInsnInstance, int, MachineFormalArg]]:
        '''
        Iterates over all exclusive regions in the generated assembly code.

        The results include the 2opm argument and the machine instructions from
        which we derived the regions.

        Results are:
        (2opm_arg,
             (offset, length),
             (minsn, offset-of-minsn-start (bytes), formal-arg-in-minsn))
        '''
        for pm_arg in self.args:
            for mach_arginfo in self.arg_in_minsn(pm_arg):
                minsn, offset, mach_formal = mach_arginfo
                if mach_formal.exclusive_region is not None:
                    (start, length) = mach_formal.exclusive_region
                    yield (pm_arg, (start + offset, length), mach_arginfo)

    # @property
    # def arg_bindings(self) -> list[tuple[PMMachineArg, MachineInsnInstance, int, MachineFormalArg]]:
    #     '''
    #     Iterates over all machine formal arguments, including their context
    #     '''
    #     for pmarg in self.args:
    #         for minsni, insn_offset, mach_formal in self.arg_in_minsn(arg):
    #             yield (pmarg, minsni, insn_offset, mach_formal)

    @property
    def machine_insns_args_nr(self):
        '''
        Total number of arguments passed to MachineInsnInstances that make up
        this Insn
        '''
        return sum(len(minsn.formals) for minsn in self.machine_code.machine_insns)

    def argname(self, arg):
        return self.arg_name[arg]

    def argindex(self, arg):
        return self.arg_index[arg]

    @property
    def c_emit_fn(self):
        return Insn.emit_prefix + self.function_name

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
        prln(self.c_emit_fn + '(' + ', '.join(["buffer_t *buf"] + arglist) + ')' + trail)

    @property
    def machine_code_len(self):
        return len(self.machine_code)

    def print_return_arg_offset(self, arg_nr, arg_to_c, prln=print):
        for arg in self.args:
            if arg.mtype.kind != "r":
                minsn_formals = self.arg_in_minsn(arg)
                offsets = [offset + minsn_formal.byte_span[0]
                           for (minsni, offset, minsn_formal) in minsn_formals
                           if minsn_formal.byte_span is not None]
                if offsets:
                    if len(minsn_formals) > 1:
                        raise Exception(f'Argument {arg} in {self.name} occurs more than once but wants to be relocatable')
                    prln(f'if ({arg_nr} == {self.argindex(arg)}) return {offsets[0]};')

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

        # ----------------------------------------
        # FIRST PASS: write bytes that are outside of exclusive regions
        exclusive = set()
        for _, exclusive_region, _ in self.exclusive_regions:
            exclusive |= set(range(exclusive_region[0], exclusive_region[0] + exclusive_region[1]))

        # Basic machine code generation: copy from machine code string and or in any suitable arg bits
        for offset in range(0, self.machine_code_len):
            if offset not in exclusive:
                p('data[%d] = %s;' % (offset, self.machine_code.generate_encoding_at(offset, self.argname)))

        # ----------------------------------------
        # SECOND PASS: write exclusive regions

        for pm_arg, exclusive_region, _ in self.exclusive_regions:
            pm_arg.mtype.print_generate_exclusive(exclusive_region, self.argname(pm_arg), 'data', prln=p)

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

    def gen_LaTeX_table(self):
        '''Returns list with the following elements (as LaTeX): [insn-name, args, short description]'''

        args = []
        m = { 'r' : 0 }
        for a in self.args:
            args.append(a.gen_LaTeX(m))

        valstr = m['v'] if 'v' in m else '?'

        descr = self.descr

        if type(descr) is not str:
            descr = self.descr.getDescription()

        descr = (descr
                 .replace('\\', '\\')
                 .replace('%v', '\\texttt{' + valstr + '}')
                 .replace('%a', '\\texttt{addr}'))

        anonymous_regnames = 4

        regnames = ['pc', 'sp', 'gp', 'fp']
        for (pfx, count) in [('a', 6), ('v', 1), ('t', 2), ('s', 4)]:
            for c in range(0, count + 1):
                regnames.append(pfx + str(c))

        for r in regnames:
            descr = descr.replace('$' + r, '\\texttt{\\$' + r + '}')

        descr = (descr
                 .replace('$$', '$')
                 .replace('_', '\\_'))

        descr = PMRegister.make_anonymous_regnames_subscript(descr)

        name = '\\textcolor{dblue}{\\textbf{\\texttt{' + self.name.replace('_', '\\_') + '}}}'

        return [name, ', '.join(args), descr]

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


class InsnDecoderConstraint:
    '''
    The most recently matched instruction must also satisfy some
    constraint on one of its arguments.
    '''
    def __init__(self, formal_index : int, mtype : MachineArgType):
        '''The formal index is based on all formal parameters to all MachineInsnInstances in this Insn.'''
        self.formal_index = formal_index
        self.mtype = mtype

    @property
    def info(self):
        return self.formal_index

    def c_arg(self, arg_nr : int, mtype=None):
        if mtype is None:
            mtype = self.mtype
        return 'args.buf[%d].%s' % (arg_nr, mtype.c_union_field)

    def gen_check(self):
        raise Exception('missing')

    def __eq__(self, other):
        return type(self) is type(other) and self.info == other.info

    def __hash__(self):
        return hash(self.info)


class InsnDecoderValueConstraint(InsnDecoderConstraint):
    '''
    A specific formal parameter must have a specific value
    '''
    def __init__(self, mtype, formal_index : int, value : int):
        InsnDecoderConstraint.__init__(formal_index, mtype)
        self.value = value

    def gen_check(self):
        return '%s == %s' % (self.c_arg(self.formal_index), self.mtype.gen_literal(self.value))

    @property
    def info(self):
        return (self.formal_index, self.nr)


class InsnDecoderEqConstraint:
    def __init__(self, mtype, formal_index : int, earlier_index : int):
        InsnDecoderConstraint.__init__(formal_index, mtype)
        self.earlier_index = earlier_index

    def gen_check(self):
        return '%s == %s' % (self.c_arg(self.formal_index), self.c_arg(self.earlier_index))

    @property
    def info(self):
        return (self.formal_index, self.earlier_index)


class InsnDecoderState:
    def __init__(self, nr, bytes_nr=None, insns_nr=None, args_nr=None):
        self.nr = nr

        # conclusion[0]: preconditions to satisfy before we can match
        # conclusion[1]: if we reach this point, this is the best instruction match so far
        # conclusion[2][n]: Which actual machine arg can we read the 2OPM arg at index #n from?
        self.conclusions : list[tuple[set[InsnDecoderConstraint], Insn, dict(int, int)]] = []
        self.bytes_nr : int = bytes_nr # number of bytes read until here
        self.insns_nr : int = insns_nr # number of instructions read until here
        self.args_nr : int = args_nr # number of machine arguments read until here
        self.fallback_state_nr : int = None # where to go if we couldn't match a local conclusion
        self.insn_out = {} # keys are machine insns

        self.forward_table_offset = None # start entry in the forward table

    def print_tests_matches_returns(self, c_stateptr : str, p, c_printf, mi_set : MachineInsnSet):
        '''
        Prints 'case' match, checks, match handling, and subsequent return operations.
        Is a no-op if the state has no conclusions.
        '''
        if not self.conclusions:
            return
        pp = p.indent()

        first_line = 'case %d:' % self.nr
        first_entry = True # nicer formatting

        # sort: most constrained first
        conclusions = sorted(self.conclusions, key=lambda concl: -len(concl[0]))
        for constraints, insn, register_map in conclusions:
            if constraints:
                check = '&&'.join('(%s)' % c.gen_check() for c in constraints)
                pp(f'if ({check}) {{')
                ppp = pp.indent()
                ppp_close = pp
            else:
                ppp = pp
                if first_entry:
                    first_line += '\t{'
                else:
                    ppp('{')
                ppp_close = p

            if first_entry:
                # print "case %d:" plus suffix, if appropriate
                p(first_line)
                first_entry = False

            formatstring = [f'{insn.name}\\t']
            varlist = []
            counter = 0
            for formal in insn.args:
                mtype = formal.mtype
                load_pos = register_map[insn.argindex(formal)]
                varname = 'v_' + insn.argname(formal)
                if counter > 0:
                    formatstring.append(', ')
                counter += 1

                mtype.print_prepare_c_format(varname,
                                             f'args.buf[{load_pos}].{mtype.c_union_field}',
                                             prln=ppp)
                #ppp(f'const {mtype.c_type} {varname} = };')
                formatstring.append(mtype.c_format_str)
                varlist.append(mtype.c_format_expr(varname))

            ppp(c_printf(['"%s"' % ''.join(formatstring)] + varlist))
            ppp('return byte_offset_current;')

            ppp_close('}')

        # unconditional conclusions
        unconditionals = [c for c in conclusions if len(c[0]) == 0]
        if len(unconditionals) == 0:
            # we might not match:
            pp('break;')
        if len(unconditionals) > 10:
            # Ambiguity detected:
            raise Exception('There are multiple possible parses for {self}: {[c[1] for c in unconditionals]}')

    @property
    def forward_table_is_trivial(self):
        return len(self.insn_out) == 0

    def forward_table_entries(self, mi_set : MachineInsnSet):
        return ([f'/* #{self.nr}: */']
                + [(mi_set.c_MACHINE_INSN(k), '%d' % v.nr)
                   for (k, v) in self.insn_out.items()]
                + [(0, 0)])


class InsnDecoderDFA:
    '''
    A DFA that encodes how to parse sequences of MachineInsnInstances into 2OPM Insns.

    Codegen:
    - state chart:
      represents parser state.  Each state has a fallback_state and a pointer
      into the forward table.
    - forward table:
      Contains pairs of (machine_insn_id, next_state), terminated by (0, 0)
    - forward parse loop:
      Goes forward through state chart to find the longest parse match.
    - backward detection loop:
      Goes backward through fallback_states, checking conditions to identify the
      most constrained match (if any) before reverting.
    '''

    C_CODEPTR = 'code'
    C_CODEMAXLEN = 'max_len'


    def __init__(self, mi_set, insns):
        self.states = []
        self.start = self.new_state(bytes_nr = 0, insns_nr = 0, args_nr = 0)
        self.mi_set = mi_set
        self.max_machine_code_len = 0 # longest instruction in terms of machine insns
        for insn in insns:
            self.add_insn(insn)
        self.link_fallbacks()

        # Forward table contains both strings and tuples of ints.
        # The strings are (property enclosed) comments.
        self.forward_table = []

        self.assemble_forward_table()

    @property
    def c_forward_table_elements_ty(self):
        if len(self.states) <= 0xffff:
            return 'unsigned short'
        return 'unsigned int'

    def new_state(self, **kwargs):
        '''
        Creates a fresh NFA state
        '''
        state = InsnDecoderState(len(self.states), **kwargs)
        self.states.append(state)
        return state

    def get_next_state(self, mapping, key):
        if key in mapping:
            return mapping[key]
        else:
            state = self.new_state()
            mapping[key] = state
            return state

    def add_insn(self, insn):
        self.max_machine_code_len = max(self.max_machine_code_len, len(insn.assembly.machine_insns))

        state = self.start
        marg_pos = 0 # counter for all machine args
        bytes_nr = 0
        insns_nr = 0
        args_nr = 0

        # PMMachineArg -> int (first arg that contains that arg)
        arg_first_read = {}

        all_constraints = set()
        for miinstance in insn.assembly.machine_insns:
            # first hop: machine instruction decoding
            minsn = miinstance.insn
            state = self.get_next_state(state.insn_out, minsn)

            bytes_nr += len(miinstance)
            state.bytes_nr = bytes_nr
            insns_nr += 1
            state.insns_nr = insns_nr
            args_nr += len(miinstance.formals)
            state.args_nr = args_nr

            # second hop: constraint decoding
            constraints = set([])
            for actual, formal in zip(miinstance.actuals, miinstance.formals):
                marg_nr = marg_pos
                marg_pos += 1

                bare_constraint = actual.insn_decoder_constraint
                if bare_constraint is None:
                    continue
                elif type(bare_constraint) is int:
                    # constraint: machine argument equal to constant
                    constraints.append(InsnDecoderValueConstraint(formal.mtype, marg_pos, bare_constraint))
                elif isinstance(bare_constraint, PMMachineArg):
                    # machine argument matches 2OPM argument
                    arg_index = insn.arg_index[bare_constraint]
                    if arg_index in arg_first_read:
                        # we have already read that argument, so we have a true equality constraint
                        constraints.append(InsnDecoderEqConstraint(formal.mtype, marg_pos, arg_first_read[arg_index]))
                    else:
                        # first time reading this argument
                        arg_first_read[arg_index] = marg_nr
                else:
                    raise Exception('unknown constraint %s' % bare_constraint)

            all_constraints |= constraints

        state.conclusions.append((all_constraints, insn, arg_first_read))

    def link_fallbacks(self):
        '''
        After adding all insns, back-link all states to their most recent ancestors that had at least one conclusion
        '''
        def link(ancestor):
            def linkto(current):
                current.fallback_state_nr = ancestor.nr
                for child in current.insn_out.values():
                    if current.conclusions:
                        link(current, child)
                    else:
                        # re-use ancestor
                        linkto(child)
            return linkto
        link(self.start)(self.start)

    def assemble_forward_table(self):
        '''
        Ensures that the last entry is { 0, 0 }
        '''
        offset = 0
        table = []
        for state in self.states:
            if not state.forward_table_is_trivial:
                state.forward_table_offset = offset
                entries = state.forward_table_entries(self.mi_set)
                # only count non-comment entries
                offset += len([e for e in entries if type(e) is tuple])
                table += entries
        terminal = offset - 1
        assert table[-1] == (0, 0)

        for state in self.states:
            if state.forward_table_is_trivial:
                state.forward_table_offset = terminal

        self.forward_table = table

    @property
    def c_forward_table(self):
        return f'{self.mi_set.c_arch_prefix}forward_table'

    @property
    def c_state_chart(self):
        return f'{self.mi_set.c_arch_prefix}state_chart'

    @property
    def c_state_chart_size(self):
        return f'{self.mi_set.c_arch_prefix}state_chart_states_nr'.upper()

    @property
    def c_state_chart_struct(self):
        return f'struct {self.c_state_chart}_struct'

    def print_forward_table(self, prln=print):
        prln(f'static {self.c_forward_table_elements_ty} {self.c_forward_table}[][2] = {{')
        def pr(entry, term=','):
            if type(entry) is str:
                prln(f'\t{entry}')
            else:
                prln(f'\t{{ {entry[0]}, {entry[1]} }}{term}')
        for e in self.forward_table[:-1]:
            pr(e)
        pr(self.forward_table[-1], term='')
        prln('};')

    def print_state_chart(self, prln=print):
	# unsigned short bytes_read;
	# unsigned short args_read;
        prln(f'''
#define {self.c_state_chart_size} {len(self.states)}

static {self.c_state_chart_struct} {{
	unsigned short fallback_state;
        unsigned short insns_read;
        {self.c_forward_table_elements_ty} (* forward_state)[2];
}} {self.c_state_chart}[{self.c_state_chart_size}] = {{''')

        last_state_nr = self.states[-1].nr
        for state in self.states:
            is_last_state = state.nr == last_state_nr
            prln(('\t{ .fallback_state = %d, '
                  #.bytes_read = %d,
                  + '.insns_read = %d, '
                  #+ '.args_read = %d, '
                  +'.forward_state = &(%s[%d]) }%s')
                 % (state.fallback_state_nr,
                    #state.bytes_nr,
                    state.insns_nr,
                    #state.args_nr,
                    self.c_forward_table, state.forward_table_offset,
                    '' if is_last_state else ','))
        prln('};')

    def print_forward_parse_loop(self, prln=print):
        c_codeptr = InsnDecoderDFA.C_CODEPTR
        c_codemaxlen = InsnDecoderDFA.C_CODEMAXLEN
        p = mkp(1, prln)
        p(f'''unsigned int state = 0;
        unsigned char* code_read_pos = {c_codeptr};
        size_t bytes_left = {c_codemaxlen};
        size_t byte_offset_current = 0;
        size_t byte_offsets[{1 + self.max_machine_code_len}]; // starting offset of each machine insn
        size_t byte_offsets_index = 0; // number of recognised machine insns
	{self.mi_set.c_machine_arg_t} args = {{ .read_offset = 0, .write_offset = 0 }};

        while (1) {{
		byte_offsets[byte_offsets_index++] = byte_offset_current;

        	{self.c_forward_table_elements_ty}(* forwards)[2] = {self.c_state_chart}[state].forward_state;
		if (0 == (*forwards)[0]) {{
        		break; // no need to parse further
		}}

		{self.mi_set.c_machine_insn_info_t} machinfo = {self.mi_set.c_disassemble_native_fn}(code_read_pos, bytes_left, &args);
		byte_offset_current += machinfo.size;

        	if (0 == machinfo.size) {{
			break; // end of input or could not parse insn, stop here
		}}
		while ((0 != (*forwards)[0]) && ((*forwards)[0] != machinfo.insn)) {{
			forwards += 1;
		}}
		if (0 == (*forwards)[0]) {{
			break; // no match for this instruction, we are done
		}}
		state = (*forwards)[1]; // found a match: continue
        }}''')

    def print_backward_detection_loop(self, c_printf, prln=print):
        p = mkp(1, prln)
        p(f'''while (0 != state) {{
		if (state >= AMD64_STATE_CHART_STATES_NR) {{
			fprintf(stderr, "Disassembler error: invalid state %d\\n", state);
        		return 0;
	        }}
                {self.c_state_chart_struct}* state_ptr = &({self.c_state_chart}[state]);

		switch (state) {{''')
        for s in self.states:
            s.print_tests_matches_returns('state_ptr', p.indent(), c_printf=c_printf, mi_set=self.mi_set)
        p('''	default:
			// fallback
			break;
		}
		// no match at this state: must backtrack
        	state = state_ptr->fallback_state;
		byte_offset_current = byte_offsets[state_ptr->insns_read];
	}
	return 0; // failure: no match''')


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

    def __len__(self):
        return len(self.insns)

    def print_disassembler_header(self, trail=';', prln=print):
        codeptr = InsnDecoderDFA.C_CODEPTR
        maxlen = InsnDecoderDFA.C_CODEMAXLEN
        prln(f'''size_t
disassemble_one(FILE* file, unsigned char* {codeptr}, size_t {maxlen}){trail}''')

    def print_disassembler(self, mi_set : MachineInsnSet, prln=print):
        max_machine_args_nr = max(insn.machine_insns_args_nr for insn in self)

        machine_arg_buf_mask = smallest_mask_for(max_machine_args_nr)
        mi_set.print_decoder_header(machine_arg_buf_mask, prln=prln)
        mi_set.print_decoder(prln=prln)
        prln('')

        dfa = self.build_dfa(mi_set)
        dfa.print_forward_table(prln=prln)
        dfa.print_state_chart(prln=prln)
        prln('')

        self.print_disassembler_header(trail='', prln=prln)
        prln('{')
        dfa.print_forward_parse_loop(prln=prln)

        def c_printf(strlist):
            return 'if (file) { fprintf(file, %s); }' % ', '.join(strlist)

        dfa.print_backward_detection_loop(c_printf=c_printf, prln=prln)
        prln('}')

    def build_dfa(self, mi_set : MachineInsnSet) -> InsnDecoderDFA:
        '''
        Builds NFA structure for decoding parsed instructions.
        '''
        return InsnDecoderDFA(mi_set, self.insns)

    def print_disassembler_doc(self, prln=print):
        prln('/**')
        prln(' * Disassembles a single assembly instruction and prlns it to stdout')
        prln(' *')
        prln(' * @param code: pointer to the instruction to disassemble')
        prln(' * @param max_len: max. number of viable bytes in the instruction')
        prln(' * @return Number of bytes in the disassembled instruction, or 0 on error')
        prln(' */')
