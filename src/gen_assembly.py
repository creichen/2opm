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
        May consist of multiple MachineInsnInstances (= Assemblies).
        May select one of multiple different assemblies based on parameter choices.
        - Should not choose between different possible encodings for MachineInsnInstance, unless needed for correctness.
          (Selecting "better" encodings of the same MachineInsns we can add to MachineInsns later; this should be optional to use,
           i.e., use a different 'emit_opt_*()' function.  Disassembly should be strictly MachineInsn-side in that case.)
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

        bitoffset = 0
        for bp in self.bit_patterns:
            assert isinstance(bp, SingleByteEncoding)
            assert not isinstance(bp, MultiByteEncoding)

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
            span = self.pattern.span
            if span and span[1] == 1 and self.mtype.kind in ('i', 'a'):
                return None # not worth using memcpy for
            return span


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

    @staticmethod
    def ensure_assembly(assembly):
        if isinstance(assembly, MachineAssembly):
            return assembly
        if isinstance(assembly, list):
            return MachineAssemblySeq(assembly)
        raise Exception('Not a MachineAssembly: %s' % type(assembly))

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

    def generate_encoding_at(self, offset, arg_encode):
        '''
        @param offset : int  byte offset to encode at
        @param arg_encode : PMArgument -> string  map 2OPM args to C expressions
        '''
        minsn_offset = 0
        for masm in self.seq:
            if offset >= minsn_offset and offset < minsn_offset + len(masm):
                # found it
                return masm.generate_encoding_at(offset - minsn_offset, arg_encode)
            minsn_offset += len(masm)

    def __str__(self):
        return '<%s>' % ('+'.join(str(s) for s in self.seq))

    def __len__(self):
        total = 0
        for mc in self.seq:
            total += len(mc)

        return total


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


class MachineCode(list):
    '''
    Byte sequence to represent machine code
    '''
    def __init__(self, *args):
        list.__init__(self, *args)

    @staticmethod
    def validate(machine_code_raw, formals : list[MachineFormalArg], name='unknown machine instruction'):
        def fail(s):
            raise Exception('While validating machine code (%s of type %s) for machine insn %s: %s' % (machine_code_raw, type(machine_code_raw), name, s))

        def string_machine_code(mcraw):
            def binary(encoding):
                fail('Not implemented yet')

            def hex(encoding):
                result = []
                exclusives = [] # exclusive regions as per machine code

                if len(encoding) & 1:
                    fail('Odd number of hex digits')
                for n in range(0, len(encoding), 2):
                    s = encoding[n:n+2]
                    if s == '##':
                        exclusives.append(n//2)
                        result.append(0)
                    else:
                        try:
                            result.append(int(s, 16))
                        except:
                            fail('Could not parse hex digits for byte #%d: %s' % (n // 2, s))

                expected_exclusives = [] # exclusive regions as per formals
                for f in formals:
                    span = f.pattern.span
                    if span:
                        for n in range(span[0], span[0] + span[1]):
                            expected_exclusives.append(n)
                    expected_exclusives.sort()

                if expected_exclusives != exclusives:
                    fail('Disagreement on exclusive (usually immediate) args: bytes expected in hex encoding=%s; bytes expected by formal arguments=%s' % (exclusives, expected_exclusives))

                return result

            if mcraw.startswith('b:'):
                encoding = binary
            elif mcraw.startswith('x:'):
                encoding = hex
            else:
                fail('Unknown encoding for string-encoded machine code')

            s = mcraw[2:]
            for b in ' _+':
                s = s.replace(b, '')

            return encoding(s)

        if type(machine_code_raw) is str:
            machine_code = string_machine_code(machine_code_raw)
        elif type(machine_code_raw) is list:
            machine_code = machine_code_raw
        elif type(machine_code_raw) is MachineCode:
            return machine_code_raw
        else:
            fail('Unknown/unsupported type for machine code')

        return MachineCode(machine_code)


def MachineInsnFactory(architecture : str, target_dict=None):
    '''
    Factory for abstract instructions for one architecture

    Returns (MachineInsnSet, (name, list[int], list[formals]) -> MachineInsn)
    '''
    mset = MachineInsnSet(architecture, [])
    def make(name, formals, machine_code_raw):
        '''
        Factory for MachineInsns.

        @param name: Name of MachineInsn.  Added to "target_dict".
                     The internal name for the MachineInsn will only include
                     parts of "name" that are before the first '.', if any.
        @param formals: List of MachineFormalArg.
        @param machine_code_raw: A suitable machine code encoding, with
               all bits mapped to formals set to zero.
               Options:
               - list of bytes
               - string encoding (may use '_', '+', ' ' as purely visual separators):
                 - binary: 'b:11010110'.
                           Only '1', '0'. 'a', 'b', 'c', 'i' are also
                           allowed and map to 0:
                           - 'a': first register arg
                           - 'b': second register arg
                           - 'c': third register arg
                           - 'i': immediate arg
                 - hexadecimal: 'x:0f05'
                           Only hex digits and '##' allowed
                           - '##': exclusive byte
        '''
        longname = name
        suffix = ''
        if '.' in name:
            name, suffix = name.split('.', 1)
            suffix = '_' + suffix
        machine_code = MachineCode.validate(machine_code_raw, formals, name=longname)
        insn = MachineInsn(architecture, name, machine_code, formals)
        if target_dict:
            target_dict[name + suffix] = insn
        mset.append(insn)
        return insn
    return (mset, make)

# ----------------------------------------
# MachineAssemblyCond
#
# Temporary objects used while generating InsnMachineEncodingCond() objects

class MachineAssemblyCond:
    '''
    Multiple different assemblies, at least some of which are guarded by conditionals
    '''
    def __init__(self, branches):
        normalised_branches = []
        for b in branches:
            if isinstance(b, MachineAssemblyCondBranch):
                normalised_branches.append(b)
            else:
                normalised_branches.append(MachineAssemblyCondLabel(True, b))
        self.branches = normalised_branches


class MachineAssemblyCondBranch:
    def __init__(self, condition, code, to_label=None, of_label=None):
        '''
        @param: either True or InsnArgUnresolvedEqConstraint
        '''
        self.code = None if code is None else MachineAssembly.ensure_assembly(code)
        self.condition = condition
        self.to_label = to_label
        self.of_label = of_label
        assert to_label or code

    @property
    def condition_set(self):
        return MachineAssemblyCondBranch.condset(self.condition)

    @staticmethod
    def condset(cond) -> set[tuple[object, object]]:
        if cond is True:
            return set()

        def is_constant(v):
            return type(v) is int

        if is_constant(cond.lhs):
            return set([(cond.rhs, cond.lhs)])
        if is_constant(cond.rhs):
            return set([(cond.lhs, cond.rhs)])

        return set([(cond.lhs, cond.rhs), (cond.rhs, cond.lhs)])


class MachineAssemblyCondLabel:
    def __init__(self, label):
        MachineAssembly.__init__(self)
        self.label = label

    def eq(self, other):
        return self.label == other.label

    def hash(self):
        return hash(self.label)

    def __rshift__(self, code):
        '''labelled assembly'''
        if isinstance(code, MachineAssembly) or isinstance(code, list):
            return MachineAssemblyCondBranch(True, code, of_label=self)
        if isinstance(code, MachineAssemblyCondBranch):
            if code.to_label is None:
                code.to_label = self
                return code
            raise Exception('Cannot have multiple labels naming same code fragment')
        raise Exception('Unsupported argument: %s' % type(code))

    def __str__(self):
        return self.label


class InsnArgUnresolvedEqConstraint:
    def __init__(self, lhs, rhs, rhs_name=None):
        self.lhs = lhs
        self.rhs = rhs
        self.rhs_name = rhs_name if rhs_name is not None else ('%s' % rhs)

    def __bool__(self):
        '''
        Conservatively determine truth
        '''
        return self.lhs is self.rhs

    def gen(self, insn):
        def encode(v):
            if isinstance(v, PMRegister):
                return insn.argname(v)
            if isinstance(v, MachineRegister):
                return '%s' % v.num
            if isinstance(v, int):
                return '%s' % v
            raise Exception('Not sure how to handle %s' % type(v))
        return f'{encode(self.lhs)} == {encode(self.rhs)}'

    def __rshift__(self, code):
        if isinstance(code, MachineAssemblyCondLabel):
            return MachineAssemblyCondBranch(self, None, to_label=code)
        return MachineAssemblyCondBranch(self, code)


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

    @staticmethod
    def make(arch: str, target_dict=None):
        '''
        See MachineInsnFactory.make for arguments.

        Returns:
        (MachineInsnSet, (str, list[MachineFormalArg], bin) -> MachineInsn)
        '''
        return MachineInsnFactory(arch, target_dict)

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
        	pattern |= ((uint64_t)code[i]) << (i << 3);
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

    def __eq__(self, other):
        if type(other) == type(self) and other.pmid == self.pmid:
            return True
        if isinstance(other, PMRegister):
            return InsnArgUnresolvedEqConstraint(self, other)
        if isinstance(other, MachineRegister):
            return InsnArgUnresolvedEqConstraint(self, other.num, other.name)
        return False


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

class InsnMachineEncoding:
    '''
    Encoding of a 2OPM instruction into machine code.

    Bridges the different styles of assemblies with code generation and instruction decoding.
    '''
    def __init__(self, insn):
        self.insn = insn

    @staticmethod
    def make(insn, code):
        if isinstance(code, MachineAssemblyCond):
            return InsnMachineEncodingCond(insn, code)
        if isinstance(code, MachineAssembly):
            return InsnMachineEncodingSimple(insn, code)
        if isinstance(code, list):
            return InsnMachineEncodingSimple(insn, MachineAssembly.ensure_assembly(code))

    def print_encoder_header(self, c_emit_fn, trail=';', static=False, prln=print):
        if static:
            prln('static void')
        else:
            prln('void')
        prln(c_emit_fn + '(' + self.c_encoder_args() + ')' + trail)

    def c_encoder_args(self, types=True):
        arglist = []
        for arg in self.insn.args:
            typeinfo = (arg.mtype.c_type + ' ') if types else ''
            arglist.append(typeinfo + self.insn.argname(arg))
        return ', '.join([('buffer_t* ' if types else '') + 'buf'] + arglist)

    def c_constant_value_for(self, arg):
        '''
        What value, if any, is the arg hardwired to in this encoding?
        '''
        return None

    def aliases_for(self, arg):
        '''
        What aliases does this argument have in this encoding?
        '''
        return []


class InsnMachineEncodingSimple(InsnMachineEncoding):
    '''
    Unconditional encoding of a 2OPM instruction into machine code
    '''
    def __init__(self, insn, assembly : MachineAssembly, constraints=None):
        InsnMachineEncoding.__init__(self, insn)
        self.assembly = assembly
        self.constraints = constraints

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
        for pm_arg in self.insn.args:
            for mach_arginfo in self.arg_in_minsn(pm_arg):
                minsn, offset, mach_formal = mach_arginfo
                if mach_formal.exclusive_region is not None:
                    (start, length) = mach_formal.exclusive_region
                    yield (pm_arg, (start + offset, length), mach_arginfo)

    @property
    def machine_code(self):
        return self.assembly

    @property
    def machine_code_len(self):
        return len(self.machine_code)

    @property
    def machine_encodings(self):
        return [self]

    def print_encoder(self, c_emit_fn, static=False, prln=print):
        self.print_encoder_header(c_emit_fn=c_emit_fn, static=static, trail='', prln=prln)
        prln('{')
        p = mkp(1, prln)
        p('const int machine_code_len = %d;' % self.machine_code_len)
        p('unsigned char *data = buffer_alloc(buf, machine_code_len);')

        # ----------------------------------------
        # FIRST PASS: write bytes that are outside of exclusive regions
        exclusive = set()
        for _, exclusive_region, _ in self.exclusive_regions:
            exclusive |= set(range(exclusive_region[0], exclusive_region[0] + exclusive_region[1]))

        # Basic machine code generation: copy from machine code string and or in any suitable arg bits
        for offset in range(0, self.machine_code_len):
            if offset not in exclusive:
                p('data[%d] = %s;' % (offset, self.machine_code.generate_encoding_at(offset, self.insn.argname)))

        # ----------------------------------------
        # SECOND PASS: write exclusive regions

        for pm_arg, exclusive_region, _ in self.exclusive_regions:
            pm_arg.mtype.print_generate_exclusive(exclusive_region, self.insn.argname(pm_arg), 'data', prln=p)

        prln('}')

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
    def machine_insns_args_nr(self):
        '''
        Total number of arguments passed to MachineInsnInstances that make up
        this Insn
        '''
        return sum(len(minsn.formals) for minsn in self.machine_code.machine_insns)

    def arg_offset(self, arg):
        '''
        Gets the argument offset, if there is a byte offset for the argument
        '''
        if arg.mtype.kind != "r":
            minsn_formals = self.arg_in_minsn(arg)
            offsets = [offset + minsn_formal.byte_span[0]
                       for (minsni, offset, minsn_formal) in minsn_formals
                       if minsn_formal.byte_span is not None]
            if offsets:
                if len(minsn_formals) > 1:
                    raise Exception(f'Argument {arg} in {self.insn.name} occurs more than once but wants to be relocatable; %s' % (minsn_formals))
                return offsets[0]

    def c_constant_value_for(self, arg):
        if self.constraints is None:
            return None
        for (k, v) in self.constraints:
            if k == arg and type(v) is int:
                return arg.mtype.gen_literal(v)
        return None

    def aliases_for(self, arg):
        if self.constraints is None:
            return []
        return [a for (r, a) in self.constraints if r == arg]


class InsnMachineEncodingCond(InsnMachineEncoding):
    '''
    Encoding of a 2OPM instruction into multiple alternative machine code variants
    '''
    def __init__(self, insn, cond_assembly : MachineAssemblyCond):
        InsnMachineEncoding.__init__(self, insn)
        named_options_map = {}

        def ensure(prop, msg):
            if not prop:
                raise Exception('Insn(%s).cond(): %s' % (self.insn.name, msg))

        for branch in cond_assembly.branches[:-1]:
            ensure(branch.condition is not True, 'Unconditional branches must come last (%s)' % branch.code)
        ensure(cond_assembly.branches[-1].condition is True, 'Last branch must be unconditional')

        self.options : list[InsnMachineEncodingSimple] = []
        branches = []

        # First:
        # - Collect all instances of actual code
        # - Mark order of branches
        for branch in cond_assembly.branches:
            if branch.code:
                index = len(self.options)
                if branch.of_label:
                    label = branch.of_label.label
                    ensure(label not in named_options_map, 'Label %s defined more than once' % label)
                    named_options_map[label] = index
                # While adding option, also track condition
                self.options.append(InsnMachineEncodingSimple(insn, branch.code, constraints=branch.condition_set))
                branches.append((branch.condition, index))
            else:
                ensure(not branch.of_label, 'Label %s names a branch that contains no code' % branch.of_label)
                ensure(branch.to_label, 'Empty branch?  Internal bug?')
                branches.append((branch.condition, branch.to_label.label))

        # Second:
        # - Resolve branches identified by labels
        self.branches = []
        for branchcond, branchcode_index in branches:
            if type(branchcode_index) is str:
                ensure(branchcode_index in named_options_map, 'Reference to undefined label %s' % branchcode_index)
                branchcode_index = named_options_map[branchcode_index]
                # Attach condition; we only allow conditions that are true on ALL branches to this
                # encoding
                self.options[branchcode_index].constraints &= MachineAssemblyCondBranch.condset(branchcond)
            self.branches.append((branchcond, branchcode_index))


    @property
    def machine_encodings(self) -> list[InsnMachineEncoding]:
        return self.options

    def print_encoder(self, c_emit_fn, static=False, prln=print):
        option_names = []

        # First emit support functions
        for option in self.options:
            c_emit_option_fn = c_emit_fn + ('__%d' % len(option_names))
            option_names.append(c_emit_option_fn)
            option.print_encoder(c_emit_option_fn, static=True, prln=prln)

        self.print_encoder_header(c_emit_fn=c_emit_fn, static=static, trail='', prln=prln)

        args = self.options[0].c_encoder_args(types=False) # must be the same for all of them

        prln('{')
        p = mkp(1, prln)

        for (cond, index) in self.branches:
            if cond is True:
                pp = p
            else:
                p(f'if ({cond.gen(self.insn)}) {{')
                pp = mkp(2, prln)

            pp(f'return {option_names[index]}({args});')

            if cond is not True:
                p('}')

        prln('}')


class InsnMeta(type):
    '''
    Metaclass for Insn, used to simplify metaprogramming.
    '''
    def __matmul__(_, label):
        return MachineAssemblyCondLabel(label)


class Insn(metaclass=InsnMeta):
    '''
    2OPM instruction, which is then mapped to machine instructions.

    Constructing an Insn requires specifying the machine code instructions as a
    MachineAssembly.  For some instructions, we need multiple alternative
    encodings due to limitations of the target ISA.  These can be specified
    with a DSL:

    Insn.cond(  branch, ..., branch  )

    where "branch" has the form

    branch ::= [ label '>>' ] [ cond '>>' ] asm
             | cond '>>' label
    label ::= 'Insn@' string
    cond ::= arg '==' arg
           | arg '==' MachineRegister
           | arg '==' int
    asm ::= MachineAssembly
          | '[' MachineAssembly ',' ... ',' MachineAssembly ']'


    Example:

    Insn.cond(
        (R(0) == amd64.rax)  >>  Insn@'default',          # A
        (R(0) == R(1))       >>  amd64.SHL_ri(R(0), 1),   # B
        Insn@'default'       >>  amd64.ADD_rr(R(0), R(1)) # C
    )

    # C: This instruction will default to adding its R(0) and R(1)
         registers.
    # B: There is one exception: if both registers are the same, then
         the generated code will instead shift that register left by one.
    # A: However, exception #B does not apply if R(0) is the RAX register,
         in wich case we emit the same code as in #C.
    '''
    emit_prefix = LIB_PREFIX + "emit_"

    def __init__(self, name : str, descr,
                 formals : list[PMMachineArg],
                 machine_encodings,
                 format=None,
                 test=None):
        '''
        @param machine_encoding: MachineAssembly, list[MachineAssembly], or MachineAssemblyCond.
        @param format: change the disassembly format away from comma-separated to the format presented there,
                       Must include one '%s' per formal argument.
        '''
        self.name = name
        self.descr = descr
        self.function_name = name
        self.is_static = False
        self.format = format
        self.machine_encoding : InsnMachineEncoding = InsnMachineEncoding.make(self, machine_encodings)
        self.args = formals
        args = formals
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

    @staticmethod
    def cond(*cond_assemblies):
        return MachineAssemblyCond(cond_assemblies)

    @property
    def machine_encodings(self):
        return self.machine_encoding.machine_encodings

    def argname(self, arg):
        if arg not in self.arg_name:
            raise Exception(f'Insn {self.name} uses argument {arg} without listing it as a parameter')
        return self.arg_name[arg]

    def argindex(self, arg):
        return self.arg_index[arg]

    @property
    def c_emit_fn(self):
        return Insn.emit_prefix + self.function_name

    def arg_offset(self, arg):
        results = [mencoding.arg_offset(arg) for mencoding in self.machine_encodings]
        result = results[0]
        for r in results[1:]:
            if r != result:
                return None
        return result

    def print_encoder_header(self, trail=';', prln=print):
        arglist = []
        for arg in self.args:
            arglist.append(arg.mtype.c_type + ' ' + self.argname(arg))
        if self.is_static:
            prln('static void')
        else:
            prln('void')
        prln(self.c_emit_fn + '(' + ', '.join(["buffer_t* buf"] + arglist) + ')' + trail)


    def print_encoder(self, prln=print):
        self.machine_encoding.print_encoder(c_emit_fn=self.c_emit_fn, prln=prln)

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


class InsnArgConstraint:
    '''
    An instruction must also satisfy some constraint on one of its arguments.
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


class InsnArgValueConstraint(InsnArgConstraint):
    '''
    A specific formal parameter must have a specific value
    '''
    def __init__(self, mtype, formal_index : int, value : int):
        InsnArgConstraint.__init__(self, formal_index, mtype)
        self.value = value

    def gen_check(self):
        return '%s == %s' % (self.c_arg(self.formal_index), self.mtype.gen_literal(self.value))

    @property
    def info(self):
        return (self.formal_index, self.value)


class InsnArgEqConstraint(InsnArgConstraint):
    def __init__(self, mtype, formal_index : int, earlier_index : int):
        InsnArgConstraint.__init__(self, formal_index, mtype)
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
        self.conclusions : list[tuple[set[InsnArgConstraint], Insn, dict(int, int)]] = []
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

        p('case %d:' % self.nr)

        # sort: most constrained first
        conclusions = sorted(self.conclusions, key=lambda concl: -len(concl[0]))
        for constraints, insn, mencoding, register_map in conclusions:
            ppp = pp.indent()
            if constraints:
                print
                check = ' && '.join('(%s)' % c.gen_check() for c in constraints)
                pp(f'if ({check}) {{')
                ppp_close = pp
            else:
                pp('{')
                ppp_close = p

            formatstring_elements = []
            varlist = []
            def v_name(formal):
                return 'v_' + insn.argname(formal)

            for formal in insn.args:
                mtype = formal.mtype
                varname = v_name(formal)

                formatstring_elements.append(mtype.c_format_str)

                # Depending on whether we can extract the formal from the machine code or on
                # whether its value is implicit in the encoding, we now try multiple options.
                constant_value = mencoding.c_constant_value_for(formal)
                if constant_value is not None:
                    # We have a constant value, use that instead
                    varlist.append(mtype.c_format_expr(constant_value))
                elif insn.argindex(formal) not in register_map:
                    # Parameter should be implicitly aliased in this mencoding, use one of the aliases instead
                    aliases = mencoding.aliases_for(formal)
                    available_aliases = [alias for alias in aliases if insn.argindex(alias) in register_map]
                    if available_aliases == []:
                        raise Exception('Internal error: %s(%s) missing from register_map=%s' % (formal, insn.argindex(formal), register_map))
                    varlist.append(mtype.c_format_expr(v_name(available_aliases[0])))
                else:
                    # Default case: decode from machine encoding
                    load_pos = register_map[insn.argindex(formal)]

                    mtype.print_prepare_c_format(varname,
                                                 f'args.buf[{load_pos}].{mtype.c_union_field}',
                                                 prln=ppp)
                    varlist.append(mtype.c_format_expr(varname))

            if insn.format:
                formatstring = insn.format % tuple(formatstring_elements)
            else:
                formatstring = ', '.join(formatstring_elements)

            ppp(c_printf(['"%s\t%s"' % (insn.name, formatstring)] + varlist))
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
            for mencoding in insn.machine_encodings:
                self.add_insn(insn, mencoding)
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

    def add_insn(self, insn, mencoding):
        self.max_machine_code_len = max(self.max_machine_code_len, len(mencoding.assembly.machine_insns))

        state = self.start
        marg_pos = 0 # counter for all machine args
        bytes_nr = 0
        insns_nr = 0
        args_nr = 0

        # PMMachineArg -> int (first arg that contains that arg)
        arg_first_read = {}

        all_constraints = set()
        for miinstance in mencoding.assembly.machine_insns:
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
                    constraints |= set([(InsnArgValueConstraint(formal.mtype, marg_nr, bare_constraint))])
                elif isinstance(bare_constraint, PMMachineArg):
                    # machine argument matches 2OPM argument
                    arg_index = insn.arg_index[bare_constraint]
                    if arg_index in arg_first_read:
                        # we have already read that argument, so we have a true equality constraint
                        constraints |= set([(InsnArgEqConstraint(formal.mtype, marg_nr, arg_first_read[arg_index]))])
                    else:
                        # first time reading this argument
                        arg_first_read[arg_index] = marg_nr
                else:
                    raise Exception('unknown constraint %s' % bare_constraint)

            all_constraints |= constraints

        state.conclusions.append((all_constraints, insn, mencoding, arg_first_read))

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

		{self.mi_set.c_machine_insn_info_t} machinfo = {self.mi_set.c_disassemble_native_fn}(code + byte_offset_current, bytes_left, &args);
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
        max_machine_args_nr = max(mencoding.machine_insns_args_nr for insn in self for mencoding in insn.machine_encodings)

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
