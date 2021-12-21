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

class BitPattern:
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
        body = BitPattern.gen_shr(varname, total_rightshift)

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
        return BitPattern.gen_shr('(%s & 0x%02x)' % (byte, self.mask_in), self.encoded_bitpos - self.decoded_bitpos)


class SingleBytePattern:
    '''
    SingleBytePattern: BitPattern plus byte position and bit shift.
    '''

    def __init__(self, byte_offset, bit_pattern : BitPattern):
        '''
        byte_offset: which byte the BitPattern is valid for
        '''

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
        return SingleBytePattern(byte_offset, BitPattern(encoded_bitpos, decoded_bitpos, bits_nr))

    def gen_encoding_at(self, src, offset):
        '''
        Returns part of the encoding code for the value "src", for output byte at "offset".

        If the current BytePattern does not contribute to that byte, return None.
        '''
        return None if offset != self.byte_pos else self.pattern.gen_encoding(src)

    def gen_decoding(self, access):
        '''
        Returns decoding code for this byte pattern.

        @param access A function that maps a byte offset (int) to a string
               that represents that byte in the generated code.

        If the current BytePattern does not contribute to that byte, return None.
        '''
        return self.pattern.gen_decoding(access(self.byte_pos))


class MultiBytePattern:
    '''
    Combination of multiple SingleBytePattern objects that together encode a number across multiple patterns (specified in order)
    '''
    def __init__(self, *patterns):
        self.bit_patterns = list(patterns)
        self.bit_patterns.reverse
        # self.atbit = dict()

        bitoffset = 0
        for bp in self.bit_patterns:
            assert isinstance(bp, SingleBytePattern)
            assert not isinstance(bp, MultiBytePattern)

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
            patterns.append(SingleBytePattern.at(byte_offset, enc_bitpos, decode_bitpos, bits_nr))
            decode_bitpos += bits_nr
        return MultiBytePattern(*patterns)


class Arg:
    '''
    Represents a formal parameter to a machine instruction.
    '''

    def setName(self, name):
        self.name = name

    def strName(self):
        return self.name

    def strGenericName(self):
        '''
        Returns a string that gives human readers a hint towards the type of the parameter
        '''
        return None

    def getExclusiveRegion(self):
        '''
        Determines whether the argument fully determines the contents of a particular sequence of bytes in this instruction.

        @return None or (min_inclusive, max_inclusive)
        '''
        return None

    def inExclusiveRegion(self, offset):
        exreg = self.getExclusiveRegion()
        if exreg is not None:
            (min_v, max_v) = exreg
            return offset >= min_v and offset <= max_v

    def maskOut(self, offset):
        if self.inExclusiveRegion(offset):
            return 0x00
        return 0xff

    def getBuilderFor(self, offset):
        return None

    def getKind(self):
        '''returns "r" (register), "i" (immediate) or "a" (address), used for testing '''
        raise Exception()

    def printCopyToExclusiveRegion(self, dataptr):
        pass

    def printDisassemble(self, dataptr, offset_shift, p):
        '''
        prints C code to diassemble this particular argument

        @param p: print function
        @param offset_shift: Tatsaechliche Position ist offset_shift + eigenes-offset; negative Positionen sind ungueltig
        @return a tuple ([printf format strings], [args to format strings])
        '''
        return ([], [])

    def isDisabled(self):
        return False

    def genLatex(self, m):
        '''
        Generates LaTeX description.  Updates map `m' if needed.  In m:
        'r' keeps the register count (0 initially)
        'v' stores the desired representation for the immediate arg
        '''
        pass

    def getType(self):
        '''Returns the type (ASM_ARG_*) for reflection purposes'''
        pass

    def validate(self, arg):
        '''Confirms that the specified arg is of a valid type'''
        raise Exception('Abstract "validate" operation won\'t accept any arguments')

    def try_inline(self, machine_code, arg):
        return None


class PCRelative(Arg):
    '''
    Represents an address parameter to an Insn and describes how the register number is encoded.
    '''

    def __init__(self, byte, width, delta):
        self.byte = byte
        self.width = width
        self.delta = delta

    def getExclusiveRegion(self):
        return (self.byte, self.byte + self.width - 1)

    def strGenericName(self):
        return 'label'

    def strType(self):
        return 'label_t *'

    def getKind(self):
        return 'a'

    def printCopyToExclusiveRegion(self, p, dataptr):
        p('%s->label_position = %s + %d;' % (self.strName(), dataptr, self.byte))
        p('%s->base_position = %s + machine_code_len;' % (self.strName(), dataptr))
        #p('int %s_offset = (char *)data + %d - (char *)%s;' % (self.strName(), self.delta, self.strName()))
        #p('memcpy(%s + %d, &%s_offset, %d);' % (dataptr, self.byte, self.strName(), self.width))

    def printDisassemble(self, dataptr, offset_shift, p):
        if (self.byte + offset_shift < 0):
            return
        p('int relative_%s;'% self.strName())
        p('memcpy(&relative_%s, data + %d, %d);' % (self.strName(), self.byte, self.width))
        p('unsigned char *%s = data + relative_%s + machine_code_len;' % (self.strName(), self.strName()))

        maxsize = 128
        p('char %s_buf[%d];' % (self.strName(), maxsize))
        if True:
            p('if (debug_address_lookup((void *) %s, &addr_prefix)) {' % self.strName())
            p('\tsnprintf(%s_buf, %d, "%%-10%s\t; %%s%%s", %s, addr_prefix, debug_address_lookup((void *) %s, NULL));' % (
                self.strName(), maxsize, 'p', self.strName(), self.strName()))
            p('} else {')
            p('\tsnprintf(%s_buf, %d, "%%%s", %s);' % (self.strName(), maxsize, 'p', self.strName()))
            p('}')
        else:
            p('snprintf(%s_buf, %d, "%%%s", %s);' % (self.strName(), maxsize, 'p', self.strName()))
        return (['%s'], ['%s_buf' % self.strName()])
        # return (["%p"], [self.strName()])

    def genLatex(self, m):
        return 'addr'

    def getType(self):
        return 'ASM_ARG_LABEL'


def make_anonymous_regnames_subscript(descr, anonymous_regnames = 4):
    for c in range(0, anonymous_regnames):
        descr = descr.replace('$r' + str(c), '$\\texttt{\\$r}_{' + str(c) + '}$')
    return descr


class Reg(Arg):
    '''
    Represents a register parameter to an Insn and describes how the register number is encoded.
    '''
    def __init__(self, bitpatterns):
        assert type(bitpatterns) is list
        self.bit_patterns = list(bitpatterns)
        self.bit_patterns.reverse()

    def getBuilderFor(self, offset):
        if offset in self.atbit:
            pats = self.atbit[offset]
            results = []
            name = self.strName()
            for (pat, bitoffset) in pats:
                results.append(pat.strExtract(name, bitoffset))
            return ' | '.join(results)
        return None

    def getKind(self):
        return 'r'

    def strGenericName(self):
        return 'r'

    def strType(self):
        return 'int'

    def printDisassemble(self, dataptr, offset_shift, p):
        decoding = []
        bitoffset = 0
        for pat in self.bit_patterns:
            offset = pat.byte_pos + offset_shift
            if (offset >= 0):
                decoding.append('(' + pat.str_decode(dataptr + '[' + str(offset) + ']') + ('<< %d)' % bitoffset))
            bitoffset += pat.bits_nr
        p('int %s = %s;' % (self.strName(), ' | ' .join(decoding)))
        return (['%s'], ['register_names[' + self.strName() + '].mips'])

    def genLatex(self, m):
        n = m['r']
        m['r'] = n + 1
        return make_anonymous_regnames_subscript('$r' + str(n)) # '\\texttt{\\$r' + str(n) + '}'

    def getType(self):
        return 'ASM_ARG_REG'

    def validate(self, arg):
        if not isinstance(arg, AbstractRegister):
            raise Exception('Register parameter required, but was passed %s' % type(arg))

    def try_inline(self, machine_code, arg):
        return None



class JointReg(Arg):
    '''
    Multiple destinations for a single register argument (no exclusive range)
    '''
    def __init__(self, subs):
        self.subs = subs

    def setName(self, name):
        self.name = name
        for n in self.subs:
            n.setName(name)

    def getExclusiveRegion(self):
        return None

    def getBuilderFor(self, offset):
        builders = []
        for n in self.subs:
            b = n.getBuilderFor(offset)
            if b is not None:
                builders.append(b)
        if builders == []:
            return None
        return ' | '.join('(%s)' % builder for builder in builders)

    def getKind(self):
        return 'r'

    def maskOut(self, offset):
        mask = 0xff
        for n in self.subs:
            mask = mask & n.maskOut(offset)
        return mask

    def strGenericName(self):
        return 'r'

    def strType(self):
        return 'int'

    def printDisassemble(self, dataptr, offset_shift, p):
        return self.subs[0].printDisassemble(dataptr, offset_shift, p)

    def genLatex(self, m):
        return self.subs[0].genLatex(m)

    def getType(self):
        return self.subs[0].getType()


class Imm(Arg):
    '''
    Represents an immediate value as parameter.

    name_lookup: should this number be looked up in the address store to check for special meanings?
    '''
    def __init__(self, ctype, docname, cformatstr, bytenr, bytelen, name_lookup=True, format_prefix=''):
        self.ctype = ctype
        self.docname = docname
        self.cformatstr = cformatstr
        self.bytenr = bytenr
        self.bytelen = bytelen
        self.name_lookup = name_lookup
        self.format_prefix = format_prefix

    def getKind(self):
        return 'i'

    def getExclusiveRegion(self):
        return (self.bytenr, self.bytenr + self.bytelen - 1)

    def strGenericName(self):
        return 'imm'

    def strType(self):
        return self.ctype

    def printCopyToExclusiveRegion(self, p, dataptr):
        p('memcpy(%s + %d, &%s, %d);' % (dataptr, self.bytenr, self.strName(), self.bytelen))

    def printDisassemble(self, dataptr, offset_shift, p):
        if (self.bytenr + offset_shift < 0):
            return
        p('%s %s;' % (self.ctype, self.strName()))
        p('memcpy(&%s, %s + %d, %d);' % (self.strName(), dataptr, self.bytenr + offset_shift, self.bytelen))
        maxsize = 128
        p('char %s_buf[%d];' % (self.strName(), maxsize))
        if (self.name_lookup):
            p('if (debug_address_lookup((void *) %s, &addr_prefix)) {' % self.strName())
            p('\tsnprintf(%s_buf, %d, "%s%%-10%s\t; %%s%%s", %s, addr_prefix, debug_address_lookup((void *) %s, NULL));' % (
                self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName(), self.strName()))
            p('} else {')
            p('\tsnprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
            p('}')
        else:
            p('snprintf(%s_buf, %d, "%s%%%s", %s);' % (self.strName(), maxsize, self.format_prefix, self.cformatstr, self.strName()))
        return (['%s'], ['%s_buf' % self.strName()])

    def genLatex(self, m):
        name = self.docname + str(self.bytelen * 8)
        assert 'v' not in m
        m['v'] = name
        return name

    def getType(self):
        return 'ASM_ARG_IMM' + str(self.bytelen * 8) + self.docname.upper()

class DisabledArg(Arg):
    '''
    Disables an argument.  The argument will still be pretty-print for disassembly (with the provided
    default value) but won't be decoded or encoded.
    '''
    def __init__(self, arg, defaultvalue):
        self.arg = arg
        self.arg.setName(defaultvalue)

    def getExclusiveRegion(self):
        return None

    def strGenericName(self):
        return self.arg.strGenericName()

    def printDisassemble(self, d, o, p):
        def skip(s):
            pass
        return self.arg.printDisassemble(d, o, skip)

    def isDisabled(self):
        return True

    def genLatex(self, m):
        return self.arg.genLatex(m)

def mkp(indent):
    '''Helper for indented printing'''
    def p(s):
        print(('\t' * indent) + s)
    return p


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

def ImmInt(offset):
    return Imm('int', 's', 'd', offset, 4, name_lookup = False)

def ImmUInt(offset):
    return Imm('unsigned int', 'u', 'x', offset, 4, name_lookup = False, format_prefix='0x')

def ImmByte(offset):
    return Imm('unsigned char', 'u', 'x', offset, 1, name_lookup = False, format_prefix='0x')

def ImmLongLong(offset):
    return Imm('long long', 's', 'llx', offset, 8, format_prefix='0x')

def ImmReal(offset):
    return Imm('double', 'f', 'f', offset, 8, name_lookup = False)


def make_registers(reg_specs : list[tuple[str, str]]):
    count = 0
    module = {}
    regs = []
    for regnative, reg2opm in reg_specs:
        reg = Register(regnative, reg2opm, count)
        module[regnative] = reg
        regs.append(reg)
        count += 1
    module['REGISTERS'] = regs
    return module


class Assembly:
    '''Abstract sequence of machine instructions for a specific architecture'''
    def __init__(self):
        pass

    @property
    def arch(self):
        raise Exception('Abstract')

    def generate(self):
        raise Exception('Abstract')

    def __add__(self, rhs):
        return AssemblySeq(self, rhs)

    def __radd__(self, rhs):
        return AssemblySeq(self, rhs)


class AssemblySeq(Assembly):
    '''Concrete sequence of machine instructions for a specific architecture'''
    def __init__(self, asms):
        seq = []
        arch = asms[0].arch

        for asm in asms:
            if type(asm) is AssemblySeq:
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


def MachineInsn(architecture : str):
    '''Factory for abstract instructions for one architecture'''
    def AbstractInsn(name, machine_code, formals):
        '''Factory for concrete uses of one machine instruction'''
        class Insn(Assembly):
            def __init__(self, *actuals):
                self.architecture = architecture
                self.name = name
                self.formals = formals
                self.actuals = actuals
                assert len(formals) == len(actuals)

                # unfilled_arguments : list[tuple(formal, actual)]: list of arguments that still need filling in
                unfilled_arguments : list[tuple(formal, actual)] = []

                for formal, actual in zip(formals, actuals):
                    fomal.validate(actual)
                    inlined = formal.try_inline(machine_code)
                    if inlined is None:
                        unfilled_arguments.append((formal, actual))
                    else:
                        machine_code = inlined

                self.unfilled_arguments = unfilled_arguments
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


        return Insn

    return AbstractInsn


class AbstractRegister:
    pass


class MachineRegister(AbstractRegister):
    def __init__(self, name : str, name2opm : str, num : int):
        self.num = num
        self.name = name
        self.name2opm = name2opm


class R(AbstractRegister):
    '''Register parameter from client code'''

    def __init__(self, num):
        self.num = num

    def for_formals(self, formals):
        return formals[self.num]


I = R
