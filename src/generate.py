#! /usr/bin/env python3
# This file is Copyright (C) 2014, 2020 Christoph Reichenbach
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
# The author can be reached as "creichen" at the usual gmail server.

# assume 16 registers total

import subprocess
import sys
import tempfile

try:
    from termcolor import colored
except:
    def colored(text, *col):
        return text


LIB_PREFIX = ''

class BitPattern(object):
    '''
    Represents part of a bit pattern string, which is used to encode information (specifically register data).

    We represent bit pattern strings as lists of BitPattern objects, from msb to lsb.

    byteid: offset into a byte string (first = 0)
    bitid: offset into the byte (lsb = 0)
    bits_nr: number of bits to encode starting at bitid (inclusive)
    '''
    def __init__(self, byteid, bitid, bits_nr):
        self.byteid = byteid
        self.bitid = bitid
        self.bits_nr = bits_nr

    def strExtract(self, varname, bitoffset):
        '''
        Generates code for extracting relevant bits from `varname', starting at its `bitoffset'
        '''
        total_rightshift = bitoffset - self.bitid
        body = varname
        if total_rightshift > 0:
            body = '(' + body + ' >> ' + str(total_rightshift) + ')'
        elif total_rightshift < 0:
            body = '(' + body + ' << ' + str(-total_rightshift) + ')'

        return '%s & 0x%02x' % (body, self.maskIn())

    def maskIn(self):
        mask = 0
        for i in range(0, self.bits_nr):
            mask = ((mask << 1) | 1)

        mask = mask << self.bitid
        return mask

    def maskOut(self):
        return 0xff ^ self.maskIn()

    def strDecode(self, byte):
        return '(' + byte + (' & 0x%02x' % self.maskIn()) + ') >> ' + str(self.bitid)


class Arg(object):
    '''
    Represents an argument to an instruction.
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
        self.atbit = dict()

        bitoffset = 0
        for bp in self.bit_patterns:
            if bp.byteid in self.atbit:
                self.atbit[bp.byteid].append((bp, bitoffset))
            else:
                self.atbit[bp.byteid] = [(bp, bitoffset)]
            bitoffset += bp.bits_nr

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

    def maskOut(self, offset):
        mask = 0xff
        try:
            for (pat, bitoffset) in self.atbit[offset]:
                mask = mask & pat.maskOut()
        except KeyError:
            pass
        return mask

    def strGenericName(self):
        return 'r'

    def strType(self):
        return 'int'

    def printDisassemble(self, dataptr, offset_shift, p):
        decoding = []
        bitoffset = 0
        for pat in self.bit_patterns:
            offset = pat.byteid + offset_shift
            if (offset >= 0):
                decoding.append('(' + pat.strDecode(dataptr + '[' + str(offset) + ']') + ('<< %d)' % bitoffset))
            bitoffset += pat.bits_nr
        p('int %s = %s;' % (self.strName(), ' | ' .join(decoding)))
        return (['%s'], ['register_names[' + self.strName() + '].mips'])

    def genLatex(self, m):
        n = m['r']
        m['r'] = n + 1
        return make_anonymous_regnames_subscript('$r' + str(n)) # '\\texttt{\\$r' + str(n) + '}'

    def getType(self):
        return 'ASM_ARG_REG'


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
        return None

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


class Insn(object):
    emit_prefix = LIB_PREFIX + "emit_"

    def __init__(self, name, descr, machine_code, args, test=None):
        self.name = name
        self.descr = descr
        self.function_name = name
        self.is_static = False
        self.machine_code = machine_code
        assert type(machine_code) is list
        self.args = args
        assert type(args) is list
        self.format_string = None # optional format string override
        self.test = test

        arg_type_counts = {}
        for arg in self.args:
            if arg is not None:
                n = arg.strGenericName()
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
                n = arg.strGenericName()
                if arg_type_multiplicity[n] > 1:
                    arg.setName(n + str(arg_type_counts[n]))
                    arg_type_counts[n] -= 1
                else:
                    arg.setName(n) # only one of these here

    def allEncodings(self):
        return [self]

    def getArgs(self):
        return self.args

    def printHeader(self, trail=';'):
        arglist = []
        for arg in self.args:
            if not arg.isDisabled():
                arglist.append(arg.strType() + ' ' + arg.strName())
        if self.is_static:
            print('static void')
        else:
            print('void')
        print(Insn.emit_prefix + self.function_name + '(' + ', '.join(["buffer_t *buf"] + arglist) + ')' + trail)

    def machineCodeLen(self):
        return '%d' % len(self.machine_code)

    def prepareMachineCodeLen(self, p):
        pass

    def postprocessMachineCodeLen(self, p):
        pass

    def initialMachineCodeOffset(self):
        return 0

    def printDataUpdate(self, p, offset, machine_code_byte, spec):
        p('data[%d] = 0x%02x%s;' % (offset, machine_code_byte, spec))

    def getConstructionBitmaskBuilders(self, offset):
        builders = []
        build_this_byte = True
        for arg in self.args:
            if arg is not None:
                if arg.inExclusiveRegion(offset):
                    return None

                builder = arg.getBuilderFor(offset)
                if builder is not None:
                    builders.append('(' + builder + ')')
        return builders

    def printOffsetCalculatorBranch(self, tabs, argarg):
        al = []
        for arg in self.args:
            exclusive_region = arg.getExclusiveRegion()
            if (exclusive_region):
                al.append('%d' % exclusive_region[0])
            else:
                al.append('-1')

        print((tabs + 'return ({arg} < 0 || {arg} >= {max})?-1: ((int[]){{ {offsets} }})[{arg}];'
               .format(arg=argarg, max=len(self.args),
                       offsets=', '.join(al))))

    def printGenerator(self):
        self.printHeader(trail='')
        print('{')
        p = mkp(1)
        self.prepareMachineCodeLen(p)
        p('const int machine_code_len = %s;' % self.machineCodeLen())
        p('unsigned char *data = buffer_alloc(buf, machine_code_len);')
        self.postprocessMachineCodeLen(p)

        # Basic machine code generation: copy from machine code string and or in any suitable arg bits
        offset = self.initialMachineCodeOffset()
        for byte in self.machine_code:
            builders = self.getConstructionBitmaskBuilders(offset)
            if builders is not None:
                if len(builders) > 0:
                    builders = [''] + builders # add extra ' | ' to beginning
                self.printDataUpdate(p, offset, byte, ' | '.join(builders))

            offset += 1

        for arg in self.args:
            if arg is not None:
                if arg.getExclusiveRegion() is not None:
                    arg.printCopyToExclusiveRegion(p, 'data')

        print('}')

    def printTryDisassemble(self, data_name, max_len_name):
        self.printTryDisassembleOne(data_name, max_len_name, self.machine_code, 0)

    def setFormat(self, string):
        self.format_string = string
        return self

    def printTryDisassembleOne(self, data_name, max_len_name, machine_code, offset_shift):
        checks = []

        offset = offset_shift
        for byte in machine_code:
            bitmask = 0xff
            for arg in self.args:
                if arg is not None:
                    bitmask = bitmask & arg.maskOut(offset)

            if bitmask != 0:
                if bitmask == 0xff:
                    checks.append('data[%d] == 0x%02x' % (offset - offset_shift, byte))
                else:
                    checks.append('(data[%d] & 0x%02x) == 0x%02x' % (offset - offset_shift, bitmask, byte))
            offset += 1

        assert len(checks) > 0

        p = mkp(1)
        p(('if (%s >= %d && ' % (max_len_name, len(machine_code))) + ' && '.join(checks) + ') {')
        pp = mkp(2)

        pp('const int machine_code_len = %d;' % len(machine_code));
        formats = []
        format_args = []
        for arg in self.args:
            if arg is not None:
                (format_addition, format_args_addition) = arg.printDisassemble('data', -offset_shift, pp)
                formats = formats + format_addition
                format_args = format_args + format_args_addition
        pp('if (file) {');
        if len(formats) == 0:
            pp('\tfprintf(file, "%s");' % self.name)
        else:
            format_string = ', '.join(formats)
            if self.format_string is not None:
                format_string = self.format_string % tuple(formats)
            pp(('\tfprintf(file, "%s\\t' % self.name) + format_string + '", ' + ', '.join(format_args) + ');');
        pp('}')
        pp('return machine_code_len;')
        p('}')

    def genLatexTable(self):
        '''Returns list with the following elements (as LaTeX): [insn-name, args, short description]'''

        args = []
        m = { 'r' : 0 }
        for a in self.args:
            args.append(a.genLatex(m))

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

        descr = make_anonymous_regnames_subscript(descr)

        name = '\\textcolor{dblue}{\\textbf{\\texttt{' + self.name.replace('_', '\\_') + '}}}'

        return [name, ', '.join(args), descr]



class InsnAlternatives(Insn):
    '''
    Multiple alternative instruction encodings wrapped into the same call
    '''
    def __init__(self, name, descr, default, options, test=None):
        '''
        name: Name of the joint instruction
        default: Default instruction encoding, a pair of (machine_code, args) as for Insn
        options: Alternative instrucion encodings, a tuple (cond, (machine_code, args)) where
                 "cond" is a C conditional that may refer to arguments (of the "default") by "{arg0}" .. "{argn}"

                 Alternative encodings may skip args (specify as "None").  Make sure to
                 maintain the order of the original argument list, though.
        '''
        Insn.__init__(self, name, descr, default[0], default[1], test=test)
        self.options = {opt : Insn(name, descr, machine_code, args) for (opt, (machine_code, args)) in options}

        name_nr = 0

        for o in self.options.values():
            o.is_static = True
            o.function_name = o.name + '__%d' % name_nr
            name_nr += 1

        self.default_option = Insn(name, descr, default[0], default[1])
        self.default_option.is_static = True
        self.default_option.function_name = self.default_option.name + '__%d' % name_nr

    def allEncodings(self):
        return list(self.options.values()) + [self]

    def setFormat(self, fmt):
        Insn.setFormat(self, fmt)
        for n in self.options.values():
            n.setFormat(fmt)
        self.default_option.setFormat(fmt);
        return self

    def printOffsetCalculatorBranch(self, tabs, argarg):
        print('{')
        argdict = {}
        count = 0
        for arg in self.args:
            n = arg.strGenericName()
            argdict['arg%d' % count] = 'args[%d].%s' % (count, n)
            count += 1
        for (condition, option) in self.options.items():
            print((tabs + 'if (%s)' % (condition.format(**argdict))))
            option.printOffsetCalculatorBranch('\t' + tabs, argarg)
        self.default_option.printOffsetCalculatorBranch(tabs, argarg)
        print('{t}}}'.format(t = tabs))

    def printGenerator(self):
        self.default_option.printGenerator()
        print('')
        for o in self.options.values():
            o.printGenerator()
            print('')

        # Print selection function
        arglist = []
        argdict = {}
        count = 0
        for arg in self.args:
            n = arg.strName()
            argdict['arg%d' % count] = n
            arglist.append(n)
            count += 1

        def invoke(insn):
            ma = ['buf']
            mc = 0
            for arg in insn.args:
                if not arg.isDisabled():
                    ma.append(arglist[mc])
                mc += 1
            return Insn.emit_prefix + insn.function_name + '(' + ', '.join(ma) + ');'

        self.printHeader(trail='')
        print('{')
        p = mkp(1)
        pp = mkp(2)
        for (condition, option) in self.options.items():
            p('if (%s) {' % (condition.format(**argdict)))
            pp(invoke(option));
            pp('return;')
            p('}')
        # otherwise default
        p(invoke(self.default_option))
        print('}')

    def getArgs(self):
        return self.default_option.getArgs()

    def printLatex(self, m):
        return self.default_option.printLatex(m)


class OptPrefixInsn (Insn):
    '''
    An instruction that permits an optional prefix byte.
    This byte is generated iff one bit in byte -1 must be set to nonzero.
    '''

    def __init__(self, name, descr, opt_prefix, machine_code, args, test=None):
        Insn.__init__(self, name, descr, [opt_prefix] + machine_code, args, test)
        self.opt_prefix = opt_prefix

    def machineCodeLen(self):
        return Insn.machineCodeLen(self) + ' - 1 + data_prefix_len';

    def prepareMachineCodeLen(self, p):
        p('int data_prefix_len = 0;')
        p('if (%s) { data_prefix_len = 1; }' % (' || '.join(self.getConstructionBitmaskBuilders(-1))))

    def postprocessMachineCodeLen(self, p):
        p('data += data_prefix_len;')

    def initialMachineCodeOffset(self):
        return -1

    def printDataUpdate(self, p, offset, mcb, spec):
        pp = p
        if (offset < 0):
            pp = mkp(2)
            p('if (data_prefix_len) {')
        Insn.printDataUpdate(self, pp, offset, mcb, spec)
        if (offset < 0):
            p('}')

    def printTryDisassemble(self, data_name, max_len_name):
        self.printTryDisassembleOne(data_name, max_len_name, self.machine_code, -1)
        self.printTryDisassembleOne(data_name, max_len_name, self.machine_code[1:], 0)


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


def Name(mips, intel=None):
    '''
    Adjust this if you prefer the Intel asm names
    '''
    return mips


def ArithmeticDestReg(offset, baseoffset=0):
    return Reg([BitPattern(baseoffset, 0, 1), BitPattern(offset, 0, 3)])
def ArithmeticSrcReg(offset, baseoffset=0):
    return Reg([BitPattern(baseoffset, 2, 1), BitPattern(offset, 3, 3)])
def OptionalArithmeticDestReg(offset):
    return Reg([BitPattern(-1, 0, 1), BitPattern(offset, 0, 3)])

def printDisassemblerDoc():
    print('/**')
    print(' * Disassembles a single assembly instruction and prints it to stdout')
    print(' *')
    print(' * @param data: pointer to the instruction to disassemble')
    print(' * @param max_len: max. number of viable bytes in the instruction')
    print(' * @return Number of bytes in the disassembled instruction, or 0 on error')
    print(' */')

def printDisassemblerHeader(trail=';'):
    print('int')
    print('disassemble_one(FILE *file, unsigned char *data, int max_len)' + trail)

def printDisassembler(instructions):
    printDisassemblerHeader(trail='')
    print('{')
    p = mkp(1)
    p('char* addr_prefix;')
    for preinsn in instructions:
        for insn in preinsn.allEncodings():
            insn.printTryDisassemble('data', 'max_len')
    p('return 0; // failure')
    print('}')


REGISTERS = [
    ('$v0', 0),
    ('$a3', 0),
    ('$a2', 0),
    ('$s0', 0),
    ('$sp', 'stack'),
    ('$fp', 'stack'),
    ('$a1', 0),
    ('$a0', 0),
    ('$a4', 0),
    ('$a5', 0),
    ('$t0', 'temp'),
    ('$t1', 'temp'),
    ('$s1', 0),
    ('$s2', 0),
    ('$s3', 0),
    ('$gp', 0)]



class Test(object):
    ALL_REGISTERS = [r[0] for r in REGISTERS]
    TEMP_REGISTERS = [r[0] for r in REGISTERS if r[1] == 'temp']
    NON_TEMP_REGISTERS = [r[0] for r in REGISTERS if r[1] != 'temp']

    # caller-saved registers that have no deep semantics and can be used to back up other registers:
    BACKUP_REGISTERS = [ '$t0', '$t1',
                         '$a1', '$a2', '$a3' ]

    def __init__(self, testclosure):
        self.testclosure = testclosure

    def run(self, binary, insn):
        '''False iff test fails'''
        return False

    def run_test(self, binary, body):
        with tempfile.NamedTemporaryFile() as tfile:
            tfile.write(body.encode('utf-8'))
            tfile.flush()
            output = subprocess.run([binary, tfile.name], input='', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output

    def body(self, code, data):
        full = ['.text', 'main:'] + code + ['  jreturn', '.data'] + data
        return ''.join(s + '\n' for s in full)

    def expect_preservation(self, binary, operations, register, data, temp_reg):
        '''check operation to confirm that the register is preserved through the operations'''

        expected = [0, 1, 2]
        sum_body = []

        for n in expected:
            is_temp = register in Test.TEMP_REGISTERS
            sum_body += ((['  move ' + temp_reg + ', ' + register + '  ; pres-backup'] if not is_temp else [])
                         + ['  li ' + register + ', %d' % n]
                         + operations
                         + (['  move $a0, ' + register + '  ; pres-restore'] if not register == '$a0' else [])
                         + (['  move ' + register + ', ' + temp_reg] if not (register == '$a0' or is_temp) else [])
                         + ['  jal print_int'])
        return self.expect(binary, self.body(sum_body, data), expected)

    def expect(self, binary, testbody, testoutput):
        result = self.run_test(binary, testbody)
        failed = False
        result_stdout = result.stdout.decode('utf-8')
        expected = ''.join(str(to) + '\n' for to in testoutput)
        if result.returncode != 0:
            failed = True
            print("  => unexpected exit code %d" % result.returncode)
        elif result_stdout != expected:
            failed = True
            print("  => unexpected output")
        if failed:
            print('/--[code]------------------------------------------')
            print(testbody)
            print('|--[stdout]----------------------------------------')
            print(result_stdout)
            print('|--[expected]--------------------------------------')
            print(expected)
            print('|--[stderr]----------------------------------------')
            print(result.stderr.decode('utf-8'))
            print('\\--------------------------------------------------')
        return not failed

    def get_free_temps(self, args):
        return [r for r in self.BACKUP_REGISTERS if r not in args]


class ArithmeticTest(Test):
    TEST_VALUES=[0, 1, 2, 15, -7, -1]

    '''Tests an arithmetic operation with one result, no changes to unrelated registers'''
    def __init__(self, tc):
        Test.__init__(self, tc)
        self.limits = {}

    def filter_for_testarg(self, index, filter):
        '''
        Restrict the index-th parameter (starting at 0) to only values that pass the filter
        '''
        self.limits[index] = [v for v in self.test_values_for(index) if filter(v)]
        return self

    def test_values_for(self, index):
        if index in self.limits:
            return self.limits[index]
        return ArithmeticTest.TEST_VALUES

    def run_test_expected_behaviour(self, binary, insn):
        args = insn.args
        # First check that the operation produces intended results
        def try_test(init, args, bindings):
            used_regs = [a for a in args if a[0] == '$']
            regs_to_back_up = [r for r in used_regs if r not in Test.BACKUP_REGISTERS and not r == '$v0']
            unused_backups = [r for r in Test.BACKUP_REGISTERS if r not in used_regs]
            backups = []
            restores = []
            for rd in regs_to_back_up:
                backup_r = unused_backups.pop()
                backups.append('  move %s, %s' % (backup_r, rd))
                restores.append('  move %s, %s' % (rd, backup_r))

            body = (backups
                    + init
                    + ['  %s %s   ; test' % (insn.name, ', '.join(args))]
                    + ['  move $v0, %s' % args[0]]
                    + restores
                    + ['  move $a0, $v0']
                    + ['  jal print_int'])

            def interpret_arg(arg):
                if arg[0] == '$':
                    return bindings[arg]
                else:
                    return int(arg)

            i_args = tuple(interpret_arg(a) for a in args)
            #print('i-args = %s' % [i_args])
            expected = [self.testclosure(*i_args)]

            return self.expect(binary, self.body(body, []), expected)

        def all_configs_behave(index, config_init, config_args, config_bindings):
            if index >= len(args):
                k = try_test(config_init, config_args, config_bindings)
                return k

            kind = args[index].getKind()
            if kind == 'i':
                for v in self.test_values_for(index):
                    if not all_configs_behave(index + 1,
                                              config_init,
                                              config_args + [str(v)],
                                              config_bindings):
                        return False
                return True
            elif kind == 'r':
                count = 0
                for reg in Test.ALL_REGISTERS:
                    count += 1
                    if reg in config_bindings: # register already initialised
                        if config_bindings[reg] not in self.test_values_for(index):
                            continue # existing register binding not allowed at this index (this happens if we use the same reg. twice and a later position is more restrictive)
                        success = all_configs_behave(index + 1,
                                                     config_init,
                                                     config_args + [reg],
                                                     config_bindings)
                    else:
                        for v in self.test_values_for(index):
                            new_bindings = dict(config_bindings)
                            new_bindings[reg] = v
                            success = all_configs_behave(index + 1,
                                                         config_init + ['  li %s, %s' % (reg, v)],
                                                         config_args + [reg],
                                                         new_bindings)
                            if not success:
                                return False
                    if not success:
                        return False
                return True
            else:
                raise Exception('Unexpected kind: %s' % kind)

        if not all_configs_behave(0,
                                  [], # initialisation instructions
                                  [], # args to insn call
                                  {}): # mappings from register name to int binding
            return False
        return True

    def run_test_preservation(self, binary, insn):
        args = insn.args
        def try_test(args, tempreg):
            body = ['  move %s, %s' % (tempreg, args[0]),
                    '  %s %s   ; test' % (insn.name, ', '.join(args)), # the insn we care about
                    '  move %s, %s' % (args[0], tempreg)]
            data = []

            for reg in Test.ALL_REGISTERS:
                if reg != tempreg and reg != args[0]:
                    if not self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg, tempreg])[0]):
                        return False
            return True

        reg_args = []
        default_args = []
        RV0 = '$v0'
        index = 0
        for a in args:
            kind = args[index].getKind()
            if kind == 'r':
                reg_args.append(index)
                default_args.append(RV0)
            elif kind == 'i':
                default_args.append("0")
            else:
                raise Exception('Unexpected kind: %s' % kind)
            index += 1
        # check preservation for all registers at arglist positions stored in reg_args
        # (only vary one arg at a time)
        for shuffle_arg in reg_args:
            for subst_reg in Test.ALL_REGISTERS:
                args = list(default_args)
                args[shuffle_arg] = subst_reg
                viable_temp_regs = self.get_free_temps(args)
                for i in [0, 1]:
                    if not try_test(args, viable_temp_regs[i]):
                        return False
        return True


    def run(self, binary, insn):
        if not self.run_test_expected_behaviour(binary, insn):
            print("  Unexpected behaviour")
            return False
        # Now run preservation tests
        if not self.run_test_preservation(binary, insn):
            print("  Unexpected lack of preservation")
            return False
        return True


class BranchTest(Test):
    '''Tests an operation with a (conditional) branch'''
    def __init__(self, tc):
        Test.__init__(self, tc)


    def run_test_expected_behaviour(self, binary, insn):
        args = insn.args[1:]
        test_regs = ['$v0'] * len(args)
        for swap_index in range(0, len(args)):
            for alt in Test.ALL_REGISTERS:
                test_regs[swap_index] = alt
                temp_regs = self.get_free_temps(test_regs)
                out_reg = temp_regs[len(test_regs)]
                def run_cnf(assignments, backups):
                    test_regs_set = set(test_regs)
                    body = (  ['  move %s, %s ; backup' % (backups[r], r) for r in test_regs_set]
                            + ['  li   %s, %s ; load' % (assignments[r], r) for r in test_regs_set]
                            + ['  %s  dest, %s' % (insn.name, ', '.join(test_regs)),
                               '  li   %s, 0' % out_reg,
                               '  j    done',
                               'dest:',
                               '  li   %s, 1' % out_reg,
                               'done:']
                            + ['  move %s, %s ; restore' % (r, backups[r]) for r in test_regs_set]
                            + ['  move %a0, %s' % out_reg,
                               '  jal  print_int'])
                    expected = [1 if insn.test(tuple([assignments[r] for r in test_regs])) else 0]
                    return self.expect(binary,
                                       self.body(body, []),
                                       expected)

                def testcnf(index, assignments, backups):
                    if index >= len(args):
                        return run_cnf(assignments, backups)
                    r = test_regs[index]
                    if r not in assignments:
                        assignments = dict(assignments)
                        backups = dict(backups)
                        backups[r] = temp_regs[index]
                        for i in [-1, 0, 1]:
                            assignments[r] = i
                            if not testcnf(index + 1, assignments, backups):
                                return False
                        return True
                    # otherwise, if already assigned
                    if not testcnf(index + 1, assignments, backups):
                        return False
                    return True

            test_regs[swap_index] = '$v0'

    def run_test_preservation(self, binary, insn):
        args = insn.args[1:]
        def try_test(args, tempreg):
            body = ['  %s  dest, %s   ; test' % (insn.name, ', '.join(args)), # the insn we care about
                    'dest:']
            data = []

            for reg in Test.ALL_REGISTERS:
                if not self.expect_preservation(binary, body, reg, data, self.get_free_temps(args + [reg])[0]):
                    return False
            return True

        reg_args = []
        default_args = []
        RV0 = '$v0'
        index = 0
        for a in args:
            kind = args[index].getKind()
            if kind == 'r':
                reg_args.append(index)
                default_args.append(RV0)
            elif kind == 'i':
                default_args.append("0")
            else:
                raise Exception('Unexpected kind: %s' % kind)
            index += 1
        # check preservation for all registers at arglist positions stored in reg_args
        # (only vary one arg at a time)
        for shuffle_arg in reg_args:
            for subst_reg in Test.ALL_REGISTERS:
                args = list(default_args)
                args[shuffle_arg] = subst_reg
                viable_temp_regs = self.get_free_temps(args)
                for i in [0, 1]:
                    if not try_test(args, viable_temp_regs[i]):
                        return False
        return True

    def run(self, binary, insn):
        if not self.run_test_expected_behaviour(binary, insn):
            print("  Unexpected behaviour")
            return False
        # Now run preservation tests
        if not self.run_test_preservation(binary, insn):
            print("  Unexpected lack of preservation")
            return False
        return True


MASK64 = 0xffffffffffffffff

def signed64(k):
    '''convert long to 64 bit signed integer equivalent'''
    k = k & MASK64
    if k > (MASK64 >> 1):
        #negative
        return -((MASK64 + 1) - k)
    return k

# shift ops
def shl(a, b):
    return signed64((a & MASK64) << (b & 0x3f))

def shr(a, b, arithmetic=False):
    if arithmetic and signed64(a) < 0:
        return signed64(((MASK64 << 32) | a) >> (b & 0x3f))  # only 6 bits of the shift offset are counted
    return signed64((a & MASK64) >> (b & 0x3f))

instructions = [
    Insn(Name(mips="move", intel="mov"), '$r0 := $r1', [0x48, 0x89, 0xc0], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a,b : b)),
    Insn(Name(mips="li", intel="mov"), '$r0 := %v', [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0], [ArithmeticDestReg(1), ImmLongLong(2)],
         test=ArithmeticTest(lambda a,b : b)),

    Insn("add", ArithmeticEffect('+'), [0x48, 0x01, 0xc0], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a,b : a + b)),
    Insn(Name(mips="addi", intel="add"), '$r0 := $r0 + %v', [0x48, 0x81, 0xc0, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
         test=ArithmeticTest(lambda a,b : a + b)),
    Insn("sub", ArithmeticEffect('$-$'), [0x48, 0x29, 0xc0], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a,b : a - b)),
    Insn(Name(mips="subi", intel="add"), '$r0 := $r0 $$-$$ %v', [0x48, 0x81, 0xe8, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
         test=ArithmeticTest(lambda a,b : a - b)),
    Insn(Name(mips="mul", intel="imul"), ArithmeticEffect('*'), [0x48, 0x0f, 0xaf, 0xc0], [ArithmeticSrcReg(3), ArithmeticDestReg(3)],
         test=ArithmeticTest(lambda a,b : a * b)),
    Insn(Name(mips="div_a2v0", intel="idiv"), '$v0 := $a2:$v0 / $r0, $a2 := remainder', [0x48, 0xf7, 0xf8], [ArithmeticDestReg(2)]),

    Insn(Name(mips="not", intel="test_mov0_sete"), 'if $r1 = 0 then $r1 := 1 else $r1 := 0',  [0x48, 0x85, 0xc0, 0x40, 0xb8, 0,0,0,0, 0x40, 0x0f, 0x94, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), JointReg([ArithmeticSrcReg(2), ArithmeticDestReg(2)])],
         test=ArithmeticTest(lambda a,b : 1 if b == 0 else 0)),

    Insn(Name(mips="and", intel="and"), '$r0 := $r0 bitwise-and $r1', [0x48, 0x21, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a, b : a & b)),
    Insn(Name(mips="andi", intel="and"), '$r0 := $r0 bitwise-and %v', [0x48, 0x81, 0xe0, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
         test=ArithmeticTest(lambda a, b : a & b)),
    Insn(Name(mips="or", intel="or"), '$r0 := $r0 bitwise-or $r1', [0x48, 0x09, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a, b : a | b)),
    Insn(Name(mips="ori", intel="or"), '$r0 := $r0 bitwise-or %v', [0x48, 0x81, 0xc8, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
         test=ArithmeticTest(lambda a, b : a | b)),
    Insn(Name(mips="xor", intel="xor"), '$r0 := $r0 bitwise-exclusive-or $r1', [0x48, 0x31, 0xc0,], [ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a, b : a ^ b)),
    Insn(Name(mips="xori", intel="xor"), '$r0 := $r0 bitwise-exclusive-or %v', [0x48, 0x81, 0xf0, 0, 0, 0, 0], [ArithmeticDestReg(2), ImmUInt(3)],
         test=ArithmeticTest(lambda a, b : a ^ b)),

    InsnAlternatives(Name(mips="sll", intel="shl"), '$r0 := $r0 $${<}{<}$$ $r1[0:7]',
                     ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe0, 0x48, 0x87, 0xc1], [
                         # xchg rcx, r0    ; rcx=$a0
                         # shl  r1, cl
                         # xchg rcx, r0    ; rcx=$a0
                         ArithmeticDestReg(5, baseoffset=3),
                         JointReg([ArithmeticSrcReg(2),
                                   ArithmeticSrcReg(8, baseoffset=6)])]),
                     [ # sll $r, $a0 (RCX):
                         ('{arg1} == 1',
                          ([0x48, 0xd3, 0xe0], [
                              # shl  r1, cl
                              ArithmeticDestReg(2),
                              DisabledArg(ArithmeticDestReg(2), '1')
                          ])),
                       # sll $r, $r:
                         ('{arg0} == {arg1}',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe1, 0x48, 0x87, 0xc1], [
                              JointReg([ArithmeticSrcReg(2),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                       # sll $a0 (RCX), $r:
                         ('{arg0} == 1',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe0, 0x48, 0x87, 0xc1], [
                              # xchg rcx, r1    ; rcx=$a0
                              # shl  r1, cl
                              # xchg rcx, r1    ; rcx=$a0
                              #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
                              DisabledArg(ArithmeticDestReg(8), '1'),
                              JointReg([ArithmeticSrcReg(2, baseoffset=0),
                                        ArithmeticDestReg(5, baseoffset=3),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                     ],
                     test=ArithmeticTest(lambda a, b : shl(a, (0x3f & b))),
                 ),
    Insn(Name(mips="slli", intel="shl"), '$r0 := $r0 bit-shifted left by %v', [0x48, 0xc1, 0xe0, 0], [ArithmeticDestReg(2), ImmByte(3)],
         test=ArithmeticTest(lambda a, b : shl(a, 0x3f & b)).filter_for_testarg(1, lambda x : x >= 0)),

    InsnAlternatives(Name(mips="srl", intel="shr"), '$r0 := $r0 $${>}{>}$$ $r1[0:7]',
                     ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe8, 0x48, 0x87, 0xc1], [
                         ArithmeticDestReg(5, baseoffset=3),
                         JointReg([ArithmeticSrcReg(2),
                                   ArithmeticSrcReg(8, baseoffset=6)])]),
                     [ # srl $r, $a0 (RCX):
                         ('{arg1} == 1',
                         ([0x48, 0xd3, 0xe8], [
                             ArithmeticDestReg(2),
                             DisabledArg(ArithmeticDestReg(2), '1')
                         ])),
                       # srl $r, $r:
                         ('{arg0} == {arg1}',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe9, 0x48, 0x87, 0xc1], [
                              JointReg([ArithmeticSrcReg(2),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                       # srl $a0 (RCX), $r:
                         ('{arg0} == 1',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xe8, 0x48, 0x87, 0xc1], [
                              # xchg rcx, r1    ; rcx=$a0
                              # srl  r1, cl
                              # xchg rcx, r1    ; rcx=$a0
                              #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
                              DisabledArg(ArithmeticDestReg(8), '1'),
                              JointReg([ArithmeticSrcReg(2, baseoffset=0),
                                        ArithmeticDestReg(5, baseoffset=3),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                     ],
                     test=ArithmeticTest(lambda a, b : shr((0xffffffffffffffff & a), (0x3f & b))),
                 ),
    Insn(Name(mips="srli", intel="shr"), '$r0 := $r0 bit-shifted right by %v', [0x48, 0xc1, 0xe8, 0], [ArithmeticDestReg(2), ImmByte(3)],
         test=ArithmeticTest(lambda a, b : shr(a, b)).filter_for_testarg(1, lambda x : x >= 0)),

    InsnAlternatives(Name(mips="sra", intel="sar"), '$r0 := $r0 $${>}{>}$$ $r1[0:7], sign-extended',
                     ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf8, 0x48, 0x87, 0xc1], [
                         ArithmeticDestReg(5, baseoffset=3),
                         JointReg([ArithmeticSrcReg(2),
                                   ArithmeticSrcReg(8, baseoffset=6)])]),
                     [('{arg1} == 1',
                         ([0x48, 0xd3, 0xf8], [
                             ArithmeticDestReg(2),
                             DisabledArg(ArithmeticDestReg(2), '1')
                         ])),
                       # sra $r, $r:
                         ('{arg0} == {arg1}',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf9, 0x48, 0x87, 0xc1], [
                              JointReg([ArithmeticSrcReg(2),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                       # sra $a0 (RCX), $r:
                         ('{arg0} == 1',
                          ([0x48, 0x87, 0xc1, 0x48, 0xd3, 0xf8, 0x48, 0x87, 0xc1], [
                              # xchg rcx, r1    ; rcx=$a0
                              # sra  r1, cl
                              # xchg rcx, r1    ; rcx=$a0
                              #DisabledArg(ArithmeticSrcReg(5, baseoffset=3), '1'),
                              DisabledArg(ArithmeticDestReg(8), '1'),
                              JointReg([ArithmeticSrcReg(2, baseoffset=0),
                                        ArithmeticDestReg(5, baseoffset=3),
                                        ArithmeticSrcReg(8, baseoffset=6)])])
                          ),
                     ],
                     test=ArithmeticTest(lambda a, b : shr(a, 0x3f & b)),
                 ),
    Insn(Name(mips="srai", intel="sar"), '$r0 := $r0 bit-shifted right by %v, sign extension', [0x48, 0xc1, 0xf8, 0], [ArithmeticDestReg(2), ImmByte(3)],
         test=ArithmeticTest(lambda a, b : shr(a, 0x3f & b, arithmetic=True)).filter_for_testarg(1, lambda x : x >= 0)),


    Insn(Name(mips="slt", intel="cmp_mov0_setl"), 'if $r1 $$<$$ $r2 then $r1 := 1 else $r1 := 0',  [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x9c, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a, b, c : 1 if b < c else 0)),
    Insn(Name(mips="sle", intel="cmp_mov0_setle"), 'if $r1 $$\le$$ $r2 then $r1 := 1 else $r1 := 0', [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x9e, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticDestReg(2), ArithmeticSrcReg(2)],
         test=ArithmeticTest(lambda a, b, c : 1 if b <= c else 0)),
    Insn(Name(mips="seq", intel="cmp_mov0_sete"), 'if $r1 = $r2 then $r1 := 1 else $r1 := 0',  [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x94, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticSrcReg(2), ArithmeticDestReg(2)],
         test=ArithmeticTest(lambda a, b, c : 1 if b == c else 0)),
    Insn(Name(mips="sne", intel="cmp_mov0_setne"), 'if $r1 $$\\ne$$ $r2 then $r1 := 1 else $r1 := 0', [0x48, 0x39, 0xc0, 0x40, 0xb8, 0,0,0,0,  0x40, 0x0f, 0x95, 0xc0], [JointReg([ArithmeticDestReg(12, baseoffset=9), ArithmeticDestReg(4, baseoffset = 3)]), ArithmeticSrcReg(2), ArithmeticDestReg(2)],
         test=ArithmeticTest(lambda a, b, c : 1 if b != c else 0)),

    Insn(Name(mips="bgt", intel="cmp_jg"), 'if $r0 $$>$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8f, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a > b)),
    Insn(Name(mips="bge", intel="cmp_jge"), 'if $r0 $$\\ge$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8d, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a >= b)),
    Insn(Name(mips="blt", intel="cmp_jl"), 'if $r0 $$<$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8c, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a < b)),
    Insn(Name(mips="ble", intel="cmp_jle"), 'if $r0 $$\\le$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x8e, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a <= b)),
    Insn(Name(mips="beq", intel="cmp_je"), 'if $r0 = $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x84, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a == b)),
    Insn(Name(mips="bne", intel="cmp_jne"), 'if $r0 $$\\ne$$ $r1, then jump to %a', [0x48, 0x39, 0xc0, 0x0f, 0x85, 0, 0, 0, 0], [ArithmeticDestReg(2), ArithmeticSrcReg(2), PCRelative(5, 4, -9)],
         test=BranchTest(lambda a, b : a != b)),
    Insn(Name(mips="bgtz", intel="cmp0_jg"), 'if $r0 $$>$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8f, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a > 0)),
    Insn(Name(mips="bgez", intel="cmp0_jge"), 'if $r0 $$\ge$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8d, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a >= 0)),
    Insn(Name(mips="bltz", intel="cmp0_jl"), 'if $r0 $$<$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8c, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a < 0)),
    Insn(Name(mips="blez", intel="cmp0_jle"), 'if $r0 $$\\le$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x8e, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a <= 0)),
    Insn(Name(mips="bnez", intel="cmp0_jnz"), 'if $r0 $$\\ne$$ 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x85, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a != 0)),
    Insn(Name(mips="beqz", intel="cmp0_jz"), 'if $r0 = 0, then jump to %a', [0x48, 0x83, 0xc0, 0x00, 0x0f, 0x84, 0, 0, 0, 0], [ArithmeticDestReg(2), PCRelative(6, 4, -10)],
         test=BranchTest(lambda a : a == 0)),

    Insn(Name(mips="j", intel="jmp"), 'jump to %a', [0xe9, 0, 0, 0, 0], [PCRelative(1, 4, -5)],
         test=BranchTest(lambda _: True)),
    Insn(Name(mips="jr", intel="jmp"), 'jump to $r0', [0x40, 0xff, 0xe0], [ArithmeticDestReg(2)]),
    Insn(Name(mips="jal", intel="callq"), 'push next instruction address, jump to %a', [0xe8, 0x00, 0x00, 0x00, 0x00], [PCRelative(1, 4, -5)]),
    OptPrefixInsn(Name(mips="jalr", intel="callq"), "push next instruction address, jump to $r0" ,0x40, [0xff, 0xd0], [OptionalArithmeticDestReg(1)]),
    Insn(Name(mips="jreturn", intel="ret"), 'jump to mem64[$sp]; $sp := $sp + 8', [0xc3], []),

    InsnAlternatives(Name(mips="sb", intel="mov_byte_r"), 'mem8[$r1 + %v] := $r0[7:0]',
                     ([0x40, 0x88, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
                         ('{arg2} == 4', ([0x40, 0x88, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
                     ]).setFormat('%s, %s(%s)'),
    InsnAlternatives(Name(mips="lb", intel="mov_byte_r"), 'mem8[$r1 + %v] := $r0[7:0]',
                     ([0x40, 0x0f, 0xb6, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(3), ImmInt(5), ArithmeticDestReg(3)]), [
                         ('{arg2} == 4', ([0x40, 0x0f, 0xb6, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(3), ImmInt(5), DisabledArg(ArithmeticDestReg(3), '4')]))
                     ]).setFormat('%s, %s(%s)'),

    InsnAlternatives(Name(mips="sd", intel="mov_qword_r"), 'mem64[$r1 + %v] := $r0',
                     ([0x48, 0x89, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
                         ('{arg2} == 4', ([0x48, 0x89, 0x84, 0x24, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
                     ]).setFormat('%s, %s(%s)'),
    InsnAlternatives(Name(mips="ld", intel="mov_r_qword"), '$r0 := mem64[$r1 + %v]',
                     ([0x48, 0x8b, 0x80, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(3), ArithmeticDestReg(2)]), [
                         ('{arg2} == 4', ([0x48, 0x8b, 0x84, 0x24, 0, 0, 0, 0], [ArithmeticSrcReg(2), ImmInt(4), DisabledArg(ArithmeticDestReg(2), '4')]))
                     ]).setFormat('%s, %s(%s)'),

    Insn(Name(mips="syscall", intel="syscall"), 'system call', [0x0f, 0x05], []),
    Insn(Name(mips="push", intel="push"), '$sp := $sp - 8; mem64[$sp] = $r0', [0x48, 0x50], [ArithmeticDestReg(1)]),
    Insn(Name(mips="pop", intel="pop"), '$r0 = mem64[$sp]; $sp := $sp + 8', [0x48, 0x58], [ArithmeticDestReg(1)]),
]


def printUsage():
    print('usage: ')
    for n in ['headers', 'code', 'latex', 'assembler', 'assembler-header', 'test']:
        print('\t' + sys.argv[0] + ' ' + n)

def printWarning():
    print('// This is GENERATED CODE.  Do not modify by hand, or your modifications will be lost on the next re-buld!')

def printHeaderHeader():
    print('#include "assembler-buffer.h"')
    print('#include <stdio.h>')

def printCodeHeader():
    print('#include <string.h>')
    print('#include <stdio.h>')
    print('')
    print('#include "assembler-buffer.h"')
    print('#include "debugger.h"')
    print('#include "registers.h"')

def printOffsetCalculatorHeader(trail=';'):
    print('int')
    print('asm_arg_offset(char *insn, asm_arg *args, int arg_nr)' + trail)


def printAssemblerHeader():
    print("""// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#ifndef A2OPM_INSTRUCTIONS_H
#define A2OPM_INSTRUCTIONS_H

#include "assembler-buffer.h"

typedef union {
	label_t *label;
	int r;			// register nr
	unsigned long long imm;	// immediate
} asm_arg;

#define ASM_ARG_ERROR	0
#define ASM_ARG_REG	1
#define ASM_ARG_LABEL	2
#define ASM_ARG_IMM8U	3
#define ASM_ARG_IMM32U	4
#define ASM_ARG_IMM32S	5
#define ASM_ARG_IMM64U	6
#define ASM_ARG_IMM64S	7
// We may get further combinations later.

/**
 * Returns the number of arguments, or -1 if the instruction is unknown
 */
int
asm_insn_get_args_nr(char *insn);

/**
 * Decodes the type of the specified argument
 */
int
asm_insn_get_arg(char *insn, int arg_nr);

/**
 * Issues a single instruction.  No error checking is performed.
 */
void
asm_insn(buffer_t *buf, char *insn, asm_arg *args, int args_nr);

/**
 * Computes the offset of the `arg_nr'th argument in the given instruction, or -1 if it has no unique memory offset
 */

""")
    printOffsetCalculatorHeader()
    print("#endif // !defined(A2OPM_INSTRUCTIONS_H)")

def printAssemblerModule():
    print("""
// This code is AUTO-GENERATED.  Do not modify, or you may lose your changes!
#include <stdio.h>
#include <strings.h>

#include "assembler-buffer.h"
#include "assembler.h"
#include "assembler-instructions.h"

#define INSTRUCTIONS_NR {instructions_nr}
#define ARGS_MAX 5

static struct {{
	char *name;
	int args_nr;
	int args[ARGS_MAX];
}} instructions[INSTRUCTIONS_NR] = {{""".format(instructions_nr = len(instructions)))
    for insn in instructions:
        args = insn.getArgs()
        print ('\t{{ .name = "{name}", .args_nr = {args_nr}, .args = {{ {args} }} }},'
               .format(name = insn.name,
                       args_nr = len(insn.args),
                       args = ', '.join(a.getType() for a in args)))
    print('};')

    print("""
int
asm_insn_get_args_nr(char *insn)
{
	for (int i = 0; i < INSTRUCTIONS_NR; i++) {
		if (0 == strcasecmp(insn, instructions[i].name)) {
			return instructions[i].args_nr;
		}
	}
	return -1;
}

int
asm_insn_get_arg(char *insn, int arg_nr)
{
	for (int i = 0; i < INSTRUCTIONS_NR; i++) {
		if (0 == strcasecmp(insn, instructions[i].name)) {
			if (arg_nr < 0 || arg_nr >= instructions[i].args_nr) {
				return -1;
			} else {
				return instructions[i].args[arg_nr];
			}
		}
	}
	return -1;
}

void
asm_insn(buffer_t *buf, char *insn, asm_arg *args, int args_nr)
{
	// This isn't terribly efficient, but that's probably okay.""")
    for insn in instructions:
        args = insn.getArgs()
        arglist = list(args)
        for i in range(0, len(args)):
            arglist[i] = 'args[{i}].{select}'.format(i = str(i), select = args[i].strGenericName())

        print ('\tif (0 == (strcasecmp(insn, "{name}"))) {{\n\t\t{lib_prefix}emit_{name}({args});\n\t\treturn;\n\t}}'
               .format(name = insn.name,
                       lib_prefix = LIB_PREFIX,
                       args = ', '.join(['buf'] + arglist)))

    print('\tfprintf(stderr, "Unexpected instruction: %s\\n", insn);')
    print('\treturn;')
    print('}')
    print('')
    printOffsetCalculatorHeader('')
    print('{')
    for insn in instructions:
        print ('\tif (0 == strcasecmp("{name}", insn)) '
               .format(name = insn.name)),
        insn.printOffsetCalculatorBranch('\t\t', 'arg_nr')
    print('\treturn -1;')
    print('}')

def printDocs():
    print('\\begin{tabular}{llp{8cm}}')
    print('\\small')
    for i in instructions:
        [a,b,c] = i.genLatexTable()
        print(a + '&\t' + b + '&\t' + c + '\\\\')
    print('\\end{tabular}')

def printSty():
    insn_names = [i.name for i in instructions]
    print('''
\\lstdefinelanguage[2opm]{{Assembler}}%
{{morekeywords=[1]{{{KW}}},%
morekeywords=[2]{{.asciiz,.data,.text,.byte,.word}},%
comment=[l]\\#%
}}[keywords,strings,comments]
'''.format(KW=','.join(insn_names)))

def runTests(binary, names):
    insns = 0
    tested = 0
    failed = 0
    for insn in instructions:
        if names != [] and insn.name not in names:
            continue
        insns += 1
        if insn.test is not None:
            tested += 1
            print('Testing %s:' % insn.name)
            did_fail = 0 if insn.test.run(binary, insn) else 1
            if did_fail == 1:
                print(colored('  FAILED', 'red'))
            else:
                print(colored('  OK', 'green'))
            failed += did_fail
    print('insns = %d | tested = %d | failed = %d' % (insns, tested, failed))
    sys.exit(1 if failed > 0 else 0)

if len(sys.argv) > 1:
    if sys.argv[1] == 'headers':
        printWarning()
        printHeaderHeader()
        for insn in instructions:
            insn.printHeader()
        printDisassemblerDoc()
        printDisassemblerHeader()

    elif sys.argv[1] == 'code':
        printWarning()
        printCodeHeader()
        for insn in instructions:
            insn.printGenerator()
            print("\n")
        printDisassembler(instructions)

    elif sys.argv[1] == 'latex':
        printDocs()

    elif sys.argv[1] == 'latex-sty':
        printSty()

    elif sys.argv[1] == 'assembler':
        printAssemblerModule()

    elif sys.argv[1] == 'assembler-header':
        printAssemblerHeader()

    elif sys.argv[1] == 'test':
        runTests(sys.argv[2], sys.argv[3:])

    else:
        printUsage()

else:
    printUsage()
