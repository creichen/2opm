#! /usr/bin/env python3
# This file is Copyright (C) 2014, 2020--2022 Christoph Reichenbach
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

# Register categories:

STACK	= 'stack'
TEMP	= 'temp'
ARG	= 'arg'
RETURN	= 'ret'

class Register:
    def __init__(self, name, category, callee_saved=False):
        self.name = name
        self.category = category
        self.callee_saved = callee_saved

    @property
    def is_temp(self):
        return self.category == TEMP

REGISTERS = [
    Register('$v0', RETURN),
    Register('$a0', ARG),
    Register('$a1', ARG),
    Register('$a2', ARG),
    Register('$a3', ARG),
    Register('$a4', ARG),
    Register('$a5', ARG),
    Register('$t0', TEMP),
    Register('$t1', TEMP),
    Register('$s0', 0,		callee_saved=True),
    Register('$s1', 0,		callee_saved=True),
    Register('$s2', 0,		callee_saved=True),
    Register('$s3', 0,		callee_saved=True),
    Register('$sp', STACK),
    Register('$fp', STACK),
    Register('$gp', 0),
]
