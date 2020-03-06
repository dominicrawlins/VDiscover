"""
This file is part of VDISCOVER.

VDISCOVER is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

VDISCOVER is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with VDISCOVER. If not, see <http://www.gnu.org/licenses/>.

Copyright 2014 by G.Grieco
"""

import copy
from ptrace.cpu_info import (CPU_POWERPC, CPU_INTEL, CPU_X86_64, CPU_I386)


class Type:

    def __init__(self, name, size, index=None):
        self.name = str(name)
        self.size_in_bytes = size
        self.index = index

    def __str__(self):

        r = str(self.name)
        if (self.index is not None):
            r = r + "(" + str(self.index) + ")"

        return r

    def getSize(self):
        return self.size_in_bytes

    # def copy(self):
    #  return copy.copy(self)

ptypes = [Type("Num32", 4, None),
          Type("Ptr32", 4, None),  # Generic pointer
          Type("SPtr32", 4, None),  # Stack pointer
          Type("HPtr32", 4, None),  # Heap pointer
          Type("GxPtr32", 4, None),  # Global eXecutable pointer
          Type("FPtr32", 4, None),  # File pointer
          Type("NPtr32", 4, None),  # NULL pointer
          Type("DPtr32", 4, None),  # Dangling pointer
          Type("GPtr32", 4, None),  # Global pointer
          Type("Top32", 4, None),
          Type("Num64", 8, None),
          Type("Ptr64", 8, None),  # Generic pointer
          Type("SPtr64", 8, None),  # Stack pointer
          Type("HPtr64", 8, None),  # Heap pointer
          Type("GxPtr64", 8, None),  # Global eXecutable pointer
          Type("FPtr64", 8, None),  # File pointer
          Type("NPtr64", 8, None),  # NULL pointer
          Type("DPtr64", 8, None),  # Dangling pointer
          Type("GPtr64", 8, None),  # Global pointer
          Type("Top64", 8, None)
          ]

ptypes += list(map(lambda x : Type("Num32B" + str(x), 4, None), list(range(0,33,8))))
ptypes += list(map(lambda x : Type("Num64B" + str(x), 8, None), list(range(0,65,8))))



num32_ptypes = list(filter(lambda t: "Num32" in str(t), ptypes))
ptr32_ptypes = list(filter(lambda t: "Ptr32" in str(t), ptypes))
generic32_ptypes = [Type("Top32", 4, None)]

num64_ptypes = list(filter(lambda t: "Num64" in str(t), ptypes))
ptr64_ptypes = list(filter(lambda t: "Ptr64" in str(t), ptypes))
generic64_ptypes = [Type("Top64", 8, None)]


def isNum(ptype):
    return ptype in ["int", "ulong", "long", "char"]


def isPtr(ptype):
    return "addr" in ptype or "*" in ptype or "string" in ptype or "format" in ptype or "file" in ptype


def isVoid(ptype):
    return ptype == "void"


def isNull(val):
    return val == "0x0" or val == "0"


def GetPtype(ptype):

    if CPU_X86_64:
        if isPtr(ptype):
            return Type("Ptr64", 8)
        elif isNum(ptype):
            return Type("Num64", 8)
        elif isVoid(ptype):
            return Type("Top64", 8)
        else:
            return Type("Top64", 8)
    if isPtr(ptype):
        return Type("Ptr32", 4)
    elif isNum(ptype):
        return Type("Num32", 4)
    elif isVoid(ptype):
        return Type("Top32", 4)
    else:
        return Type("Top32", 4)
