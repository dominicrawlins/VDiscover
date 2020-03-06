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

from math import ceil

from vdiscover.Types import Type
from ptrace.error import PtraceError


def FindModule(value, mm):
    return mm.findModule(value)


def RefinePType(ptype, value, process, mm):

    architecture = "32" if "32" in str(ptype) else "64"
    bytes = 4 if architecture == "32" else 8

    if value is None:
        return (Type("Top" + architecture, bytes), value)

    if ("Ptr" in str(ptype)):
        ptr = value
        if ptr == 0x0:
            return (Type("NPtr" + architecture, bytes), ptr)
        else:

            try:
                _ = process.readBytes(ptr, 4) if architecture == "32" else process.readBytes(ptr, 8)
            except PtraceError:
                return (Type("DPtr" + architecture, bytes), ptr)

            mm.checkPtr(ptr)
            if mm.isStackPtr(ptr):
                return (Type("SPtr" + architecture, bytes), ptr)
            elif mm.isHeapPtr(ptr):
                return (Type("HPtr" + architecture, bytes), ptr)
            elif mm.isCodePtr(ptr):
                return (Type("GxPtr" + architecture, bytes), ptr)
            elif mm.isFilePtr(ptr):
                return (Type("FPtr" + architecture, bytes), ptr)
            elif mm.isGlobalPtr(ptr):
                return (Type("GPtr" + architecture, bytes), ptr)
            else:
                return (Type("Ptr" + architecture, bytes), ptr)

    elif "Num" in str(ptype):
        num = value
        if num == 0x0:
            return (Type("Num" + architecture + "B0", bytes), num)
        else:
            binlen = len(bin(num)) - 2
            binlen = int(ceil(binlen / 8.0)) * 8
            return (Type("Num" + architecture + "B" + str(binlen), bytes), num)

    return (Type("Top" + architecture, 8), value)
