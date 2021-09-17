# Copyright (C) 2021 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gdb
import gdb.disassembler
import struct
import sys

from gdb.disassembler import Disassembler

# A global, holds the program-counter address at which we should
# perform the extra disassembly that this script provides.
current_pc = None


def remove_all_python_disassemblers():
    for a in gdb.architecture_names():
        gdb.disassembler.register_disassembler(None, a)
    gdb.disassembler.register_disassembler(None, None)


class TestDisassembler(Disassembler):
    """A base class for disassemblers within this script to inherit from.
       Implements the __call__ method and ensures we only do any
       disassembly wrapping for the global CURRENT_PC."""

    def __init__(self):
        global current_pc

        super(TestDisassembler, self).__init__("TestDisassembler")
        if current_pc == None:
            raise gdb.GdbError("no current_pc set")

    def __call__(self, info):
        global current_pc

        if info.address != current_pc:
            return None
        return self.disassemble(info)

    def disassemble(self, info):
        raise NotImplementedError("override the disassemble method")


class GlobalPreInfoDisassembler(TestDisassembler):
    """Check the attributes of DisassembleInfo before disassembly has occurred."""

    def disassemble(self, info):
        ad = info.address
        st = info.string
        le = info.length
        ar = info.architecture

        if le is not None:
            raise gdb.GdbError("invalid length")

        if st is not None:
            raise gdb.GdbError("invaild string")

        if ad != current_pc:
            raise gdb.GdbError("invalid address")

        gdb.disassembler.builtin_disassemble(info)

        text = info.string + "\t## ad = 0x%x, st = %s, le = %s, ar = %s" % (
            ad,
            st,
            le,
            ar.name(),
        )
        info.set_result(info.length, text)


class GlobalPostInfoDisassembler(TestDisassembler):
    """Check the attributes of DisassembleInfo after disassembly has occurred."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)

        ad = info.address
        st = info.string
        le = info.length
        ar = info.architecture

        if ad != current_pc:
            raise gdb.GdbError("invalid address")

        if st is None or st == "":
            raise gdb.GdbError("invalid string")

        if le <= 0:
            raise gdb.GdbError("invalid length")

        text = info.string + "\t## ad = 0x%x, st = %s, le = %d, ar = %s" % (
            ad,
            st,
            le,
            ar.name(),
        )
        info.set_result(info.length, text)


class GlobalEscDisassembler(TestDisassembler):
    """Check the can_emit_style_escape attribute."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        text = info.string + "\t## style = %s" % info.can_emit_style_escape
        info.set_result(info.length, text)


class GlobalReadDisassembler(TestDisassembler):
    """Check the DisassembleInfo.read method."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        len = info.length
        str = ""
        for o in range(len):
            if str != "":
                str += " "
            v = bytes(info.read_memory(1, o))[0]
            if sys.version_info[0] < 3:
                v = struct.unpack ('<B', v)
            str += "0x%02x" % v
        text = info.string + "\t## bytes = %s" % str
        info.set_result(info.length, text)


class GlobalAddrDisassembler(TestDisassembler):
    """Check the gdb.disassembler.format_address method."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        arch = info.architecture
        addr = info.address
        str = gdb.disassembler.format_address(arch, addr)
        text = info.string + "\t## addr = %s" % str
        info.set_result(info.length, text)


class NonMemoryErrorEarlyDisassembler(TestDisassembler):
    """Throw an error (not a memory error) before setting a result."""

    def disassemble(self, info):
        raise gdb.GdbError("error before setting a result")
        gdb.disassembler.builtin_disassemble(info)


class NonMemoryErrorLateDisassembler(TestDisassembler):
    """Throw an error (not a memory error) after setting a result."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        raise gdb.GdbError("error after setting a result")


class MemoryErrorEarlyDisassembler(TestDisassembler):
    """Throw a memory error before setting a result."""

    def disassemble(self, info):
        info.read_memory(1, -info.address + 2)
        gdb.disassembler.builtin_disassemble(info)


class MemoryErrorLateDisassembler(TestDisassembler):
    """Throw a memoryh error after setting a result."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        info.read_memory(1, -info.address + 2)


class SimpleMemoryErrorDisassembler(TestDisassembler):
    """Some basic testing around setting memory errors, ensure that the
    length and string return to None after setting a memory error."""

    def disassemble(self, info):
        if info.length is not None:
            raise gdb.GdbError("length is not None before")
        if info.string is not None:
            raise gdb.GdbError("string is not None before")
        info.set_result(1, "!! INVALID !! ")
        info.memory_error(0)
        if info.length is not None:
            raise gdb.GdbError("length is not None after")
        if info.string is not None:
            raise gdb.GdbError("string is not None after")


class CaughtMemoryErrorEarlyDisassembler(TestDisassembler):
    """Throw a memory error before setting a result."""

    def disassemble(self, info):
        try:
            info.read_memory(1, -info.address + 2)
        except gdb.MemoryError as e:
            info.memory_error(-info.address + 2)
            return None
        gdb.disassembler.builtin_disassemble(info)


class CaughtMemoryErrorLateDisassembler(TestDisassembler):
    """Throw a memoryh error after setting a result."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        try:
            info.read_memory(1, -info.address + 2)
        except gdb.MemoryError as e:
            # This memory error will discard the earlier result and
            # mark this disassembly as failed with a memory error.
            info.memory_error(-info.address + 2)


class SetResultBeforeBuiltinDisassembler(TestDisassembler):
    """Set a result, then call the builtin disassembler."""

    def disassemble(self, info):
        info.set_result(1, "!! DISCARD THIS TEXT !! ")
        gdb.disassembler.builtin_disassemble(info)


class CaughtMemoryErrorEarlyAndReplaceDisassembler(TestDisassembler):
    """Throw a memory error before setting a result."""

    def disassemble(self, info):
        tag = "NO MEMORY ERROR"
        try:
            info.read_memory(1, -info.address + 2)
        except gdb.MemoryError as e:
            info.memory_error(-info.address + 2)
            tag = "GOT MEMORY ERROR"

        # This disassembly will replace the earlier memory error
        # marker, and leave this instruction disassembling just fine,
        # however, the tag that we add will tell us that we did see a
        # memory error.
        gdb.disassembler.builtin_disassemble(info)
        text = info.string + "\t## tag = %s" % tag
        info.set_result(info.length, text)


class TaggingDisassembler(TestDisassembler):
    """A simple disassembler that just tags the output."""

    def __init__(self, tag):
        super(TaggingDisassembler, self).__init__()
        self._tag = tag

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        text = info.string + "\t## tag = %s" % self._tag
        info.set_result(info.length, text)


class GlobalColorDisassembler(TestDisassembler):
    """A disassembler performs syntax highlighting."""

    def disassemble(self, info):
        gdb.disassembler.builtin_disassemble(info)
        gdb.disassembler.syntax_highlight(info)


class GlobalCachingDisassembler(TestDisassembler):
    """A disassembler that caches the DisassembleInfo that is passed in. Once
    the call into the disassembler is complete then the DisassembleInfo
    becomes invalid, and any calls into it should trigger an
    exception."""

    # This is where we cache the DisassembleInfo object.
    cached_insn_disas = None

    def disassemble(self, info):
        """Disassemble the instruction, add a CACHED comment to the output,
        and cache the DisassembleInfo so that it is not garbage collected."""
        GlobalCachingDisassembler.cached_insn_disas = info
        gdb.disassembler.builtin_disassemble(info)
        text = info.string + "\t## CACHED"
        info.set_result(info.length, text)

    @staticmethod
    def check():
        """Check that all of the methods on the cached DisassembleInfo trigger an
        exception."""
        info = GlobalCachingDisassembler.cached_insn_disas
        assert isinstance(info, gdb.disassembler.DisassembleInfo)
        try:
            val = info.address
            raise gdb.GdbError("DisassembleInfo.address is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError("DisassembleInfo.address raised an unexpected exception")

        try:
            val = info.string
            raise gdb.GdbError("DisassembleInfo.string is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError("DisassembleInfo.string raised an unexpected exception")

        try:
            val = info.length
            raise gdb.GdbError("DisassembleInfo.length is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError("DisassembleInfo.length raised an unexpected exception")

        try:
            val = info.architecture
            raise gdb.GdbError("DisassembleInfo.architecture is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError(
                "DisassembleInfo.architecture raised an unexpected exception"
            )

        try:
            val = info.read_memory(1, 0)
            raise gdb.GdbError("DisassembleInfo.read is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError("DisassembleInfo.read raised an unexpected exception")

        try:
            val = info.set_result(1, "XXX")
            raise gdb.GdbError("DisassembleInfo.set_result is still valid")
        except RuntimeError as e:
            assert str(e) == "DisassembleInfo is no longer valid."
        except:
            raise gdb.GdbError(
                "DisassembleInfo.set_result raised an unexpected exception"
            )

        print("PASS")


class GlobalNullDisassembler(TestDisassembler):
    """A disassembler that does not change the output at all."""

    def disassemble(self, info):
        pass


class AnalyzingDisassembler(Disassembler):
    def __init__(self, name):
        """Constructor."""
        super(AnalyzingDisassembler, self).__init__(name)

        # Details about the instructions found during the first disassembler
        # pass.
        self._pass_1_length = []
        self._pass_1_insn = []
        self._pass_1_address = []

        # The start and end address for the instruction we will replace with
        # one or more 'nop' instructions during pass two.
        self._start = None
        self._end = None

        # The index in the _pass_1_* lists for where the nop instruction can
        # be found, also, the buffer of bytes that make up a nop instruction.
        self._nop_index = None
        self._nop_bytes = None

        # The DisassembleInfo object passed into __call__ as INFO.
        self._info = None

        # A flag that indicates if we are in the first or second pass of
        # this disassembler test.
        self._first_pass = True

        # The disassembled instructions collected during the second pass.
        self._pass_2_insn = []

        # A copy of _pass_1_insn that has been modified to include the extra
        # 'nop' instructions we plan to insert during the second pass.  This
        # is then checked against _pass_2_insn after the second disassembler
        # pass has completed.
        self._check = []

    def __call__(self, info):
        """Called to perform the disassembly."""

        # Record INFO, we'll need to refer to this in READ_MEMORY which is
        # called back to by the builtin disassembler.
        self._info = info
        gdb.disassembler.builtin_disassemble(info, self)

        # Record some informaiton about the first 'nop' instruction we find.
        if self._nop_index is None and info.string == "nop":
            self._nop_index = len(self._pass_1_length)
            # The offset in the following read_memory call defaults to 0.
            self._nop_bytes = info.read_memory(info.length)

        # Record information about each instruction that is disassembled.
        # This test is performed in two passes, and we need different
        # information in each pass.
        if self._first_pass:
            self._pass_1_length.append(info.length)
            self._pass_1_insn.append(info.string)
            self._pass_1_address.append(info.address)
        else:
            self._pass_2_insn.append(info.string)

    def _read_replacement(self, length, offset):
        """Return a slice of the buffer representing the replacement nop
        instructions."""

        assert(self._nop_bytes is not None)
        rb = self._nop_bytes

        # If this request is outside of a nop instruction then we don't know
        # what to do, so just raise a memory error.
        if offset >= len(rb) or (offset + length) > len(rb):
            raise gdb.MemoryError("invalid length and offset combination")

        # Return only the slice of the nop instruction as requested.
        s = offset
        e = offset + length
        return rb[s:e]

    def read_memory(self, len, offset):
        """Callback used from the builtin disassembler to read the contents of
        memory."""

        info = self._info
        assert info is not None

        # If this request is within the region we are replacing with 'nop'
        # instructions, then call the helper function to perform that
        # replacement.
        if self._start is not None:
            assert self._end is not None
            if info.address >= self._start and info.address < self._end:
                return self._read_replacement(len, offset)

        # Otherwise, we just forward this request to the default read memory
        # implementation.
        return info.read_memory(len, offset)

    def find_replacement_candidate(self):
        """Call this after the first disassembly pass.  This identifies a suitable
        instruction to replace with 'nop' instruction(s)."""

        if self._nop_index is None:
            raise gdb.GdbError("no nop was found")

        nop_idx = self._nop_index
        nop_length = self._pass_1_length[nop_idx]

        # First we look for an instruction that is larger than a nop
        # instruction, but whose length is an exact multiple of the nop
        # instruction's length.
        replace_idx = None
        for idx in range(len(self._pass_1_length)):
            if (
                idx > 0
                and idx != nop_idx
                and self._pass_1_insn[idx] != "nop"
                and self._pass_1_length[idx] > self._pass_1_length[nop_idx]
                and self._pass_1_length[idx] % self._pass_1_length[nop_idx] == 0
            ):
                replace_idx = idx
                break

        # If we still don't have a replacement candidate, then search again,
        # this time looking for an instruciton that is the same length as a
        # nop instruction.
        if replace_idx is None:
            for idx in range(len(self._pass_1_length)):
                if (
                    idx > 0
                    and idx != nop_idx
                    and self._pass_1_insn[idx] != "nop"
                    and self._pass_1_length[idx] == self._pass_1_length[nop_idx]
                ):
                    replace_idx = idx
                    break

        # Weird, the nop instruction must be larger than every other
        # instruction, or all instructions are 'nop'?
        if replace_idx is None:
            raise gdb.GdbError("can't find an instruction to replace")

        # Record the instruction range that will be replaced with 'nop'
        # instructions, and mark that we are now on the second pass.
        self._start = self._pass_1_address[replace_idx]
        self._end = self._pass_1_address[replace_idx] + self._pass_1_length[replace_idx]
        self._first_pass = False
        print("Replace from 0x%x to 0x%x with NOP" % (self._start, self._end))

        # Finally, build the expected result.  Create the _check list, which
        # is a copy of _pass_1_insn, but replace the instruction we
        # identified above with a series of 'nop' instructions.
        self._check = list (self._pass_1_insn)
        nop_count = int(self._pass_1_length[replace_idx] / self._pass_1_length[nop_idx])
        nops = ["nop"] * nop_count
        self._check[replace_idx : (replace_idx + 1)] = nops

    def check(self):
        """Call this after the second disassembler pass to validate the output."""
        if self._check != self._pass_2_insn:
            raise gdb.GdbError("mismatch")
        print("PASS")

# Create a global instance of the AnalyzingDisassembler.  This isn't
# registered as a disassembler yet though, that is done from the
# py-diasm.exp later.
analyzing_disassembler = AnalyzingDisassembler("AnalyzingDisassembler")

def add_global_disassembler(dis_class):
    """Create an instance of DIS_CLASS and register it as a global disassembler."""
    dis = dis_class()
    gdb.disassembler.register_disassembler(dis, None)


# Start with all disassemblers removed.
remove_all_python_disassemblers()

print("Python script imported")
