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

"""Disassembler related module."""

import gdb
import _gdb.disassembler

from _gdb.disassembler import *

# Module global dictionary of gdb.disassembler.Disassembler objects.
# The keys of this dictionary are bfd architecture names, or the
# special value None.
#
# When a request to disassemble comes in we first lookup the bfd
# architecture name from the gdbarch, if that name exists in this
# dictionary then we use that Disassembler object.
#
# If there's no architecture specific disassembler then we look for
# the key None in this dictionary, and if that key exists, we use that
# disassembler.
_disassembly_registry = {}

# Module global callback.  This is the entry point that GDB calls, but
# only if this is a callable thing.
#
# Initially we set this to None, so GDB will not try to call into any
# Python code.
#
# When Python disassemblers are registered into _disassembly_registry
# then this will be set to something callable.
_print_insn = None


class Disassembler(object):
    """A base class from which all user implemented disassemblers must
    inherit."""

    def __init__(self, name):
        """Constructor.  Takes a name, which should be a string, which can be
        used to identify this disassembler in diagnostic messages."""
        self.name = name

    def __call__(self, info):
        """A default implementation of __call__.  All sub-classes must
        override this method.  Calling this default implementation will throw
        a NotImplementedError exception."""
        raise NotImplementedError("Disassembler.__call__")


def register_disassembler(disassembler, architecture=None):
    """Register a disassembler.  DISASSEMBLER is a sub-class of
    gdb.disassembler.Disassembler.  ARCHITECTURE is either None or a
    string, the name of an architecture known to GDB.

    DISASSEMBLER is registered as a disassmbler for ARCHITECTURE, or
    all architectures when ARCHITECTURE is None.

    Returns the previous disassembler registered with this
    ARCHITECTURE value.
    """

    if not isinstance(disassembler, Disassembler) and disassembler is not None:
        raise TypeError("disassembler should sub-class gdb.disassembler.Disassembler")

    old = None
    if architecture in _disassembly_registry:
        old = _disassembly_registry[architecture]
        del _disassembly_registry[architecture]
    if disassembler is not None:
        _disassembly_registry[architecture] = disassembler

    global _print_insn
    if len(_disassembly_registry) > 0:
        _print_insn = _perform_disassembly
    else:
        _print_insn = None

    return old


def _lookup_disassembler(arch):
    try:
        name = arch.name()
        if name is None:
            return None
        if name in _disassembly_registry:
            return _disassembly_registry[name]
        if None in _disassembly_registry:
            return _disassembly_registry[None]
        return None
    except:
        return None


def _perform_disassembly(info):
    disassembler = _lookup_disassembler(info.architecture)
    if disassembler is None:
        return None
    return disassembler(info)


class StyleDisassembly(gdb.Parameter):
    def __init__(self):
        super(StyleDisassembly, self).__init__(
            "style disassembly", gdb.COMMAND_NONE, gdb.PARAM_BOOLEAN
        )
        self.value = True
        self._pygments_module_available = True

    def get_show_string(self, sval):
        return 'Disassembly styling is "%s".' % sval

    def get_set_string(self):
        if not self._pygments_module_available and self.value:
            self.value = False
            return "Python pygments module is not available"
        return ""

    def failed_to_load_pygments(self):
        self.value = False
        self._pygments_module_available = False

    def __bool__(self):
        return self.value

    def __nonzero__(self):
        if self.value:
            return 1
        else:
            return 0


style_disassembly_param = StyleDisassembly()

try:
    from pygments import formatters, lexers, highlight

    _lexer = lexers.get_lexer_by_name("asm")
    _formatter = formatters.TerminalFormatter()

    def syntax_highlight(info):
        # If we should not be performing syntax highlighting, or if
        # INFO does not hold a result, then there's nothing to do.
        if (
            not gdb.parameter("style enabled")
            or not style_disassembly_param
            or not info.can_emit_style_escape
            or info.string is None
        ):
            return
        # Now apply the highlighting, and update the result.
        str = highlight(info.string, _lexer, _formatter)
        info.set_result(info.length, str.strip())

    class _SyntaxHighlightingDisassembler(Disassembler):
        """A syntax highlighting disassembler."""

        def __init__(self, name):
            """Constructor."""
            super(_SyntaxHighlightingDisassembler, self).__init__(name)

        def __call__(self, info):
            """Invoke the builtin disassembler, and syntax highlight the result."""
            gdb.disassembler.builtin_disassemble(info)
            gdb.disassembler.syntax_highlight(info)

    register_disassembler(
        _SyntaxHighlightingDisassembler("syntax_highlighting_disassembler")
    )

except:

    # Update the 'set/show style disassembly' parameter now we know
    # that the pygments module can't be loaded.
    style_disassembly_param.failed_to_load_pygments()

    def syntax_highlight(info):
        # An implementation of syntax_highlight that can safely be
        # called event when syntax highlighting is not available.
        # This just returns, leaving INFO unmodified.
        return
