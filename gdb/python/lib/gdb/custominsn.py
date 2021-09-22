import gdb
import gdb.disassembler
from gdb.disassembler import Disassembler
import xml.etree.ElementTree as ElementTree
from os.path import expanduser

## This is an example script for the Buffalo custom instruction
## disassembler, it has a very simplistic disassembler core which is
## really only geared toward disassembling two instructions:
##
## asm (".insn r 0x0b, 0x0, 0x0, x3, x4, x5" ::: "memory");
## asm (".insn ca 0x1, 0x27, 0x2, x8, x9" ::: "memory");
##
## Here are two XML files that can be used with this script and the
## above instructions:
##
## <instructions>
##   <instruction length="4" type="r" mask="0xfe00707f" value="0x0000000b" mnemonic="blah"/>
##   <instruction length="2" type="ca" mask="0xfc63" value="0x9c41" mnemonic="c.blah"/>
## </instructions>
##
## Here's a second XML file:
##
## <instructions>
##   <instruction length="4" type="r" mask="0xfe00707f" value="0x0000000b" mnemonic="woof"/>
##   <instruction length="2" type="ca" mask="0xfc63" value="0x9c41" mnemonic="c.woof"/>
## </instructions>
##
## This script supports fetching the XML file from the remote target.
## This is done using the packet:
##
## qXfer:features:read:annex:start,length
##
## Which is the same packet as is used for reading the target XML
## description.  The only difference will be in the name of the annex
## which is passed.
##
## The default remote annex is 'insn.xml', but it can be changed using:
##
## set custom-instruction-filename remote:ANNEX

#####################################################################
##
## Create a parameter that can be used to enable or disable the custom
## disassembler functionality.
##


class RISCVDisassemblerEnabled(gdb.Parameter):
    """When this setting is on the disassembler will disassemble custom
instructions based on the contents of the XML file identified by
the file pointed to by 'show custom-instruction-path'.

When this setting is off then the disassembler will display custom
instructions using the standard builtin behaviour."""

    def __init__(self):
        """Constructor."""
        self.set_doc = (
            "Set whether the disassembler should perform custom instruction display."
        )
        self.show_doc = (
            "Show whether the disassembler should perform custom instruction display."
        )

        parent = super(RISCVDisassemblerEnabled, self)
        parent.__init__(
            "custom-instruction-display", gdb.COMMAND_NONE, gdb.PARAM_BOOLEAN
        )
        self.value = True

    def get_show_string(self, svalue):
        """Handle 'show custom-instruction-display'."""
        return 'Custom instruction display is "%s".' % svalue

    def __nonzero__(self):
        """Used when casting to boolean within Python2."""
        if self.value:
            return 1
        else:
            return 0

    def __bool__(self):
        """Used when casting to boolean within Python3."""
        return self.value


custom_instruction_display_p = RISCVDisassemblerEnabled()

#####################################################################
##
## Create a parameter that points at the filename for the XML file
## that describes the custom instruction.
##
## The value of this parameter can be either a path on the local
## system, or the name of a file on the remote target with a 'remote:'
## prefix.
##


class RISCVDisassemblerFilename(gdb.Parameter):
    """This setting contains the path to the XML file that contains the
custom instruction descriptions.  This setting can take two values
depending on whether the XML file is located on the local machine, or
is served from a remote target.

If the XML file is on the local machine, then this setting should be
set to the absolute path to the XML file.

If the XML file should be fetched from the remote target then the
setting should be set to the name of the XML file with the prefix
'remote:', e.g. if the XML file is called foo.xml this setting should
be 'remote:foo.xml'.

As a special case, if this setting is set to just 'remote:' then this
is equivalent to 'remote:insn.xml'."""

    def __init__(self):
        """Constructor."""
        self.set_doc = "Set the path to the XML file containing the custom instruction descriptions."
        self.show_doc = "Show the path to the XML file containing the custom instruction descriptions."

        parent = super(RISCVDisassemblerFilename, self)
        parent.__init__(
            "custom-instruction-filename", gdb.COMMAND_NONE, gdb.PARAM_FILENAME
        )
        homedir = expanduser("~")
        self.value = "%s/tmp/simple-insn.xml" % homedir

    def get_show_string(self, svalue):
        if svalue.startswith("remote:"):
            return 'Custom instructions read from remote file "%s".' % svalue
        else:
            return 'Custom instructions read from local file "%s".' % svalue

    def get_set_string(self):
        riscv_disassembler.discard_cached_disassembler()
        if self.value == "remote:":
            self.value = "remote:insn.xml"
            return (
                'custom-instruction-path set to default remote path "%s".' % self.value
            )
        return ""

    def fetch_xml(self):
        """Fetch the XML file, either from the local machine, or from the
        remote target, parse it using the ElementTree module, and return the
        root node."""

        if self.value.startswith("remote:"):
            conn = gdb.selected_inferior().connection
            if conn is None:
                return None
            if conn.type != "remote" and conn.type != "extended-remote":
                return None
            try:
                filename = self.value[7:]
                if filename == "":
                    raise gdb.GdbError("missing filename")
                xml_string = ""
                start_pos = 0
                fetch_len = 200
                while True:
                    # Fetch the next part of the XML document.
                    str = conn.send_remote_packet(
                        "qXfer:features:read:%s:%d,%d"
                        % (filename, start_pos, fetch_len)
                    )
                    # Update the start for when we try to get the next bit.
                    start_pos += fetch_len
                    # The first character is either 'l' (last) or 'm'
                    # (more) to indicate if this is the last part of
                    # the content, or if there is still more to fetch.
                    #
                    # Strip the first character from the content
                    # string, and add the new content to the
                    # xml_string we are building up.
                    c = str[0]
                    str = str[1:]
                    xml_string += str
                    # If this is the last part, then we are now done.
                    if c == "l":
                        break
                tree = ElementTree.ElementTree(ElementTree.fromstring(xml_string))
            except:
                return None
        else:
            tree = ElementTree.parse(self.value)
        return tree.getroot()


custom_instruction_path = RISCVDisassemblerFilename()

#####################################################################
##
## The following is a temporary place holder while the real
## disassembler is developed.  This reads an XML file, but the format
## is not very good, and it doesn't allow for all of the fancy format
## strings that the real disassembler is going to support.
##


class CustomInstructionHandler:
    def __init__(self):
        self._root = custom_instruction_path.fetch_xml()
        self._get_operands = {
            "r": self._operands_for_type_r,
            "ca": self._operands_for_type_ca,
        }
        self._x_reg_names = [
            "zero",
            "ra",
            "sp",
            "gp",
            "tp",
            "t0",
            "t1",
            "t2",
            "fp",
            "s1",
            "a0",
            "a1",
            "a2",
            "a3",
            "a4",
            "a5",
            "a6",
            "a7",
            "s2",
            "s3",
            "s4",
            "s5",
            "s6",
            "s7",
            "s8",
            "s9",
            "s10",
            "s11",
            "t3",
            "t4",
            "t5",
            "t6",
        ]
        self._cx_reg_names = ["fp", "s1", "a0", "a1", "a2", "a3", "a4", "a5"]

    def _operands_for_type_r(self, insn):
        rd = (insn >> 7) & 0x1F
        rs1 = (insn >> 15) & 0x1F
        rs2 = (insn >> 20) & 0x1F
        return "%s,%s,%s" % (
            self._x_reg_names[rd],
            self._x_reg_names[rs1],
            self._x_reg_names[rs2],
        )

    def _operands_for_type_ca(self, insn):
        rd_rs1 = (insn >> 7) & 0x7
        rs2 = (insn >> 2) & 0x7
        return "%s,%s,%s" % (
            self._cx_reg_names[rd_rs1],
            self._cx_reg_names[rd_rs1],
            self._cx_reg_names[rs2],
        )

    def disassemble(self, insn, len, info):
        if self._root is None:
            return None

        for child in self._root.findall("instruction"):
            attrib = child.attrib
            i_len = int(attrib.get("length"))
            if i_len is None or i_len != len:
                continue
            i_mask = int(attrib.get("mask"), 16)
            i_val = int(attrib.get("value"), 16)
            if i_mask is None or i_val is None:
                continue
            if insn & i_mask != i_val:
                continue
            i_mnem = attrib.get("mnemonic")
            if i_mnem is None:
                continue
            i_type = attrib.get("type")
            if i_type is None:
                continue
            operands = self._get_operands[i_type](insn)
            if operands is None:
                continue
            str = i_mnem + "\t" + operands
            return str
        return None


#####################################################################
##
## A class that performs syntax highlighting.  Our actual disassembler
## class will inherit from this, and call back into this class to
## perform syntax highlighting.


class SyntaxHighlightingDisassembler(Disassembler):
    def __init__(self, name):
        super(SyntaxHighlightingDisassembler, self).__init__(name)

    def __call__(self, info):
        if info.string is None:
            gdb.disassembler.builtin_disassemble(info)
        gdb.disassembler.syntax_highlight(info)
        return None


#####################################################################
##
## This is the actual hook into GDB, this code is closer to production
## ready, though we might find things that need improviing once users
## start to test this.
##


class RISCVDisassembler(SyntaxHighlightingDisassembler):
    def __init__(self):
        super(RISCVDisassembler, self).__init__("RISCVDisassembler")
        self._disassembler_cache = {}
        self._callback = lambda ev: self._discard_cached_disassembler(ev.connection)
        gdb.events.connection_removed.connect(self._callback)

    def __del__(self):
        gdb.events.connection_removed.disconnect(self._callback)

    def get_disassembler(self):
        conn = gdb.selected_inferior().connection
        if not conn in self._disassembler_cache:
            disassembler = CustomInstructionHandler()
            self._disassembler_cache[conn] = disassembler
        return self._disassembler_cache[conn]

    def _discard_cached_disassembler(self, conn):
        if conn in self._disassembler_cache:
            del self._disassembler_cache[conn]

    def discard_cached_disassembler(self):
        conn = gdb.selected_inferior().connection
        self._discard_cached_disassembler(conn)

    def __call__(self, info):

        if not custom_instruction_display_p:
            super(RISCVDisassembler, self).__call__(info)
            return

        disassembler = self.get_disassembler()

        # Read the first byte, figure out the instruction length, then
        # load the entire instruction.
        insn_bytes = None
        first_byte = bytes(info.read_memory(1, 0))[0]
        if first_byte & 0x3 == 0x3:
            insn_bytes = bytes(info.read_memory(4, 0))
        else:
            insn_bytes = bytes(info.read_memory(2, 0))

        # Convert the list of instruction bytes into a single value.
        insn = 0
        shift = 0
        for b in insn_bytes:
            insn = insn | (b << shift)
            shift += 8

        str = disassembler.disassemble(insn, len(insn_bytes), info)
        if str is not None:
            info.set_result(len(insn_bytes), str)
        else:
            gdb.disassembler.builtin_disassemble(info)

        super(RISCVDisassembler, self).__call__(info)


#####################################################################
##
## Register the disassembler callback for every RISC-V architecture.
## We create just a single disassembler object, and register it for
## every architecture we're insterested in.
##

riscv_disassembler = RISCVDisassembler()

for name in gdb.architecture_names():
    if name.startswith("riscv"):
        gdb.disassembler.register_disassembler(riscv_disassembler, name)
