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


class Insn:
    def __init__(self, elem):
        self.opcode = int(elem.attrib['opcode'],16)
        self.str = elem.attrib['str']
        self.type = elem.attrib['type']
        self.funct3 = None
        self.funct4 = None
        self.funct7 = None
        self._x_reg_names = ["zero", "ra", "sp", "gp", "tp", "t0",
                             "t1", "t2", "fp", "s1", "a0", "a1",
                             "a2", "a3", "a4", "a5", "a6", "a7",
                             "s2", "s3", "s4", "s5", "s6", "s7",
                             "s8", "s9", "s10", "s11", "t3", "t4",
                             "t5", "t6"]
        self._cx_reg_names = ["fp", "s1", "a0", "a1", "a2", "a3",
                              "a4", "a5"]

    def gen_opfunc3funct7_instr(self):
        opcode = self.opcode
        funct3 = self.funct3 << 12
        funct7 = self.funct7 << 25
        insn = opcode + funct3 + funct7
        return insn

    def gen_opfunc3_instr(self):
        opcode = self.opcode
        funct3 = self.funct3 << 12
        insn = opcode + funct3
        return insn

    def gen_op_instr(self):
        insn = self.opcode
        return insn

    def gen_c_opfunc4_instr(self):
        opcode = self.opcode
        funct4 = self.funct4 << 12
        insn = opcode + funct4
        return insn

    def gen_c_opfunc3_instr(self):
        opcode = self.opcode
        funct4 = self.funct3 << 13
        insn = opcode + funct4
        return insn

    def gen_c_op_instr(self):
        insn = self.opcode
        return insn

    def gen_opfunc3funct7_mask(self):
        opcode = 0b1111111
        funct3 = 0b111 << 12
        funct7 = 0b1111111 << 25
        insn = opcode + funct3 + funct7
        return insn

    def gen_opfunc3_mask(self):
        opcode = 0b1111111
        funct3 = 0b111 << 12
        insn = opcode + funct3
        return insn

    def gen_op_mask(self):
        opcode = 0b1111111
        insn = opcode
        return insn

    def gen_c_opfunc4_mask(self):
        opcode = 0b11
        funct4 = 0b1111 << 12
        insn = opcode + funct4
        return insn

    def gen_c_opfunc3_mask(self):
        opcode = 0b11
        funct3 = 0b111 << 13
        insn = opcode + funct3
        return insn

    def gen_c_op_mask(self):
        insn = 0b11
        return insn

class Unknown_Insn(Insn):
    def __init__(self, len):
        super()
        self.len = len
        self.type = 'unknown'

    def gen_instr_assembly(self, byte_stream):
        return hex(byte_stream)


class R_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.funct7 = int(elem.attrib['funct7'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3funct7_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3funct7_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)
        funct3 = hex(int(raw_bytes[14:11:-1], 2))
        rs1 = int(raw_bytes[19:14:-1], 2)       
        rs2 = int(raw_bytes[24:19:-1], 2)
        funct7 = hex(int(raw_bytes[:24:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$funct3', funct3)
        insn = insn.replace ('$rs1', self._x_reg_names[rs1])
        insn = insn.replace ('$rs2', self._x_reg_names[rs2])
        insn = insn.replace ('$funct7', funct7)
        return insn

class I_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)
        funct3 = hex(int(raw_bytes[14:11:-1], 2))
        rs1 = int(raw_bytes[19:14:-1], 2)       
        imm = int(raw_bytes[:19:-1], 2)
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$funct3', funct3)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$rs1', self._x_reg_names[rs1])
        insn = insn.replace ('$imm', f'{(imm&0b011111111111)-(imm&0b100000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        return insn

class S_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        funct3 = hex(int(raw_bytes[14:11:-1], 2))
        rs1 = int(raw_bytes[19:14:-1], 2)       
        rs2 = int(raw_bytes[24:19:-1], 2)
        imm = (int(raw_bytes[11:6:-1], 2)) \
            + (int(raw_bytes[:24:-1], 2) << 5)
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$funct3', funct3)
        insn = insn.replace ('$rs1', self._x_reg_names[rs1])
        insn = insn.replace ('$rs2', self._x_reg_names[rs2])
        insn = insn.replace ('$imm', f'{(imm&0b011111111111)-(imm&0b100000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        return insn

class B_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        funct3 = hex(int(raw_bytes[14:11:-1], 2))
        rs1 = int(raw_bytes[19:14:-1], 2)       
        rs2 = int(raw_bytes[24:19:-1], 2)
        imm = (int(raw_bytes[11:7:-1], 2) << 1) \
            + (int(raw_bytes[30:24:-1], 2) << 5) \
            + (int(raw_bytes[7], 2) << 11) \
            + (int(raw_bytes[31], 2) << 12)
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$funct3', funct3)
        insn = insn.replace ('$rs1', self._x_reg_names[rs1])
        insn = insn.replace ('$rs2', self._x_reg_names[rs2])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        return insn

class U_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_op_instr()

    def gen_insn_mask(self):
        return self.gen_op_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)       
        imm = (int(raw_bytes[:11:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        return insn

class J_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.opcode = int(elem.attrib['opcode'],16)
        self.str = elem.attrib['str']
        self.type = elem.attrib['type']
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_op_instr()

    def gen_insn_mask(self):
        return self.gen_op_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '032b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[6::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)       
        imm = (int(raw_bytes[19:11:-1], 2) << 12) \
            + (int(raw_bytes[20], 2) << 11) \
            + (int(raw_bytes[30:20:-1], 2) << 1) \
            + (int(raw_bytes[31], 2) << 20) 
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        return insn


class CR_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct4 = int(elem.attrib['funct4'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc4_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc4_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rs2 = int(raw_bytes[6:1:-1], 2)
        rds1 = int(raw_bytes[11:6:-1], 2)       
        funct4 = hex(int(raw_bytes[:11:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rds1])
        insn = insn.replace ('$rs1', self._x_reg_names[rds1])
        insn = insn.replace ('$rs2', self._x_reg_names[rs2])
        insn = insn.replace ('$funct4', funct4)
        return insn

class CI_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)       
        imm = (int(raw_bytes[6:1:-1], 2)) \
            + (int(raw_bytes[12], 2) << 5)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$rs1', self._x_reg_names[rd])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

class CSS_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rd = int(raw_bytes[11:6:-1], 2)    
        imm = (int(raw_bytes[12:8:-1], 2) << 2) \
            + (int(raw_bytes[8:6:-1], 2) << 6)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._x_reg_names[rd])
        insn = insn.replace ('$rs1', self._x_reg_names[rd])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn


class CIW_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rd = int(raw_bytes[4:1:-1], 2)       
        imm = (int(raw_bytes[5], 2) << 3) \
            + (int(raw_bytes[6], 2) << 2) \
            + (int(raw_bytes[12:10:-1], 2) << 4) \
            + (int(raw_bytes[10:6:-1], 2) << 6)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._cx_reg_names[rd])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

class CL_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rd = int(raw_bytes[4:1:-1], 2)   
        rs1 = int(raw_bytes[9:6:-1], 2)      
        imm = (int(raw_bytes[5], 2) << 2) \
            + (int(raw_bytes[6], 2) << 6) \
            + (int(raw_bytes[12:10:-1], 2) << 3)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._cx_reg_names[rd])
        insn = insn.replace ('$rs1', self._cx_reg_names[rs1])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

class CS_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))
        rd = int(raw_bytes[4:1:-1], 2)   
        rs1 = int(raw_bytes[9:6:-1], 2)      
        imm = (int(raw_bytes[5], 2) << 2) \
            + (int(raw_bytes[6], 2) << 6) \
            + (int(raw_bytes[12:10:-1], 2) << 3)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rd', self._cx_reg_names[rd])
        insn = insn.replace ('$rs1', self._cx_reg_names[rs1])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

class CB_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))  
        rs1 = int(raw_bytes[9:6:-1], 2)      
        imm = (int(raw_bytes[2], 2) << 5) \
            + (int(raw_bytes[6:2:-1], 2) << 1) \
            + (int(raw_bytes[12:9:-1], 2) << 6)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$rs1', self._cx_reg_names[rs1])
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

class CJ_Insn(Insn):
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'],16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream):
        raw_bytes = format(byte_stream, '016b')[::-1]
        insn = self.str
        opcode = hex(int(raw_bytes[1::-1], 2))     
        imm = (int(raw_bytes[2], 2) << 5) \
            + (int(raw_bytes[6:2:-1], 2) << 1) \
            + (int(raw_bytes[12:6:-1], 2) << 6)
        funct3 = hex(int(raw_bytes[:12:-1], 2))
        insn = insn.replace ('$opcode', opcode)
        insn = insn.replace ('$imm', f'{(imm&0b0111111111111)-(imm&0b1000000000000)}')
        insn = insn.replace ('$uimm', f'{imm}')
        insn = insn.replace ('$funct3', funct3)
        return insn

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
        self._insns = self.create_insns(self._root)

    def gen_Unknown_Insn(self, len):
        return Unknown_Insn(len)

    def gen_R_insn(self, elem):
        return R_Insn(elem)

    def gen_I_insn(self, elem):
        return I_Insn(elem)

    def gen_S_insn(self, elem):
        return S_Insn(elem)

    def gen_B_insn(self, elem):
        return B_Insn(elem)

    def gen_U_insn(self, elem):
        return U_Insn(elem)

    def gen_J_insn(self, elem):
        return J_Insn(elem)

    def gen_CR_insn(self, elem):
        return CR_Insn(elem)

    def gen_CI_insn(self, elem):
        return CI_Insn(elem)

    def gen_CSS_insn(self, elem):
        return CSS_Insn(elem)

    def gen_CIW_insn(self, elem):
        return CIW_Insn(elem)

    def gen_CL_insn(self, elem):
        return CL_Insn(elem)

    def gen_CS_insn(self, elem):
        return CS_Insn(elem)

    def gen_CB_insn(self, elem):
        return CB_Insn(elem)

    def gen_CJ_insn(self, elem):
        return CJ_Insn(elem)

    def create_insns(self, root):
        masks = []
        gen_insn = {
            "R" : self.gen_R_insn,
            "I" : self.gen_I_insn,
            "S" : self.gen_S_insn,
            "B" : self.gen_B_insn,
            "SB" : self.gen_B_insn,
            "U" : self.gen_U_insn,
            "J" : self.gen_J_insn,
            "UJ" : self.gen_J_insn,
            "CR" : self.gen_CR_insn,
            "CI" : self.gen_CI_insn,
            "CSS" : self.gen_CSS_insn,
            "CIW" : self.gen_CIW_insn,
            "CL" : self.gen_CL_insn,
            "CS" : self.gen_CS_insn,
            "CB" : self.gen_CB_insn,
            "CJ" : self.gen_CJ_insn
        }
        insns = root.findall('instruction')
        for elem in insns:
            try:
                insn = gen_insn[elem.attrib['type']](elem)        
                masks.append(insn)
            except(KeyError):
                print("Unknown Instruction Type: " + elem.attrib['type'])
        return masks

    def compare_with_insns(self, byte, len):
        # print("")
        for insn in self._insns:
            if(self.compare_with_insn(byte, insn, len)):
                return insn
        return None

    def compare_with_insn(self, byte, insn, len):
        if(len != insn.len):
            return 0
        # print(insn.type)
        # print(format(insn.mask, '016b'))
        # print(format(byte, '016b'))
        # print(format(insn.insn, '016b'))
        # print(format((byte & insn.mask), '016b'))
        return (insn.insn == (byte & insn.mask))

    def disassemble(self,insn, len, info):
        insn_type = self.compare_with_insns(insn, len)
        if(insn_type is not None):
            return insn_type.gen_instr_assembly(insn)
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
