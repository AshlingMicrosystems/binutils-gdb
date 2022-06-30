import gdb
import gdb.disassembler
from gdb.disassembler import Disassembler
import xml.etree.ElementTree as ElementTree

####################################################################
#
# Create a parameter that can be used to enable or disable the custom
# disassembler functionality.
#



class RISCVDisassemblerEnabled(gdb.Parameter):
    """When this setting is on the disassembler will disassemble custom
instructions based on the contents of the XML file identified by
the file pointed to by 'show custom-instruction-path'.

When this setting is off then the disassembler will display custom
instructions using the standard builtin behaviour."""

    def __init__(self):
        """Constructor."""
        self.set_doc = "Set whether the disassembler should perform custom \
            instruction display."
        self.show_doc = "Show whether the disassembler should perform custom \
            instruction display."

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

####################################################################
#
# Create a parameter that points at the filename for the XML file
# that describes the custom instruction.
#
# The value of this parameter can be either a path on the local
# system, or the name of a file on the remote target with a 'remote:'
# prefix.
#



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
is equivalent to 'remote:insn.xml'.

Finally, setting this to the empty string will mean GDB does not try
to load any custom instruction description."""
    def __init__(self):
        """Constructor."""
        self.set_doc = "Set the path to the XML file containing the custom \
            instruction descriptions."
        self.show_doc = "Show the path to the XML file containing the custom \
            instruction descriptions."

        parent = super(RISCVDisassemblerFilename, self)
        parent.__init__("custom-instruction-filename",
                        gdb.COMMAND_NONE,
                        gdb.PARAM_FILENAME)
        self.value = ""

    def get_show_string(self, svalue):
        if svalue.startswith("remote:"):
            return 'Custom instructions read from remote file "%s".' % svalue
        else:
            return 'Custom instructions read from local file "%s".' % svalue

    def get_set_string(self):
        riscv_disassembler.discard_cached_disassembler()
        if self.value == "remote:":
            self.value = "remote:insn.xml"
            return "custom-instruction-path set to default remote path \
                \"%s\"." % self.value
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
                        "qXfer:features:read:%s:%d,%d" % (
                            filename, start_pos, fetch_len))
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
                tree = ElementTree.ElementTree(
                    ElementTree.fromstring(xml_string))
            except:
                return None
        else:
            if self.value != "":
                try:
                    tree = ElementTree.parse(self.value)
                except Exception as e:
                    print("Error loading custom-instruction-filename: %s" % e)
                    return None
            else:
                return None
        return tree.getroot()


class Insn:
    """This is the base instruction class from which all specific instructions
    inherit. Takes an XML instruction, and takes out the opcode, instruction
    string and type.

    Provides methods for initialising all valid instruction masks and
    instruction specific identifiers. """
    def __init__(self, elem):
        self.opcode = int(elem.attrib['opcode'], 16)
        self.format_string = elem.attrib['str']
        self.type = elem.attrib['type']
        self.funct3 = None
        self.funct4 = None
        self.funct7 = None
        # mapping of integer indexes to registers
        self._x_reg_names = ["zero", "ra", "sp", "gp", "tp", "t0",
                             "t1", "t2", "fp", "s1", "a0", "a1",
                             "a2", "a3", "a4", "a5", "a6", "a7",
                             "s2", "s3", "s4", "s5", "s6", "s7",
                             "s8", "s9", "s10", "s11", "t3", "t4",
                             "t5", "t6"]
        # mapping of integer indexes to compressed registers
        self._cx_reg_names = ["fp", "s1", "a0", "a1", "a2", "a3",
                              "a4", "a5"]

    def expand_format_string(self, fields, info):
        """Return a string, the expanded version of self.format_string, but
        with the '$field's replaced using FIELDS.  FIELDS is a
        dictionary of field names to values.  The field names in
        FIELDS are as they are found in format_string, but without the
        '$', e.g. a we might habve keys 'rs1', 'imm', etc.

        INFO is the DisassembleInfo from GDB."""

        res = self.format_string
        if 'imm' in fields and 'dest' not in fields:
            # If hex value, cast to int
            try:
                addr = (int(fields['imm'], 16))
            except TypeError:
                addr = (fields['imm'])
            # If address is negative, wrap around the memory space
            if addr < 0:
                if info.architecture.name() == "riscv:rv64":
                    addr = 0xffffffffffffffff + addr
                else:
                    addr = 0xffffffff + addr
            fields['dest'] \
                = gdb.disassembler.format_address(info.architecture,
                                                  addr)
        for k in fields.keys():
            f = '$' + k
            v = fields[k]
            res = res.replace(f, str(v))
        return res

    def gen_opfunc3funct7_instr(self):

        """Instruction specific identifier, func3 and funct7 specified.
        Currently only used by R-type instructions"""
        opcode = self.opcode
        funct3 = self.funct3 << 12
        funct7 = self.funct7 << 25
        insn = opcode | funct3 | funct7
        return insn

    def gen_opfunc3_instr(self):
        """Instruction specific identifier, func3 specified.
        Currently used by I, S, and B -type instructions"""
        opcode = self.opcode
        funct3 = self.funct3 << 12
        insn = opcode | funct3
        return insn

    def gen_op_instr(self):
        """Instruction specific identifier, fuction code unspecified.
        Currently used by U and J -type instructions"""
        insn = self.opcode
        return insn

    def gen_c_opfunc4_instr(self):
        """Compressed instruction specific identifier, func4 specified.
        Currently used by CR-type instructions only"""
        opcode = self.opcode
        funct4 = self.funct4 << 12
        insn = opcode | funct4
        return insn

    def gen_c_opfunc3_instr(self):
        """Compressed instruction specific identifier, func3 specified.
        Currently used by CI, CSS, CIW, CL, CS, Cb, CJ -type instructions"""
        opcode = self.opcode
        funct4 = self.funct3 << 13
        insn = opcode | funct4
        return insn

    def gen_c_op_instr(self):
        """Compressed instruction specific identifier, fuction code unspecified.
        Currently unused"""
        insn = self.opcode
        return insn

    def gen_opfunc3funct7_mask(self):
        """Instruction mask, func3 and funct7 specified.
        Currently only used by R-type instructions"""
        opcode = 0b1111111
        funct3 = 0b111 << 12
        funct7 = 0b1111111 << 25
        insn = opcode | funct3 | funct7
        return insn

    def gen_opfunc3_mask(self):
        """Instruction mask, func3 specified.
        Currently used by I, S, and B -type instructions"""
        opcode = 0b1111111
        funct3 = 0b111 << 12
        insn = opcode | funct3
        return insn

    def gen_op_mask(self):
        """Instruction mask, fuction code unspecified.
        Currently used by U and J -type instructions"""
        opcode = 0b1111111
        insn = opcode
        return insn

    def gen_c_opfunc4_mask(self):
        """Compressed instruction mask, func4 specified.
        Currently used by CR-type instructions only"""
        opcode = 0b11
        funct4 = 0b1111 << 12
        insn = opcode | funct4
        return insn

    def gen_c_opfunc3_mask(self):
        """Compressed instruction mask, func3 specified.
        Currently used by CI, CSS, CIW, CL, CS, Cb, CJ -type instructions"""
        opcode = 0b11
        funct3 = 0b111 << 13
        insn = opcode | funct3
        return insn

    def gen_c_op_mask(self):
        """Compressed instruction mask, fuction code unspecified.
        Currently unused"""
        insn = 0b11
        return insn


class R_Insn(Insn):
    """R-type instruction. Specifies both 3 bit and 7 bit function codes.
    format:
        |31    25|24 20|19 15|14    12|11 7|6      0|
        | funct7 | rs2 | rs1 | funct3 | rd | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.funct7 = int(elem.attrib['funct7'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3funct7_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3funct7_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        rs1 = int(raw_bits[19:14:-1], 2)
        fields['rs1'] = self._x_reg_names[rs1]
        rs2 = int(raw_bits[24:19:-1], 2)
        fields['rs2'] = self._x_reg_names[rs2]

        return self.expand_format_string(fields, info)


class I_Insn(Insn):
    """I-type instruction. Specifies 3 bit function code.
    format:
        |31       20|19 15|14    12|11 7|6      0|
        | imm[11:0] | rs1 | funct3 | rd | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        rs1 = int(raw_bits[19:14:-1], 2)
        fields['rs1'] = self._x_reg_names[rs1]
        uimm = int(raw_bits[:19:-1], 2)
        fields['uimm'] = uimm
        mask1 = 1 << 11
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class S_Insn(Insn):
    """S-type instruction. Specifies 3 bit function code.
    format:
        |31       25|24 20|19 15|14    12|11       7|6      0|
        | imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rs1 = int(raw_bits[19:14:-1], 2)
        fields['rs1'] = self._x_reg_names[rs1]
        rs2 = int(raw_bits[24:19:-1], 2)
        fields['rs2'] = self._x_reg_names[rs2]
        uimm = (int(raw_bits[11:6:-1], 2)) \
             | (int(raw_bits[:24:-1], 2) << 5)
        fields['uimm'] = uimm
        mask1 = 1 << 11
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class B_Insn(Insn):
    """B-type instruction. Specifies 3 bit function code.
    format:
        |31          25|24 20|19 15|14    12|11          7|6      0|
        | imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rs1 = int(raw_bits[19:14:-1], 2)
        fields['rs1'] = self._x_reg_names[rs1]
        rs2 = int(raw_bits[24:19:-1], 2)
        fields['rs2'] = self._x_reg_names[rs2]
        uimm = (int(raw_bits[11:7:-1], 2) << 1) \
             | (int(raw_bits[30:24:-1], 2) << 5) \
             | (int(raw_bits[7], 2) << 11) \
             | (int(raw_bits[31], 2) << 12)
        fields['uimm'] = hex(info.address + uimm)
        mask1 = 1 << 12
        mask2 = mask1 - 1
        fields['imm'] = hex(info.address + (uimm & mask2) - (uimm & mask1))

        return self.expand_format_string(fields, info)


class U_Insn(Insn):
    """U-type instruction. Specifies no function code.
    format:
        |31        12|11 7|6      0|
        | imm[31:12] | rd | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_op_instr()

    def gen_insn_mask(self):
        return self.gen_op_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        uimm = (int(raw_bits[:11:-1], 2)) << 12
        fields['uimm'] = uimm >> 12
        fields['imm'] = uimm >> 12

        return self.expand_format_string(fields, info)


class J_Insn(Insn):
    """J-type instruction. Specifies no function code.
    format:
        |31                   12|11 7|6      0|
        | imm[20|10:1|11|19:12] | rd | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 4

    def gen_insn(self):
        return self.gen_op_instr()

    def gen_insn_mask(self):
        return self.gen_op_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '032b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        uimm = (int(raw_bits[19:11:-1], 2) << 12) \
             | (int(raw_bits[20], 2) << 11) \
             | (int(raw_bits[30:20:-1], 2) << 1) \
             | (int(raw_bits[31], 2) << 20)
        fields['uimm'] = hex(info.address + uimm)
        mask1 = 1 << 20
        mask2 = mask1 - 1
        fields['imm'] = hex(info.address + (uimm & mask2) - (uimm & mask1))

        return self.expand_format_string(fields, info)


class CR_Insn(Insn):
    """CR-type instruction. Specifies 4 bit function code.
    format:
        |15    12|11     7|6   2|1      0|
        | funct4 | rd/rs1 | rs2 | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct4 = int(elem.attrib['funct4'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc4_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc4_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rs2 = int(raw_bits[6:1:-1], 2)
        fields['rs2'] = self._x_reg_names[rs2]
        rds1 = int(raw_bits[11:6:-1], 2)
        fields['rs1'] = self._x_reg_names[rds1]
        fields['rd'] = self._x_reg_names[rds1]

        return self.expand_format_string(fields, info)


class CI_Insn(Insn):
    """CI-type instruction. Specifies 3 bit function code.
    format:
        |15    13| 12  |11     7|6   2|1      0|
        | funct3 | imm | rd/rs1 | imm | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        fields['rs1'] = self._x_reg_names[rd]
        uimm = (int(raw_bits[6:1:-1], 2)) \
             | (int(raw_bits[12], 2) << 5)
        fields['uimm'] = uimm
        mask1 = 1 << 5
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CSS_Insn(Insn):
    """CSS-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12  7|6   2|1      0|
        | funct3 | imm | rs2 | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rd = int(raw_bits[11:6:-1], 2)
        fields['rd'] = self._x_reg_names[rd]
        fields['rs2'] = self._x_reg_names[rd]
        fields['rs1'] = self._x_reg_names[rd]
        uimm = (int(raw_bits[12:8:-1], 2) << 2) \
             | (int(raw_bits[8:6:-1], 2) << 6)
        fields['uimm'] = uimm
        mask1 = 1 << 7
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CIW_Insn(Insn):
    """CIW-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12  5|4    2|1      0|
        | funct3 | imm | rsd' | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rd = int(raw_bits[4:1:-1], 2)
        fields['rd'] = self._cx_reg_names[rd]
        uimm = (int(raw_bits[5], 2) << 3) \
             | (int(raw_bits[6], 2) << 2) \
             | (int(raw_bits[12:10:-1], 2) << 4) \
             | (int(raw_bits[10:6:-1], 2) << 6)
        fields['uimm'] = uimm
        mask1 = 1 << 9
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CL_Insn(Insn):
    """CL-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12 10|9    7|6   5|4    2|1      0|
        | funct3 | imm | rs1' | imm | rsd' | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rd = int(raw_bits[4:1:-1], 2)
        fields['rd'] = self._cx_reg_names[rd]
        rs1 = int(raw_bits[9:6:-1], 2)
        fields['rs1'] = self._cx_reg_names[rs1]
        uimm = (int(raw_bits[5], 2) << 2) \
             | (int(raw_bits[6], 2) << 6) \
             | (int(raw_bits[12:10:-1], 2) << 3)
        fields['uimm'] = uimm
        mask1 = 1 << 6
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CS_Insn(Insn):
    """CS-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12 10|9    7|6   5|4    2|1      0|
        | funct3 | imm | rs1' | imm | rs2' | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rd = int(raw_bits[4:1:-1], 2)
        fields['rd'] = self._cx_reg_names[rd]
        fields['rs1'] = self._cx_reg_names[rd]
        rs2 = int(raw_bits[9:6:-1], 2)
        fields['rs2'] = self._cx_reg_names[rs2]
        uimm = (int(raw_bits[6:4:-1], 2) << 0) \
             | (int(raw_bits[12:9:-1], 2) << 2)
        fields['uimm'] = uimm
        mask1 = 1 << 4
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CB_Insn(Insn):
    """CB-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12    10|9    7|6      2|1      0|
        | funct3 | offset | rs1' | offset | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        rs1 = int(raw_bits[9:6:-1], 2)
        fields['rs1'] = self._cx_reg_names[rs1]
        uimm = (int(raw_bits[2], 2) << 5) \
             | (int(raw_bits[6:2:-1], 2) << 1) \
             | (int(raw_bits[12:9:-1], 2) << 6)
        fields['uimm'] = uimm
        mask1 = 1 << 8
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


class CJ_Insn(Insn):
    """CJ-type instruction. Specifies 3 bit function code.
    format:
        |15    13|12          2|1      0|
        | funct3 | jump target | opcode |"""
    def __init__(self, elem):
        super().__init__(elem)
        self.funct3 = int(elem.attrib['funct3'], 16)
        self.insn = self.gen_insn()
        self.mask = self.gen_insn_mask()
        self.len = 2

    def gen_insn(self):
        return self.gen_c_opfunc3_instr()

    def gen_insn_mask(self):
        return self.gen_c_opfunc3_mask()

    def gen_instr_assembly(self, byte_stream, info):
        raw_bits = format(byte_stream, '016b')[::-1]

        fields = {}
        uimm = (int(raw_bits[2], 2) << 5) \
             | (int(raw_bits[6:2:-1], 2) << 1) \
             | (int(raw_bits[12:6:-1], 2) << 6)
        fields['uimm'] = uimm
        mask1 = 1 << 10
        mask2 = mask1 - 1
        fields['imm'] = (uimm & mask2) - (uimm & mask1)

        return self.expand_format_string(fields, info)


custom_instruction_path = RISCVDisassemblerFilename()



class CustomInstructionHandler:
    """Custom instruction handler class. Contains """
    def __init__(self):
        """Pull instruction specifications from XML file, create a dictionary
        with unique identifiers for each instruction"""
        self._root = custom_instruction_path.fetch_xml()
        if self._root is not None:
            self._insns = self.create_insns(self._root)
        else:
            self._insns = []

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
        """Take an XML file root, generate disctionary of instruction
        objects"""
        masks = []
        gen_insn = {
            "R": self.gen_R_insn,
            "I": self.gen_I_insn,
            "S": self.gen_S_insn,
            "B": self.gen_B_insn,
            "SB": self.gen_B_insn,
            "U": self.gen_U_insn,
            "J": self.gen_J_insn,
            "UJ": self.gen_J_insn,
            "CR": self.gen_CR_insn,
            "CI": self.gen_CI_insn,
            "CSS": self.gen_CSS_insn,
            "CIW": self.gen_CIW_insn,
            "CL": self.gen_CL_insn,
            "CS": self.gen_CS_insn,
            "CB": self.gen_CB_insn,
            "CJ": self.gen_CJ_insn
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
        """Compare bytes with all instructions in turn. Return the first (and
        hopefully only) matching instruction object"""
        for insn in self._insns:
            if(self.compare_with_insn(byte, insn, len)):
                return insn
        return None

    def compare_with_insn(self, byte, insn, len):
        """Compare bytes with a specific instruction object. If successful, return
        the relevant instruction object"""
        if(len != insn.len):
            return False
        return (insn.insn == (byte & insn.mask))

    def disassemble(self, insn, len, info):
        """Disassemble given bytes. Return a string with the relevant assemble, or
        None if no match"""
        insn_type = self.compare_with_insns(insn, len)
        if(insn_type is not None):
            return insn_type.gen_instr_assembly(insn, info)
        return None

####################################################################
#
# A class that performs syntax highlighting.  Our actual disassembler
# class will inherit from this, and call back into this class to
# perform syntax highlighting.


class SyntaxHighlightingDisassembler(Disassembler):
    def __init__(self, name):
        super(SyntaxHighlightingDisassembler, self).__init__(name)

    def __call__(self, info):
        if info.string is None:
            gdb.disassembler.builtin_disassemble(info)
        gdb.disassembler.syntax_highlight(info)
        return None


####################################################################
#
# This is the actual hook into GDB, this code is closer to production
# ready, though we might find things that need improviing once users
# start to test this.
#


class RISCVDisassembler(SyntaxHighlightingDisassembler):
    def __init__(self):
        super(RISCVDisassembler, self).__init__("RISCVDisassembler")
        self._disassembler_cache = {}
        self._callback = lambda ev:\
            self._discard_cached_disassembler(ev.connection)
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


####################################################################
#
# Register the disassembler callback for every RISC-V architecture.
# We create just a single disassembler object, and register it for
# every architecture we're insterested in.
#


riscv_disassembler = RISCVDisassembler()

for name in gdb.architecture_names():
    if name.startswith("riscv"):
        gdb.disassembler.register_disassembler(riscv_disassembler, name)
