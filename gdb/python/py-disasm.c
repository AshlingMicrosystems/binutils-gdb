/* Python interface to instruction disassembly.

   Copyright (C) 2008-2021 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "python-internal.h"
#include "dis-asm.h"
#include "arch-utils.h"
#include "charset.h"
#include "disasm.h"

/* Implement gdb.disassembler.DisassembleInfo type.  An object of this type
   represents a single disassembler request from GDB.  */

struct disasm_info_object {
  PyObject_HEAD

  /* The architecture in which we are disassembling.  */
  struct gdbarch *gdbarch;

  /* Address of the instruction to disassemble.  */
  bfd_vma address;

  disassemble_info *gdb_info;
  disassemble_info *py_info;

  /* The length of the disassembled instruction, a value of -1 indicates
     that there is no disassembly result set, otherwise, this should be a
     value greater than zero.  */
  int length;

  /* A string buffer containing the disassembled instruction.  This is
     initially nullptr, and is allocated when needed.  It is possible that
     the length field (above) can be -1, but this buffer is still
     allocated, this happens if the user first sets a result, and then
     marks a memory error.  In this case any value in CONTENT should be
     ignored.  */
  string_file *content;

  /* When the user indicates that a memory error has occurred then this
     field is set to true, it is false by default.  */
  bool memory_error_address_p;

  /* When the user indicates that a memory error has occurred then the
     address of the memory error is stored in here.  This field is only
     valid when MEMORY_ERROR_ADDRESS_P is true, otherwise this field is
     undefined.  */
  CORE_ADDR memory_error_address;

  /* When the user calls the builtin_disassembler function, if they pass a
     memory source object then a pointer to the object is placed in here,
     otherwise, this field is nullptr.  */
  PyObject *memory_source;
};

extern PyTypeObject disasm_info_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("disasm_info_object");

typedef int (*read_memory_ftype)
    (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
     struct disassemble_info *dinfo);

/* A sub-class of gdb_disassembler that holds a pointer to a Python
   DisassembleInfo object.  A pointer to an instance of this class is
   placed in the application_data field of the disassemble_info that is
   used when we call gdbarch_print_insn.  */

struct gdbpy_disassembler : public gdb_disassembler
{
  /* Constructor.  */
  gdbpy_disassembler (struct gdbarch *gdbarch, struct ui_file *stream,
		      disasm_info_object *obj);

  /* Get the DisassembleInfo object pointer.  */
  disasm_info_object *
  py_disasm_info () const
  {
    return m_disasm_info_object;
  }

  /* Mark this class as a friend so that it can call the disasm_info
     method, which is protected in our parent.  */
  friend class scoped_disasm_info_object;

private:
  /* The DisassembleInfo object we are disassembling for.  */
  disasm_info_object *m_disasm_info_object;
};

/* Return true if OBJ is still valid, otherwise, return false.  A valid OBJ
   will have a non-nullptr gdb_info field.  */

static bool
disasmpy_info_is_valid (disasm_info_object *obj)
{
  if (obj->gdb_info == nullptr)
    gdb_assert (obj->py_info == nullptr);
  else
    gdb_assert (obj->py_info != nullptr);

  return obj->gdb_info != nullptr;
}

/* Ensure that a gdb.disassembler.DisassembleInfo is valid.  */
#define DISASMPY_DISASM_INFO_REQUIRE_VALID(Info)			\
  do {									\
    if (!disasmpy_info_is_valid (Info))					\
      {									\
	PyErr_SetString (PyExc_RuntimeError,				\
			 _("DisassembleInfo is no longer valid."));	\
	return nullptr;							\
      }									\
  } while (0)

/* Mark OBJ as having a memory error at ADDR.  Only the first memory error
   is recorded, so if OBJ has already had a memory error set then this
   call will have no effect.  */

static void
disasmpy_set_memory_error (disasm_info_object *obj, CORE_ADDR addr)
{
  if (!obj->memory_error_address_p)
    {
      obj->memory_error_address = addr;
      obj->memory_error_address_p = true;
    }
}

/* Clear any memory error already set on OBJ.  If there is no memory error
   set on OBJ then this call has no effect.  */

static void
disasmpy_clear_memory_error (disasm_info_object *obj)
{
  obj->memory_error_address_p = false;
}

/* Clear any previous disassembler result stored within OBJ.  If there was
   no previous disassembler result then calling this function has no
   effect.  */

static void
disasmpy_clear_disassembler_result (disasm_info_object *obj)
{
  obj->length = -1;
  gdb_assert (obj->content != nullptr);
  obj->content->clear ();
}

/* Implement gdb.disassembler.builtin_disassemble().  Calls back into GDB's
   builtin disassembler.  The first argument is a DisassembleInfo object
   describing what to disassemble.  The second argument is optional and
   provides a mechanism to modify the memory contents that the builtin
   disassembler will actually disassemble.  Returns the Python None value.  */

static PyObject *
disasmpy_builtin_disassemble (PyObject *self, PyObject *args, PyObject *kw)
{
  PyObject *info_obj, *memory_source_obj = nullptr;
  static const char *keywords[] = { "info", "memory_source", nullptr };
  if (!gdb_PyArg_ParseTupleAndKeywords (args, kw, "O!|O", keywords,
					&disasm_info_object_type, &info_obj,
					&memory_source_obj))
    return nullptr;

  disasm_info_object *disasm_info = (disasm_info_object *) info_obj;
  if (!disasmpy_info_is_valid (disasm_info))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       _("DisassembleInfo is no longer valid."));
      return nullptr;
    }

  gdb::optional<scoped_restore_tmpl<PyObject *>> restore_memory_source;

  disassemble_info *info = disasm_info->py_info;
  if (memory_source_obj != nullptr)
    {
      if (!PyObject_HasAttrString (memory_source_obj, "read_memory"))
	{
	  PyErr_SetString (PyExc_TypeError,
			   _("memory_source doesn't have a read_memory method"));
	  return nullptr;
	}

      gdb_assert (disasm_info->memory_source == nullptr);
      restore_memory_source.emplace (&disasm_info->memory_source,
				     memory_source_obj);
    }

  /* When the user calls the builtin disassembler any previous result or
     memory error is discarded, and we start fresh.  */
  disasmpy_clear_disassembler_result (disasm_info);
  disasmpy_clear_memory_error (disasm_info);

  /* Now actually perform the disassembly.  */
  disasm_info->length
    = gdbarch_print_insn (disasm_info->gdbarch, disasm_info->address, info);

  if (disasm_info->length == -1)
    {
      /* In an ideal world, every disassembler should always call the
	 memory error function before returning a status of -1 as the only
	 error a disassembler should encounter is a failure to read
	 memory.  Unfortunately, there are some disassemblers who don't
	 follow this rule, and will return -1 without calling the memory
	 error function.

	 To make the Python API simpler, we just classify everything as a
	 memory error, but the message has to be modified for the case
	 where the disassembler didn't call the memory error function.  */
      if (disasm_info->memory_error_address_p)
	{
	  CORE_ADDR addr = disasm_info->memory_error_address;
	  PyErr_Format (gdbpy_gdb_memory_error,
			"failed to read memory at %s",
			core_addr_to_string (addr));
	}
      else
	PyErr_Format (gdbpy_gdb_memory_error, "failed to read memory");
      return nullptr;
    }

  /* Instructions are either non-zero in length, or we got an error,
     indicated by a length of -1, which we handled above.  */
  gdb_assert (disasm_info->length > 0);

  /* We should not have seen a memory error in this case.  */
  gdb_assert (!disasm_info->memory_error_address_p);

  Py_RETURN_NONE;
}

/* Implement DisassembleInfo.read_memory(LENGTH, OFFSET).  Read LENGTH
   bytes at OFFSET from the start of the instruction currently being
   disassembled, and return a memory buffer containing the bytes.

   OFFSET defaults to zero if it is not provided.  LENGTH is required.  If
   the read fails then this will raise a gdb.MemoryError exception.  */

static PyObject *
disasmpy_info_read_memory (PyObject *self, PyObject *args, PyObject *kw)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);

  LONGEST length, offset = 0;
  gdb::unique_xmalloc_ptr<gdb_byte> buffer;
  static const char *keywords[] = { "length", "offset", nullptr };

  if (!gdb_PyArg_ParseTupleAndKeywords (args, kw, "L|L", keywords,
					&length, &offset))
    return nullptr;

  /* The apparent address from which we are reading memory.  Note that in
     some cases GDB actually disassembles instructions from a buffer, so
     we might not actually be reading this information directly from the
     inferior memory.  This is all hidden behind the read_memory_func API
     within the disassemble_info structure.  */
  CORE_ADDR address = obj->address + offset;

  /* Setup a buffer to hold the result.  */
  buffer.reset ((gdb_byte *) xmalloc (length));

  /* Read content into BUFFER.  If the read fails then raise a memory
     error, otherwise, convert BUFFER to a Python memory buffer, and return
     it to the user.  */
  disassemble_info *info = obj->gdb_info;
  if (info->read_memory_func ((bfd_vma) address, buffer.get (),
			      (unsigned int) length, info) != 0)
    {
      PyErr_Format (gdbpy_gdb_memory_error,
		    "failed to read %s bytes at %s",
		    pulongest ((ULONGEST) length),
		    core_addr_to_string (address));
      return nullptr;
    }
  return gdbpy_buffer_to_membuf (std::move (buffer), address, length);
}

/* Implement DisassembleInfo.set_result(LENGTH, STRING).  Discard any
   previous memory error and set the result of this disassembly to be
   STRING, a LENGTH bytes long instruction.  The LENGTH must be greater
   than zero otherwise a ValueError exception is raised.  STRING must be a
   non-empty string, or a ValueError exception is raised.  */

static PyObject *
disasmpy_info_set_result (PyObject *self, PyObject *args, PyObject *kw)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);

  static const char *keywords[] = { "length", "string", nullptr };
  int length;
  const char *string;

  if (!gdb_PyArg_ParseTupleAndKeywords (args, kw, "is", keywords,
					&length, &string))
    return nullptr;

  if (length <= 0)
    {
      PyErr_SetString (PyExc_ValueError,
		       _("Length must be greater than 0."));
      return nullptr;
    }

  size_t string_len = strlen (string);
  if (string_len == 0)
    {
      PyErr_SetString (PyExc_ValueError, _("String must not be empty."));
      return nullptr;
    }

  /* Discard any previously recorded memory error, and any previous
     disassembler result.  */
  disasmpy_clear_memory_error (obj);
  disasmpy_clear_disassembler_result (obj);

  /* And set the result.  */
  obj->length = length;
  gdb_assert (obj->content != nullptr);
  obj->content->write (string, string_len);

  Py_RETURN_NONE;
}

/* Implement DisassembleInfo.memory_error().  Mark SELF (a DisassembleInfo
   object) as having a memory error.  Any previous result is discarded.  */

static PyObject *
disasmpy_info_memory_error (PyObject *self, PyObject *args, PyObject *kw)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);

  static const char *keywords[] = { "offset", nullptr };
  LONGEST offset;

  if (!gdb_PyArg_ParseTupleAndKeywords (args, kw, "L", keywords,
					&offset))
    return nullptr;

  /* Discard any previous disassembler result, and mark OBJ as having a
     memory error.  */
  disasmpy_clear_disassembler_result (obj);
  disasmpy_set_memory_error (obj, obj->address + offset);

  Py_RETURN_NONE;
}

/* Implement gdb.disassembler.format_address(ARCH, ADDR).  Formats ADDR, an
   address and returns a string.  ADDR will be formatted in the style that
   the disassembler uses: '0x.... <symbol + offset>'.  ARCH is a
   gdb.Architecture used to perform the formatting.  */

static PyObject *
disasmpy_format_address (PyObject *self, PyObject *args, PyObject *kw)
{
  static const char *keywords[] = { "architecture", "address", nullptr };
  PyObject *addr_obj, *arch_obj;
  CORE_ADDR addr;

  if (!gdb_PyArg_ParseTupleAndKeywords (args, kw, "OO", keywords,
					&arch_obj, &addr_obj))
    return nullptr;

  if (get_addr_from_python (addr_obj, &addr) < 0)
    return nullptr;

  if (!gdbpy_is_arch_object (arch_obj))
    {
      PyErr_SetString (PyExc_TypeError,
		       _("architecture argument is not a gdb.Architecture"));
      return nullptr;
    }

  gdbarch *gdbarch = arch_object_to_gdbarch (arch_obj);
  if (gdbarch == nullptr)
    {
      PyErr_SetString (PyExc_RuntimeError,
		       _("architecture argument is invalid."));
      return nullptr;
    }

  string_file buf;
  print_address (gdbarch, addr, &buf);
  return PyString_FromString (buf.c_str ());
}

/* Implement DisassembleInfo.address attribute, return the address at which
   GDB would like an instruction disassembled.  */

static PyObject *
disasmpy_info_address (PyObject *self, void *closure)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);
  return gdb_py_object_from_longest (obj->address).release ();
}

/* Implement DisassembleInfo.string attribute.  Return a string containing
   the current disassembly result, or None if there is no current
   disassembly result.  */

static PyObject *
disasmpy_info_string (PyObject *self, void *closure)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);

  gdb_assert (obj->content != nullptr);
  if (strlen (obj->content->c_str ()) == 0)
    Py_RETURN_NONE;
  gdb_assert (obj->length > 0);
  return PyUnicode_Decode (obj->content->c_str (),
			   obj->content->size (),
			   host_charset (), nullptr);
}

/* Implement DisassembleInfo.length attribute.  Return the length of the
   current disassembled instruction, as set by a call to
   DisassembleInfo.set_result.  If no result has been set yet, or if a call
   to DisassembleInfo.memory_error has invalidated the result, then None is
   returned.  */

static PyObject *
disasmpy_info_length (PyObject *self, void *closure)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);
  if (obj->length == -1)
    Py_RETURN_NONE;
  gdb_assert (obj->length > 0);
  gdb_assert (obj->content != nullptr);
  gdb_assert (strlen (obj->content->c_str ()) > 0);
  return gdb_py_object_from_longest (obj->length).release ();
}

/* Implement DisassembleInfo.architecture attribute.  Return the
   gdb.Architecture in which we are disassembling.  */

static PyObject *
disasmpy_info_architecture (PyObject *self, void *closure)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);
  return gdbarch_to_arch_object (obj->gdbarch);
}

/* Implement DisassembleInfo.can_emit_style_escape attribute.  Returns True
   if the output stream that the disassembly result will be written too
   supports style escapes, otherwise, returns False.  */

static PyObject *
disasmpy_info_can_emit_style_escape (PyObject *self, void *closure)
{
  disasm_info_object *obj = (disasm_info_object *) self;
  DISASMPY_DISASM_INFO_REQUIRE_VALID (obj);
  bool can_emit_style_escape = current_uiout->can_emit_style_escape ();
  return PyBool_FromLong (can_emit_style_escape ? 1 : 0);
}

/* This implements the disassemble_info read_memory_func callback.  This
   will either call the standard read memory function, or, if the user has
   supplied a memory source (see disasmpy_builtin_disassemble) then this
   will call back into Python to obtain the memory contents.

   Read LEN bytes from MEMADDR and place them into BUFF.  Return 0 on
   success (in which case BUFF has been filled), or -1 on error, in which
   case the contents of BUFF are undefined.  */

static int
disasmpy_read_memory_func (bfd_vma memaddr, gdb_byte *buff,
			  unsigned int len, struct disassemble_info *info)
{
  gdbpy_disassembler *dis
    = static_cast<gdbpy_disassembler *> (info->application_data);
  disasm_info_object *obj = dis->py_disasm_info ();

  /* The simple case, the user didn't pass a separate memory source, so we
     just delegate to the standard disassemble_info read_memory_func.  */
  if (obj->memory_source == nullptr)
    return obj->gdb_info->read_memory_func (memaddr, buff, len, obj->gdb_info);

  /* The user provided a separate memory source, we need to call the
     read_memory method on the memory source and use the buffer it returns
     as the bytes of memory.  */
  PyObject *memory_source = obj->memory_source;
  LONGEST offset = (LONGEST) memaddr - (LONGEST) obj->address;
  gdbpy_ref<> result_obj (PyObject_CallMethod (memory_source, "read_memory",
					       "KL", len, offset));
  if (result_obj == nullptr)
    {
      /* If we got a gdb.MemoryError then we ignore this and just report
	 that the read failed to the caller.  For any other exception type
	 we assume this is a bug in the users code, print the stack, and
	 then report the read failed.  */
      if (PyErr_ExceptionMatches (gdbpy_gdb_memory_error))
	PyErr_Clear ();
      else
	gdbpy_print_stack ();
      return -1;
    }

  /* Convert the result to a buffer.  */
  Py_buffer py_buff;
  if (!PyObject_CheckBuffer (result_obj.get ())
      || PyObject_GetBuffer (result_obj.get(), &py_buff, PyBUF_CONTIG_RO) < 0)
    {
      PyErr_Format (PyExc_TypeError,
		    _("Result from read_memory is not a buffer"));
      gdbpy_print_stack ();
      return -1;
    }

  /* Wrap PY_BUFF so that it is cleaned up correctly at the end of this
     scope.  */
  Py_buffer_up buffer_up (&py_buff);

  /* Validate that the buffer is the correct length.  */
  if (py_buff.len != len)
    {
      PyErr_Format (PyExc_ValueError,
		    _("Result from read_memory is incorrectly sized buffer"));
      gdbpy_print_stack ();
      return -1;
    }

  /* Copy the data out of the Python buffer and return succsess.*/
  const gdb_byte *buffer = (const gdb_byte *) py_buff.buf;
  memcpy (buff, buffer, len);
  return 0;
}

/* Implement memory_error_func callback for disassemble_info.  Extract the
   underlying DisassembleInfo Python object, and set a memory error on
   it.  */

static void
disasmpy_memory_error_func (int status, bfd_vma memaddr,
			   struct disassemble_info *info)
{
  gdbpy_disassembler *dis
    = static_cast<gdbpy_disassembler *> (info->application_data);
  disasm_info_object *obj = dis->py_disasm_info ();
  disasmpy_set_memory_error (obj, memaddr);
}

/* Constructor.  */

gdbpy_disassembler::gdbpy_disassembler (struct gdbarch *gdbarch,
					struct ui_file *stream,
					disasm_info_object *obj)
  : gdb_disassembler (gdbarch, stream, disasmpy_read_memory_func,
		      disasmpy_memory_error_func),
    m_disasm_info_object (obj)
{ /* Nothing.  */ }

/* A wrapper around a reference to a Python DisassembleInfo object, along
   with some supporting information that the DisassembleInfo object needs
   to reference.

   Each DisassembleInfo is created in gdbpy_print_insn, and is done with by
   the time that function returns.  However, there's nothing to stop a user
   caching a reference to the DisassembleInfo, and thus keeping the object
   around.

   We therefore have the notion of a DisassembleInfo becoming invalid, this
   happens when gdbpy_print_insn returns.  This class is responsible for
   marking the DisassembleInfo as invalid in its destructor.  */

struct scoped_disasm_info_object
{
  /* Constructor.  */
  scoped_disasm_info_object (struct gdbarch *gdbarch, CORE_ADDR memaddr,
			 disassemble_info *info)
    : m_disasm_info (allocate_disasm_info_object ()),
      m_py_disassembler (gdbarch, &m_string_file, m_disasm_info.get ())
  {
    m_disasm_info->address = memaddr;
    m_disasm_info->gdb_info = info;
    m_disasm_info->py_info = m_py_disassembler.disasm_info ();
    m_disasm_info->length = -1;
    m_disasm_info->content = &m_string_file;
    m_disasm_info->gdbarch = gdbarch;
    m_disasm_info->memory_error_address_p = false;
    m_disasm_info->memory_error_address = 0;
    m_disasm_info->memory_source = nullptr;
  }

  /* Upon destruction clear pointers to state that will no longer be
     valid.  These fields are checked in disasmpy_info_is_valid to see if
     the disasm_info_object is still valid or not.  */
  ~scoped_disasm_info_object ()
  {
    m_disasm_info->gdb_info = nullptr;
    m_disasm_info->py_info = nullptr;
    m_disasm_info->content = nullptr;
  }

  /* Return a pointer to the underlying disasm_info_object instance.  */
  disasm_info_object *
  get () const
  {
    return m_disasm_info.get ();
  }

private:

  /* Wrapper around the call to PyObject_New, this wrapper function can be
     called from the constructor initialization list, while PyObject_New, a
     macro, can't.  */
  static disasm_info_object *
  allocate_disasm_info_object ()
  {
    return (disasm_info_object *) PyObject_New (disasm_info_object,
						&disasm_info_object_type);
  }

  /* A reference to a gdb.disassembler.DisassembleInfo object.  When this
     containing instance goes out of scope this reference is released,
     however, the user might be holding other references to the
     DisassembleInfo object in Python code, so the underlying object might
     not be deleted.  */
  gdbpy_ref<disasm_info_object> m_disasm_info;

  /* A location into which the output of the Python disassembler is
     collected.  We only send this back to GDB once the Python disassembler
     has completed successfully.  */
  string_file m_string_file;

  /* Core GDB requires that the disassemble_info application_data field be
     an instance of, or a sub-class or, gdb_disassembler.  We use a
     sub-class so that functions within the file can obtain a pointer to
     the disasm_info_object from the application_data.  */
  gdbpy_disassembler m_py_disassembler;
};

/* See python-internal.h.  */

gdb::optional<int>
gdbpy_print_insn (struct gdbarch *gdbarch, CORE_ADDR memaddr,
		  disassemble_info *info)
{
  if (!gdb_python_initialized)
    return {};

  gdbpy_enter enter_py (get_current_arch (), current_language);

  /* The attribute we are going to lookup that provides the print_insn
     functionality.  */
  static const char *callback_name = "_print_insn";

  /* Grab a reference to the gdb.disassembler module, and check it has the
     attribute that we need.  */
  static gdbpy_ref<> gdb_python_disassembler_module
    (PyImport_ImportModule ("gdb.disassembler"));
  if (gdb_python_disassembler_module == nullptr
      || !PyObject_HasAttrString (gdb_python_disassembler_module.get (),
				  callback_name))
    return {};

  /* Now grab the callback attribute from the module, and check that it is
     callable.  */
  gdbpy_ref<> hook
    (PyObject_GetAttrString (gdb_python_disassembler_module.get (),
			     callback_name));
  if (hook == nullptr)
    {
      gdbpy_print_stack ();
      return {};
    }
  if (!PyCallable_Check (hook.get ()))
    return {};

  scoped_disasm_info_object scoped_disasm_info (gdbarch, memaddr, info);
  disasm_info_object *disasm_info = scoped_disasm_info.get ();

  /* Call into the registered disassembler to (possibly) perform the
     disassembly.  */
  PyObject *insn_disas_obj = (PyObject *) disasm_info;
  gdbpy_ref<> result (PyObject_CallFunctionObjArgs (hook.get (),
						    insn_disas_obj,
						    nullptr));

  if (result == nullptr)
    {
      if (PyErr_ExceptionMatches (gdbpy_gdb_memory_error))
	{
	  /* Uncaught memory errors are not printed, we assume that the
	     user tried to read some bytes for their custom disassembler,
	     but the bytes were no available, as such, we should silently
	     fall back to using the builtin disassembler, which is what
	     happens when we return no value here.  */
	  PyErr_Clear ();
	}
      else
	{
	  /* Any other error while executing the _print_insn callback
	     should result in a debug stack being printed, then we return
	     no value to indicate that the builtin disassembler should be
	     used.  */
	  gdbpy_print_stack ();
	}
      return {};
    }
  else if (result != Py_None)
    error (_("invalid return value from gdb.disassembler._print_insn"));

  if (disasm_info->memory_error_address_p)
    {
      /* We pass -1 for the status here.  GDB doesn't make use of this
	 field, but disassemblers usually pass the result of
	 read_memory_func as the status, in which case -1 indicates an
	 error.  */
      bfd_vma addr = disasm_info->memory_error_address;
      info->memory_error_func (-1, addr, info);
      return gdb::optional<int> (-1);
    }

  /* If the gdb.disassembler.DisassembleInfo object doesn't have a result
     then return false.  */
  if (disasm_info->length == -1)
    return {};

  /* Print the content from the DisassembleInfo back through to GDB's
     standard fprintf_func handler.  */
  info->fprintf_func (info->stream, "%s", disasm_info->content->c_str ());

  /* Return the length of this instruction.  */
  return gdb::optional<int> (disasm_info->length);
}

/* The tp_dealloc callback for the DisassembleInfo type.  Takes care of
   deallocating the content buffer.  */

static void
disasmpy_dealloc (PyObject *self)
{
  disasm_info_object *obj = (disasm_info_object *) self;

  /* The memory_source field is only ever temporarily set to non-nullptr
     during the disasmpy_builtin_disassemble function.  By the end of that
     function the memory_source field should be back to nullptr.  */
  gdb_assert (obj->memory_source == nullptr);

  /* The content field will also be reset to nullptr by the end of
     gdbpy_print_insn, so the following assert should hold.  */
  gdb_assert (obj->content == nullptr);
  Py_TYPE (self)->tp_free (self);
}

/* The get/set attributes of the gdb.disassembler.DisassembleInfo type.  */

static gdb_PyGetSetDef disasm_info_object_getset[] = {
  { "address", disasmpy_info_address, nullptr,
    "Start address of the instruction to disassemble.", nullptr },
  { "string", disasmpy_info_string, nullptr,
    "String representing the disassembled instruction.", nullptr },
  { "length", disasmpy_info_length, nullptr,
    "Length in octets of the disassembled instruction.", nullptr },
  { "architecture", disasmpy_info_architecture, nullptr,
    "Architecture to disassemble in", nullptr },
  { "can_emit_style_escape", disasmpy_info_can_emit_style_escape, nullptr,
    "Boolean indicating if style escapes can be emitted", nullptr },
  { nullptr }   /* Sentinel */
};

/* The methods of the gdb.disassembler.DisassembleInfo type.  */

static PyMethodDef disasm_info_object_methods[] = {
  { "read_memory", (PyCFunction) disasmpy_info_read_memory,
    METH_VARARGS | METH_KEYWORDS,
    "read_memory (LEN, OFFSET = 0) -> Octets[]\n\
Read LEN octets for the instruction to disassemble." },
  { "set_result", (PyCFunction) disasmpy_info_set_result,
    METH_VARARGS | METH_KEYWORDS,
    "set_result (LENGTH, STRING) -> None\n\
Set the disassembly result, LEN in octets, and disassembly STRING." },
  { "memory_error", (PyCFunction) disasmpy_info_memory_error,
    METH_VARARGS | METH_KEYWORDS,
    "memory_error (OFFSET) -> None\n\
A memory error occurred when trying to read bytes at OFFSET." },
  {nullptr}  /* Sentinel */
};

/* These are the methods we add into the _gdb.disassembler module, which
   are then imported into the gdb.disassembler module.  These are global
   functions that support performing disassembly.  */

PyMethodDef python_disassembler_methods[] =
{
  { "format_address", (PyCFunction) disasmpy_format_address,
    METH_VARARGS | METH_KEYWORDS,
    "format_address (ARCHITECTURE, ADDRESS) -> String.\n\
Format ADDRESS as a string suitable for use in disassembler output." },
  { "builtin_disassemble", (PyCFunction) disasmpy_builtin_disassemble,
    METH_VARARGS | METH_KEYWORDS,
    "builtin_disassemble (INFO, MEMORY_SOURCE = None) -> None\n\
Disassemble using GDB's builtin disassembler.  INFO is an instance of\n\
gdb.disassembler.DisassembleInfo.  The MEMORY_SOURCE, if not None, should\n\
be an object with the read_memory method." },
  {nullptr, nullptr, 0, nullptr}
};

#ifdef IS_PY3K
/* Structure to define the _gdb.disassembler module.  */

static struct PyModuleDef python_disassembler_module_def =
{
  PyModuleDef_HEAD_INIT,
  "_gdb.disassembler",
  nullptr,
  -1,
  python_disassembler_methods,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};
#endif

/* Called to initialize the Python structures in this file.  */

int
gdbpy_initialize_disasm (void)
{
  /* Create the _gdb.disassembler module, and add it to the _gdb module.  */

  PyObject *gdb_disassembler_module;
#ifdef IS_PY3K
  gdb_disassembler_module = PyModule_Create (&python_disassembler_module_def);
#else
  gdb_disassembler_module = Py_InitModule ("_gdb.disassembler",
					   python_disassembler_methods);
#endif
  if (gdb_disassembler_module == nullptr)
    return -1;
  PyModule_AddObject(gdb_module, "disassembler", gdb_disassembler_module);

  /* This is needed so that 'import _gdb.disassembler' will work.  */
  PyObject *dict = PyImport_GetModuleDict ();
  PyDict_SetItemString (dict, "_gdb.disassembler", gdb_disassembler_module);

  /* Having the tp_new field as nullptr means that this class can't be
     created from user code.  The only way they can be created is from
     within GDB, and then they are passed into user code.  */
  gdb_assert (disasm_info_object_type.tp_new == nullptr);
  if (PyType_Ready (&disasm_info_object_type) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_disassembler_module, "DisassembleInfo",
				 (PyObject *) &disasm_info_object_type);
}

/* Describe the gdb.disassembler.DisassembleInfo type.  */

PyTypeObject disasm_info_object_type = {
  PyVarObject_HEAD_INIT (nullptr, 0)
  "gdb.disassembler.DisassembleInfo",		/*tp_name*/
  sizeof (disasm_info_object),			/*tp_basicsize*/
  0,						/*tp_itemsize*/
  disasmpy_dealloc,                		/*tp_dealloc*/
  0,						/*tp_print*/
  0,						/*tp_getattr*/
  0,						/*tp_setattr*/
  0,						/*tp_compare*/
  0,						/*tp_repr*/
  0,						/*tp_as_number*/
  0,						/*tp_as_sequence*/
  0,						/*tp_as_mapping*/
  0,						/*tp_hash */
  0,						/*tp_call*/
  0,						/*tp_str*/
  0,						/*tp_getattro*/
  0,						/*tp_setattro*/
  0,						/*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,				/*tp_flags*/
  "GDB instruction disassembler object",	/* tp_doc */
  0,						/* tp_traverse */
  0,						/* tp_clear */
  0,						/* tp_richcompare */
  0,						/* tp_weaklistoffset */
  0,						/* tp_iter */
  0,						/* tp_iternext */
  disasm_info_object_methods,			/* tp_methods */
  0,						/* tp_members */
  disasm_info_object_getset			/* tp_getset */
};
