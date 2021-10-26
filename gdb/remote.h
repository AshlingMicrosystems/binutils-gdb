/* Remote target communications for serial-line targets in custom GDB protocol
   Copyright (C) 1999-2021 Free Software Foundation, Inc.

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

#ifndef REMOTE_H
#define REMOTE_H

#include "remote-notif.h"

struct target_desc;
struct remote_target;

/* True when printing "remote" debug statements is enabled.  */

extern bool remote_debug;

/* Print a "remote" debug statement.  */

#define remote_debug_printf(fmt, ...) \
  debug_prefixed_printf_cond (remote_debug, "remote", fmt, ##__VA_ARGS__)

/* Same as the above, but don't include the function name.  */

#define remote_debug_printf_nofunc(fmt, ...) \
		debug_prefixed_printf_cond_nofunc (remote_debug, "remote", \
						   fmt, ##__VA_ARGS__)

/* Print "remote" enter/exit debug statements.  */

#define REMOTE_SCOPED_DEBUG_ENTER_EXIT \
  scoped_debug_enter_exit (remote_debug, "remote")

/* Read a packet from the remote machine, with error checking, and
   store it in *BUF.  Resize *BUF using xrealloc if necessary to hold
   the result, and update *SIZEOF_BUF.  If FOREVER, wait forever
   rather than timing out; this is used (in synchronous mode) to wait
   for a target that is is executing user code to stop.  */

extern void getpkt (remote_target *remote,
		    char **buf, long *sizeof_buf, int forever);

/* Send a packet to the remote machine, with error checking.  The data
   of the packet is in BUF.  The string in BUF can be at most PBUFSIZ
   - 5 to account for the $, # and checksum, and for a possible /0 if
   we are debugging (remote_debug) and want to print the sent packet
   as a string.  */

extern int putpkt (remote_target *remote, const char *buf);

void register_remote_g_packet_guess (struct gdbarch *gdbarch, int bytes,
				     const struct target_desc *tdesc);
void register_remote_support_xml (const char *);

void remote_file_put (const char *local_file, const char *remote_file,
		      int from_tty);
void remote_file_get (const char *remote_file, const char *local_file,
		      int from_tty);
void remote_file_delete (const char *remote_file, int from_tty);

extern int remote_register_number_and_offset (struct gdbarch *gdbarch,
					      int regnum, int *pnum,
					      int *poffset);

extern void remote_notif_get_pending_events (remote_target *remote,
					     struct notif_client *np);
extern bool remote_target_is_non_stop_p (remote_target *t);

/* An abstract class that represents the set of callbacks that are made
   from the send_remote_packet function (declared below).  */

struct send_remote_packet_callbacks
{
  /* The SENDING callback is called once send_remote_packet has performed
     its error checking and setup, just before the packet is sent to the
     remote target.  PACKET_STR is the content of the packet that will be
     sent (before any of the protocol specific prefix, suffix, or escaping
     is applied).  */

  virtual void sending (const char *packet_str) = 0;

  /* The RECEIVED callback is called once a reply has been received from
     the remote target.  The content of the reply is in BUF which can't be
     modified, and which is not guaranteed to remain valid after the
     RECEIVED call has returned.  If you need to preserve the contents of
     BUF then a copy should be taken.  */

  virtual void received (const gdb::char_vector &buf) = 0;
};

/* Send PACKET_STR the current remote target.  If PACKET_STR is nullptr, or
   is the empty string, then an error is thrown.  If the current target is
   not a remote target then an error is thrown.

   Calls CALLBACKS->sending() just before the packet is sent to the remote
   target, and calls CALLBACKS->received() with the reply once this is
   received from the remote target.  */

extern void send_remote_packet (const char *packet_str,
				send_remote_packet_callbacks *callbacks);

#endif
