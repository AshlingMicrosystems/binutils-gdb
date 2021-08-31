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

import xml.etree.ElementTree as ET
import gdb

# Make use of gdb.TargetConnection.send_remote_packet to fetch the
# thread list from the remote target.
#
# Sending existing serial protocol packets like this is not a good
# idea, there should be better ways to get this information using an
# official API, this is just being used as a test case.
#
# Really, the send_remote_packet API would be used to send target
# specific packets to the target, but these are, by definition, target
# specific, so hard to test in a general testsuite.
def get_thread_list_str():
    start_pos = 0
    thread_desc = ""
    try:
        while True:
            conn = gdb.selected_inferior().connection
            str = conn.send_remote_packet("qXfer:threads:read::%d,200" % start_pos)
            start_pos += 200
            c = str[0]
            str = str[1:]
            thread_desc += str
            if c == "l":
                break
        return thread_desc
    except:
        return None


# Use gdb.TargetConnection.send_remote_packet to manually fetch the
# thread list, then extract the thread list using the gdb.Inferior and
# gdb.InferiorThread API.  Compare the two results to ensure we
# managed to successfully read the thread list from the remote.
def run_send_packet_test():
    # Find the IDs of all current threads.
    all_threads = {}
    for inf in gdb.inferiors():
        for thr in inf.threads():
            id = "p%x.%x" % (thr.ptid[0], thr.ptid[1])
            all_threads[id] = False

    # Now fetch the thread list from the remote, and parse the XML.
    str = get_thread_list_str()
    threads_xml = ET.fromstring(str)

    # Look over all threads in the XML list and check we expected to
    # find them, mark the ones we do find.
    for thr in threads_xml:
        id = thr.get("id")
        if not id in all_threads:
            raise "found unexpected thread in remote thread list"
        else:
            all_threads[id] = True

    # Check that all the threads were found in the XML list.
    for id in all_threads:
        if not all_threads[id]:
            raise "thread missingt from remote thread list"

    # Test complete.
    print("Send packet test passed")


# Just to indicate the file was sourced correctly.
print("Sourcing complete.")
