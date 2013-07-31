#!/usr/bin/env python

"""
This is a simple lightweight monitor that ensures that cleanup has been done.
This is only required on Windows where our cleanup handler doesn't ever get
called.

Notes:
 * This possibly could be rewritten to use python multiprocessing.
 * If pids get reused, it's possible that innocent processes will get killed,
   but that's rather unlikely.
"""

import os
import subprocess
import sys

from shutil import rmtree
from signal import SIGTERM


class monitor:
    handle = None

    def __init__(self, path):
        frozen = getattr(sys, "frozen", "")
        if frozen != "console_exe":
            return
        self.handle = subprocess.Popen([sys.executable, "--monitor=" + path],
                                       stdin=subprocess.PIPE)

    def watch_pid(self, pid):
        if self.handle is None:
            return
        self.handle.stdin.write("WATCH " + str(pid) + "\n")

    def unwatch_pid(self, pid):
        if self.handle is None:
            return
        self.handle.stdin.write("UNWATCH " + str(pid) + "\n")


def run_monitor(path):
    # This is called when sshproxy is invoked with --monitor=path
    path = os.path.abspath(path)
    monitored_pids = []

    while True:
        line = None
        try:
            line = sys.stdin.readline()
        except Exception:
            break
        except KeyboardInterrupt:
            break
        if line is None:
            break

        # Parse the simplistic monitor "protocol":
        #  * "WATCH pid"   -> Register a pid to kill on parent termination.
        #  * "UNWATCH pid" -> Deregister a pid from being killed on parent
        #                     termination.
        pid = None
        if line.startswith("WATCH "):
            try:
                pid = int(line[6:])
            except ValueError:
                continue
            if pid in monitored_pids:
                continue
            monitored_pids.append(pid)
        if line.startswith("UNWATCH "):
            try:
                pid = int(line[8:])
                monitored_pids.remove(pid)
            except ValueError:
                continue

    # Blow away the monitored children.
    for pid in monitored_pids:
        os.kill(pid, SIGTERM)

    # If the directory passed in by path still exists, blow it away.
    if os.path.exists(path):
        rmtree(path, True)
        

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
