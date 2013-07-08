#!/usr/bin/env python

"""
This is a SSH pluggable transport for Tor that uses a platform native
OpenSSH binary.  One day when there is a SSH wire protocol library
that isn't incomplete or insecure, it would be nice to remove the
dependency on platform SSH.
"""

import sys
import os
import errno
import atexit
from signal import signal, SIGTERM
from tempfile import mkdtemp
from shutil import rmtree

from twisted.python import log
from twisted.internet import reactor

import pyptlib
import pyptlib.client

import sshproxy.ssh.state as ssh_state
import sshproxy.socks as socks

from sshproxy.ssh.state import arg_to_pem

_LOG_FILE_NAME = "sshproxy.log"
_tmpdir = None


def cleanup():
    global _tmpdir
    if _tmpdir is not None:
        # Blow away the _tmpdir
        rmtree(_tmpdir, True)
        _tmpdir = None


def pysshproxy():
    # Bootstrap the pluggable transport protocol
    try:
        info = pyptlib.client.init(["ssh"])
    except pyptlib.config.EnvError:
        sys.exit(1)

    # Create the state directory if required
    if not os.path.isdir(info["state_loc"]):
        try:
            os.makedirs(info["state_loc"])
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                pyptlib.client.reportFailure("ssh", "Failed to create dir " +
                                             str(exception))
                sys.exit(1)

    log.startLogging(open(os.path.join(info["state_loc"], _LOG_FILE_NAME),
                          "w"), setStdout=False)

    # Create the instance state directory and register cleanup handlers
    #
    # Note: This will leave the directory behind on SIGKILL.  Maybe I should
    # just use a consistent path, but that will break if multiple copies of
    # this are ran at the same time.  Need to talk to asn about it.
    global _tmpdir
    _tmpdir = mkdtemp(prefix="sshproxy-", dir=info["state_loc"])
    atexit.register(cleanup)
    signal(SIGTERM, cleanup)
    log.msg("Temp dir: " + _tmpdir)

    # Initialize the ssh state manager
    state = ssh_state.state(_tmpdir)

    # Setup the SOCKSv4 proxy
    factory = socks.SOCKSv4Factory(state)
    addrport = reactor.listenTCP(0, factory, interface="localhost")

    # XXX: Trap SIGINT (Note: obfsproxy doesn't do this either)

    # Report back to Tor
    start_twisted = False
    for transport in info["transports"]:
        if transport == "ssh":
            pyptlib.client.reportSuccess("ssh", 4, (addrport.getHost().host,
                                         addrport.getHost().port),
                                         state.get_args(), state.get_optargs())
            start_twisted = True
    pyptlib.client.reportEnd()

    if start_twisted is True:
        reactor.run()


def run():
    pysshproxy()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
