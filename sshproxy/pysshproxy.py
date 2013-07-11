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
import argparse
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


def build_default_args(args):
    s = []

    if args.user is None:
        pyptlib.client.reportFailure("ssh", "ARGV: Missing user (--user)")
        return None
    s.append("user=" + args.user)

    if args.orport is None:
        pyptlib.client.reportFailure("ssh", "ARGV: Missing ORPort (--orport)")
        return None
    s.append("orport=" + str(args.orport))

    if args.privkey is None:
        pyptlib.client.reportFailure("ssh", "ARGV: Missing Private Key "
                                     "(--privkey)")
        return None
    s.append("privkey=" + args.privkey)

    if (args.ssh_rsa is None and args.ssh_dsa is None and
            args.ecdsa_sha2_nisp256 is None and
            args.ecdsa_sha2_nisp384 is None and
            args.ecdsa_sha2_nisp521 is None):
        pyptlib.client.reportFailure("ssh", "ARGV: Missing Public Hostkey")
        return None

    if args.ssh_rsa is not None:
        s.append("ssh-rsa=" + args.ssh_rsa)

    if args.ssh_dss is not None:
        s.append("ssh-dss=" + args.ssh_dss)

    nr_ecdsa = 0
    if args.ecdsa_sha2_nistp256 is not None:
        s.append("ecdsa-sha2-nistp256=" + args.ecdsa_sha2_nistp256)
        nr_ecdsa += 1

    if args.ecdsa_sha2_nistp384 is not None:
        s.append("ecdsa-sha2-nistp384=" + args.ecdsa_sha2_nistp384)
        nr_ecdsa += 1

    if args.ecdsa_sha2_nistp521 is not None:
        s.append("ecdsa-sha2-nistp521=" + args.ecdsa_sha2_nistp521)
        nr_ecdsa += 1

    if nr_ecdsa > 1:
        pyptlib.client.reportFailure("ssh", "ARGV: Expected one ECDSA Public "
                                     "Hostkey, got " + str(nr_ecdsa))
        return None

    # XXX: Do I need to escape this at all?
    return ';'.join(s)


def pysshproxy():
    # Parse the command line arguments
    #
    # Note: Once #9163 is fixed and 0.2.5.x Tor is used, all these
    # arguments should just go away.
    #
    # TODO: It would be nice to support more than one host worth of
    # parameters somehow, maybe just use a config file?
    parser = argparse.ArgumentParser(description="SSH network proxy")
    parser.add_argument("--user", help="Remote user")
    parser.add_argument("--privkey", help="RSA Private Key")  # XXX: File?
    parser.add_argument("--orport", type=int, help="Remote ORPort")
    parser.add_argument("--ssh-rsa", help="Remote RSA Public Hostkey")
    parser.add_argument("--ssh-dss", help="Remote DSA Public Hostkey")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ecdsa-sha2-nistp256",
                       help="Remote ECDSA NIST 256 Public Hostkey")
    group.add_argument("--ecdsa-sha2-nistp384",
                       help="Remote ECDSA NIST 384 Public Hostkey")
    group.add_argument("--ecdsa-sha2-nistp521",
                       help="Remote ECDSA NIST 521 Public Hostkey")
    args = parser.parse_args()

    # Bootstrap the pluggable transport protocol
    try:
        info = pyptlib.client.init(["ssh"])
    except pyptlib.config.EnvError:
        sys.exit(1)
    state_location = info["state_loc"]

    # Create the state directory if required
    if not os.path.isdir(state_location):
        try:
            os.makedirs(state_location)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                pyptlib.client.reportFailure("ssh", "Failed to create dir " +
                                             str(exception))
                sys.exit(1)

    log.startLogging(open(os.path.join(state_location, _LOG_FILE_NAME),
                          "w"), setStdout=False)

    # Create the instance state directory and register cleanup handlers
    #
    # Note:
    # This will leave the directory behind on SIGKILL.  Maybe I should just
    # use a consistent path, but that will break if multiple copies of this
    # are ran at the same time.  tempfile.NamedTemporaryFile doesn't support
    # opening the created temporary file on Windows, otherwise that would be
    # a better way to handle things.
    global _tmpdir
    _tmpdir = mkdtemp(prefix="sshproxy-", dir=state_location)
    atexit.register(cleanup)
    signal(SIGTERM, cleanup)
    log.msg("Temp dir: " + _tmpdir)

    # Initialize the ssh state manager
    state = ssh_state.state(_tmpdir)
    if len(sys.argv) > 1:
        state.default_args = build_default_args(args)
        if state.default_args is None:
            sys.exit(1)

    # Setup the SOCKSv4 proxy
    factory = socks.SOCKSv4Factory(state)
    addrport = reactor.listenTCP(0, factory, interface="localhost")

    # XXX: Trap SIGINT (Note: obfsproxy doesn't do this either)

    # Report back to Tor
    start_twisted = False
    for transport in info["transports"]:
        if transport == "ssh":
            # pyptlib is bugged(?) and doesn't handle ARGS/OPT-ARGS correctly
            # pyptlib.client.reportSuccess("ssh", 4, (addrport.getHost().host,
            #                                         addrport.getHost().port),
            #                              state.get_args(), state.get_optargs())
            pyptlib.client.reportSuccess("ssh", 4, (addrport.getHost().host,
                                                    addrport.getHost().port))
            start_twisted = True
    pyptlib.client.reportEnd()

    if start_twisted is True:
        reactor.run()


def run():
    pysshproxy()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
