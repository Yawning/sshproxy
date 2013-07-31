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

from sshproxy.monitor import run_monitor
from sshproxy.ssh.state import arg_to_pem

_LOG_FILE_NAME = "sshproxy.log"
_tmpdir = None
_state = None


def cleanup():
    global _state
    global _tmpdir

    if _state is not None:
        _state.on_shutdown()
        _state = None

    if _tmpdir is not None:
        # Blow away the _tmpdir
        rmtree(_tmpdir, True)
        _tmpdir = None


def ctrl_handler(sig):
    # Any console event is something evil happening that requires cleanup
    cleanup()
    return True


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

    if (args.hostkey_rsa is None and args.hostkey_dsa is None and
            args.hostkey_nisp256 is None and
            args.hostkey_nisp384 is None and
            args.hostkey_nisp521 is None):
        pyptlib.client.reportFailure("ssh", "ARGV: Missing Public Hostkey")
        return None

    if args.hostkey_rsa is not None:
        s.append("hostkey-rsa=" + args.hostkey_rsa)

    if args.hostkey_dss is not None:
        s.append("hostkey-dss=" + args.hostkey_dss)

    if args.no_ecdsa is False:
        nr_ecdsa = 0
        if args.hostkey_nistp256 is not None:
            s.append("hostkey-nistp256=" + args.hostkey_nistp256)
            nr_ecdsa += 1

        if args.hostkey_nistp384 is not None:
            s.append("hostkey-nistp384=" + args.hostkey_nistp384)
            nr_ecdsa += 1

        if args.hostkey_nistp521 is not None:
            s.append("hostkey-nistp521=" + args.hostkey_nistp521)
            nr_ecdsa += 1

        if nr_ecdsa > 1:
            pyptlib.client.reportFailure("ssh", "ARGV: Expected one ECDSA"
                                         "Public Hostkey, got " +
                                         str(nr_ecdsa))
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
    parser.add_argument("--no-ecdsa", action="store_true", default=False,
                        help="Disable ECDSA")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="SSH Debug Logging")
    parser.add_argument("--user", help="Remote user")
    parser.add_argument("--privkey", help="RSA Private Key")  # XXX: File?
    parser.add_argument("--orport", type=int, help="Remote ORPort")
    parser.add_argument("--hostkey-rsa", help="Remote RSA Public Hostkey")
    parser.add_argument("--hostkey-dss", help="Remote DSA Public Hostkey")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--hostkey-nistp256",
                       help="Remote ECDSA SHA2 NIST 256 Public Hostkey")
    group.add_argument("--hostkey-nistp384",
                       help="Remote ECDSA SHA2 NIST 384 Public Hostkey")
    group.add_argument("--hostkey-nistp521",
                       help="Remote ECDSA SHA2 NIST 521 Public Hostkey")
    group.add_argument("--monitor", help=argparse.SUPPRESS)
    args = parser.parse_args()
    optional_args = ["debug", "no_ecdsa"]

    # Cleanup on Windows is stupid, so sshproxy.exe also needs to double
    # as a monitor.
    if args.monitor is not None:
        run_monitor(args.monitor)
        sys.exit(0)

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

    if os.name == "nt":
        try:
            import win32api
            win32api.SetConsoleCtrlHandler(ctrl_handler, True)
        except:
            log.msg("Failed to install ConsoleCtrlHandler")
            pyptlib.client.reportFailure("ssh", "Failed to install CtrlHandler")
            sys.exit(1)

    # Initialize the ssh state manager, and handle command line arguments
    global _state
    _state = ssh_state.state(_tmpdir)

    if args.debug is True:
        log.msg("SSH: Verbose logging enabled")
        _state.debug = True

    if args.no_ecdsa is True:
        log.msg("SSH: ECDSA support disabled")
        _state.use_ecdsa = False

    have_args = False
    for k, v in args.__dict__.iteritems():
        if k not in optional_args and v is not None:
            have_args = True
            break

    if have_args is True:
        _state.default_args = build_default_args(args)
        if _state.default_args is None:
            sys.exit(1)

    if _state.ssh_works is False:
        pyptlib.client.reportFailure("ssh", "SSH client appears non-functional")
        sys.exit(1)

    # Setup the SOCKSv4 proxy
    factory = socks.SOCKSv4Factory(_state)
    addrport = reactor.listenTCP(0, factory, interface="localhost")

    # XXX: Trap SIGINT (Note: obfsproxy doesn't do this either)

    # Report back to Tor
    start_twisted = False
    for transport in info["transports"]:
        if transport == "ssh":
            # pyptlib is bugged(?) and doesn't handle ARGS/OPT-ARGS correctly
            # when it does, _state.get_args()/_state.get_optargs() will give
            # what is expected.
            pyptlib.client.reportSuccess("ssh", 4, (addrport.getHost().host,
                                                    addrport.getHost().port))
            start_twisted = True
    pyptlib.client.reportEnd()

    if start_twisted is True:
        reactor.run()


def run():
    pysshproxy()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
