#!/usr/bin/env python

"""
Duct tape an OpenSSH instance into a Twisted Protocol.  This is rather getto as
it assumes the connection will succeed and just rudely closes things off when
it receives data on stderr on the assumption that anything that will case data
to be written there is a irrecoverable error condition (Probably true).

Eventually I wish for this module to go away, but in the short term it's
unlikely, especially since I have better things to do with my life than making
Conch/Libssh2/paramiko/libssh do what is required.

In theory, this is where all the portability cruft will live, apart from the
py2exe stuff.
"""

import re
import os
import sys
import subprocess

from twisted.internet import protocol, reactor
from twisted.internet.protocol import Factory, Protocol, ClientCreator

from twisted.python import log

_SSH_ARGS = [
    "ssh",
    "-o ForwardAgent no",
    "-o ForwardX11 no",
    "-o BatchMode yes",
    "-o StrictHostKeyChecking yes",
    "-o VerifyHostKeyDNS no",
    "-o GSSAPIAuthentication no",
    "-o KbdInteractiveAuthentication no",
    "-o PasswordAuthentication no",
    "-o IdentitiesOnly yes",
    "-o ControlMaster no"   # In theory this can save us connections, but
                            # certain versions of OpenSSH break with this
                            # enabled when using -W, and there should only
                            # ever be one connection per bridge at a time.
    # XXX: Check to see if there are any other options that can screw us if we
    # don't set them explicitly.
]


_SSH_EXECUTABLE = None
_SSH_ENV = None
_SSH_W_IS_FUCKED = False
_NULL_FILE = None

# As far as I know, no one uses this cert shit, but if the remote sshd is
# configured to use them then negotiation will fail because we don't support
# verifying those at the moment.  It's not possible to remove them since
# we will look different from standard OpenSSH.
_SSH_ARGS_HKEY_NO_ECDSA = (
    "-o HostKeyAlgorithms "
    "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,"
    "ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,"
    "ssh-rsa,ssh-dss"
)

_SSH_ARGS_HKEY_ECDSA = (
    "-o HostKeyAlgorithms "
    "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
    "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
    "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
    "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,"
    "ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,"
    "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
    "ssh-rsa,ssh-dss"
)


class ducttape(protocol.ProcessProtocol):
    socks_obj = None
    host = None
    port = None

    l_client_creator = None
    l_client = None
    l_port = None
    l_attempts = None

    def __init__(self, socks_obj, host, port):
        self.socks_obj = socks_obj
        self.host = host
        self.port = port

    def connectionMade(self):
        self.socks_obj.state_mgr.l_clients.append(self)
        if _SSH_W_IS_FUCKED is False:
            self.connectionReallyMade()
        else:
            log.msg("SSH: Using -L, port:" + str(self.l_port))
            self.l_client_creator = ClientCreator(reactor, ducttape_l_client,
                                                  self)
            self.l_attempts = 0
            self.scheduleLocalConnect()

    def scheduleLocalConnect(self):
        if self.l_attempts > 3:
            log.msg("SSH: Giving up connecting to local proxy")
            self.transport.signalProcess("KILL")
        else:
            self.l_attempts += 1
            reactor.callLater(self.l_attempts * 5, self.tryLocalConnect)

    def tryLocalConnect(self):
        log.msg("SSH: Attempting to connect to local proxy port, try ",
                self.l_attempts)
        d = self.l_client_creator.connectTCP("127.0.0.1", self.l_port)
        d.addErrback(ducttape_l_client_errback, self)

    def connectionReallyMade(self):
        # Send the SOCKS reply, and set us up as the otherConn so that data
        # can be relayed
        self.socks_obj.makeReply(90, 0, port=self.port, ip=self.host)
        self.socks_obj.otherConn = self

    def outReceived(self, data):
        self.socks_obj.transport.write(data)

    def write(self, data):
        if _SSH_W_IS_FUCKED is False:
            self.transport.write(data)
        else:
            self.l_client.write(data)

    def errReceived(self, data):
        # Hmmm, got output from OpenSSH over stderr, either debug logging
        # is enabled or somethign went horribly wrong and OpenSSH is about
        # to die anyway.  Scrub IP addresses and log it for the user.
        data_scrubbed = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                               lambda x: "[scrubbed]", data)
        data_scrubbed = data_scrubbed.strip()
        log.msg("SSH stderr: " + data_scrubbed)

    def inConnectionLost(self):
        pass

    def outConnectionLost(self):
        pass

    def errConnectionLost(self):
        pass

    def processExited(self, reason):
        pass

    def processEnded(self, reason):
        self.socks_obj.transport.loseConnection()
        self.socks_obj.state_mgr.l_clients.remove(self)

    def socksClosed(self):
        try:
            self.transport.signalProcess("KILL")
        except Exception:
            sys.exc_clear()


# Ugh, ssh -W is flakly on every single windows port of OpenSSH that I've
# managed to find.
class ducttape_l_client(Protocol):
    ducttape_obj = None

    def __init__(self, ducttape_obj):
        self.ducttape_obj = ducttape_obj

    def connectionMade(self):
        self.ducttape_obj.l_client = self
        self.ducttape_obj.connectionReallyMade()

    def dataReceived(self, data):
        self.ducttape_obj.outReceived(data)

    def write(self, data):
        self.transport.write(data)

    def connectionLost(self, reason):
        try:
            self.ducttape_obj.transport.signalProcess("KILL")
        except Exception:
            sys.exc_clear()
        self.ducttape_obj = None


def ducttape_l_client_errback(error, dt):
    dt.scheduleLocalConnect()
    return error


def new_ducttape(socks_obj, host, port, user, key, orport):
    # I *should* validate that I have a known_hosts entry for host and that the
    # key_file is valid.  Can't be bothered for now, and ssh will error out if
    # either of those conditons are not true.
    process_protocol = ducttape(socks_obj, host, port)

    args = list(_SSH_ARGS)
    if socks_obj.state_mgr.debug is True:
        args.append("-vvv")
    args.append("-F")
    args.append(_NULL_FILE)
    args.append('-o UserKnownHostsFile "' +
                socks_obj.state_mgr.known_hosts_path + '"')
    args.append('-o GlobalKnownHostsFile "' + _NULL_FILE + '"')
    if socks_obj.state_mgr.use_ecdsa is True:
        args.append(_SSH_ARGS_HKEY_ECDSA)
    else:
        args.append(_SSH_ARGS_HKEY_NO_ECDSA)
    args.append('-o IdentityFile "' + key + '"')
    args.append("-p " + str(port))

    if _SSH_W_IS_FUCKED is True:
        # Find a free unallocated port to listen on
        #
        # XXX: Yes, there is a race condition here.
        p = reactor.listenTCP(0, Factory())
        l_port = p.getHost().port
        args.append("-L localhost:" + str(l_port) + ":127.0.0.1:" + str(orport))
        args.append("-T")
        args.append("-N")
        process_protocol.l_port = l_port
        p.stopListening()
    else:
        args.append("-W 127.0.0.1:" + str(orport))

    args.append(user + "@" + host)
    reactor.spawnProcess(process_protocol, _SSH_EXECUTABLE, args, env=_SSH_ENV)

    return process_protocol


def init_ducttape(state):
    # Do the platform specific runtime setup

    global _SSH_EXECUTABLE
    global _SSH_ENV
    global _SSH_W_IS_FUCKED
    global _NULL_FILE
    frozen = getattr(sys, "frozen", "")

    if frozen == "console_exe":
        # We've been packaged with py2exe:
        _SSH_EXECUTABLE = os.path.abspath(os.path.join(os.path.dirname(
            sys.executable), "ssh.exe"))
        _NULL_FILE = "NUL"
        _SSH_W_IS_FUCKED = True
        _SSH_ENV = {"CYGWIN": "nodosfilewarning"}
    else:
        _SSH_EXECUTABLE = "/usr/bin/ssh"
        _NULL_FILE = "/dev/null"

    # Run ssh - V to ensure that the SSH excutable works, that it is OpenSSH,
    # and so that we can determine if it supports ECDSA or not.
    #
    # XXX: I *should* use utils.getProcessOutput, but it's a lot easier
    # to use subprocess since I want this to be blocking.
    version = None
    try:
        version = subprocess.check_output([_SSH_EXECUTABLE, "-V"],
                                          stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as err:
        log.msg("SSH: Failed check OpenSSH version " + str(e))
        return
    version = version.strip()
    log.msg("SSH Version: " + version)
    m = re.match(r"OpenSSH_(\d+\.\d+)", version)
    if m is None:
        log.msg("SSH: Failed to determine SSH client major/minor")
        return
    v = float(m.group(1))

    # OpenSSH got ECDSA support starting from v5.6
    #
    # Apple's OpenSSH/OpenSSL does not support ECDSA at least on
    # Mountain Lion despite being fairly recent, sucks to be them.
    if v < 5.6 or sys.platform == "darwin":
        log.msg("SSH: The installed OpenSSH version does not support ECDSA")
        state.use_ecdsa = False

    state.ssh_works = True

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
