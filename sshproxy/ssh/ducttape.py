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

from twisted.internet import protocol, reactor

from twisted.python import log

_SSH_ARGS = [
    "ssh",                  # XXX: Windows?
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
                            # certain versions of OpenSSH break when with this
                            # enabled when using -W.
    # XXX: Check to see if there are any other options that can screw us if we
    # don't set them explicitly.
]

# As far as I know, no one uses this cert shit, but if the remote sshd is
# configured to use them then negotiation will fail because we don't support
# verifying those at the moment.
_SSH_ARGS_HKEY_NO_ECDSA = ("-o HostKeyAlgorithms "
            "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,"
            "ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,"
            "ssh-rsa,ssh-dss")

_SSH_ARGS_HKEY_ECDSA = ("-o HostKeyAlgorithms "
            "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
            "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
            "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
            "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,"
            "ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,"
            "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
            "ssh-rsa,ssh-dss")


class ducttape(protocol.ProcessProtocol):
    socks_obj = None
    host = None
    port = None

    def __init__(self, socks_obj):
        self.socks_obj = socks_obj

    def connectionMade(self):
        # Send the SOCKS reply, and set us up as the otherConn so that data
        # can be relayed
        self.socks_obj.makeReply(90, 0, port=self.port, ip=self.host)
        self.socks_obj.otherConn = self

    def outReceived(self, data):
        # Relay the data
        self.socks_obj.transport.write(data)

    def write(self, data):
        self.transport.write(data)

    def errReceived(self, data):
        # Welp, something went terribly wrong, and ssh is bitching over stderr
        log.msg("SSH Error(?): " + data)
        self.transport.signalProcess('KILL')

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


def new_ducttape(socks_obj, host, port, user, key, orport):
    # I *should* validate that I have a known_hosts entry for host and that the
    # key_file is valid.  Can't be bothered for now, and ssh will error out if
    # either of those conditons are not true.
    process_protocol = ducttape(socks_obj)

    args = list(_SSH_ARGS)
    #args.append("-vvv")
    args.append("-o UserKnownHostsFile " +
                socks_obj.state_mgr.known_hosts_path)
    args.append("-o GlobalKnownHostsFile /dev/null")  # XXX: Windows (NUL)
    if socks_obj.state_mgr.use_ecdsa is True:
        args.append(_SSH_ARGS_HKEY_ECDSA)
    else:
        args.append(_SSH_ARGS_HKEY_NO_ECDSA)
    args.append("-o IdentityFile " + key)
    args.append("-W 127.0.0.1:" + str(orport))
    args.append("-p " + str(port))
    args.append(user + "@" + host)

    process_protocol.host = host
    process_protocol.port = port
    reactor.spawnProcess(process_protocol, "/usr/bin/ssh", args)
                                                            # XXX: Windows

    return process_protocol

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
