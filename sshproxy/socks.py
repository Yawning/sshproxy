#!/usr/bin/env python

"""
Do the nececary integration between Twisted's SOCKSv4 code and ducttape.
"""

from twisted.protocols import socks
from twisted.internet import defer
from twisted.internet.protocol import Factory
from twisted.python import log

from sshproxy.ssh.ducttape import new_ducttape


class SOCKSv4Protocol(socks.SOCKSv4):
    state_mgr = None

    # ssh settings that aren't stored in the state_mgr
    dt = None
    user = None
    orport = None

    def __init__(self, state_mgr):
        self.state_mgr = state_mgr
        socks.SOCKSv4.__init__(self)

    def authorize(self, code, server, port, user):
        # Only support CONNECT
        if code != 1:
            log.msg("Unsupported command code: " + str(code))
            return False

        # Arguments are mandatory, but it's possible that we're not running
        # in managed mode (or we hit #9162/#9163), so attempt to continue.
        socks_args = None
        if len(user) > 0:
            socks_args = self.state_mgr.split_args(user)

        user_orport = self.state_mgr.parse_args(server, socks_args)
        if user_orport is None:
            return False
        self.user = user_orport[0]
        self.orport = user_orport[1]

        return True

    def connectClass(self, host, port, klass, *args):
        # Ignore klass/args (SOCKSv4Outgoing/self) and just use ducttape
        key = self.state_mgr.get_auth_credentials(self.user, host)
        self.dt = new_ducttape(self, host, port, self.user, key,
                               self.orport)

        return defer.succeed(True)

    def connectionLost(self, reason):
        if self.dt.l_client is not None:
            self.dt.socksClosed()
        if self.otherConn:
            self.otherConn.transport.loseConnection()


class SOCKSv4Factory(Factory):
    state_mgr = None

    def __init__(self, state_mgr):
        self.state_mgr = state_mgr

    def buildProtocol(self, addr):
        return SOCKSv4Protocol(self.state_mgr)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
