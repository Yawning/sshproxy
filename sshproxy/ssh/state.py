#!/usr/bin/env python

"""
This manages the global state that the ssh client needs to validate servers and
authenticate (hostkey(s), username, public key).
"""

import os
import csv
import base64
import hmac
import sys
from hashlib import sha1
from tempfile import mkstemp

from twisted.python import log

from sshproxy.ssh.ducttape import init_ducttape


class state:
    temp_path = None
    known_hosts_path = None
    known_hosts = {}
    known_hosts_dirty = False
    cached_credentials = {}
    use_ecdsa = True
    ssh_works = False

    default_args = None
    cached_args = {}

    key_types = [
        "ssh-rsa",
        "ssh-dss"
    ]

    ecdsa_key_types = [
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521"
    ]

    def __init__(self, path):
        self.temp_path = path
        self.known_hosts_path = os.path.abspath(os.path.join(self.temp_path,
                                                "known_hosts"))
        init_ducttape(self)

    def get_args(self):
        return "user,orport,privkey,ssh-rsa,ssh-dss"

    def get_optargs(self):
        if self.use_ecdsa is True:
            return ("ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,"
                    "ecdsa-sha2-nistp521")
        return None

    def split_args(self, args):
        s = None
        try:
            s = csv.reader([args], delimiter=';', escapechar='\\').next()
        except:
            log.msg("SOCKS: Failed to parse arguments")
            return None
        return s

    def parse_args(self, server, args):
        user = None
        orport = None
        key_pem = None
        have_hostkey = False

        # Under certain circumstances it's possible that we don't get arguments
        # from Tor.
        if args is None:
            if self.default_args is not None:
                args = self.split_args(self.default_args)
            else:
                return self.guess_args(server)

        for arg in args:
            if arg.startswith("user="):
                user = arg[5:]
                continue
            if arg.startswith("orport="):
                orport = int(arg[7:])
                continue
            if arg.startswith("privkey="):
                key_pem = arg[8:]
                continue
            if arg.startswith("ssh-rsa="):
                have_hostkey = True
                self.add_known_host(server, "ssh-rsa", arg[8:])
                continue
            if arg.startswith("ssh-dss="):
                have_hostkey = True
                self.add_known_host(server, "ssh-dss", arg[8:])
                continue
            if self.use_ecdsa is True:
                if arg.startswith("ecdsa-sha2-nistp256="):
                    have_hostkey = True
                    self.add_known_host(server, "ecdsa-sha2-nistp256",
                                        arg[20:])
                    continue
                if arg.startswith("ecdsa-sha2-nistp384="):
                    have_hostkey = True
                    self.add_known_host(server, "ecdsa-sha2-nistp384",
                                        arg[20:])
                    continue
                if arg.startswith("ecdsa-sha2-nistp521="):
                    have_hostkey = True
                    self.add_known_host(server, "ecdsa-sha2-nistp521",
                                        arg[20:])
                    continue
            log.msg("SOCKS: Ignoring invalid argument: " + arg)

        if (user is None or orport is None or key_pem is None or
                not have_hostkey):
            log.msg("SOCKS: Insufficient arguments to create a connection")
            return None

        try:
            self.write_known_hosts()
            self.add_auth_credentials(server, user, key_pem)
        except IOError:
            return None

        # Cache the user/orport so that we can work around #9162
        self.cached_args[server] = {}
        self.cached_args[server]["user"] = user
        self.cached_args[server]["orport"] = orport

        return (user, orport)

    def guess_args(self, server):
        # If we end up here, either the user screwed up the bridge line, or
        # the user's Tor is affected by #9162

        log.msg("SOCKS: No arguments received (Tor bug #9162)")

        if not server in self.known_hosts:
            log.msg("SOCKS: (#9162) Unable to build a known_hosts entry")
            return None

        if not server in self.cached_args:
            log.msg("SOCKS: (#9162) Unable to guess user/OR port")
            return None

        user = self.cached_args[server]["user"]
        key = user + "@" + server
        if not key in self.cached_credentials:
            log.msg("SOCKS: (#9162) No cached RSA key")
            return None

        log.msg("SOCKS: (#9162) Using previously seen values for this host")

        return (user, self.cached_args[server]["orport"])

    def add_known_host(self, host, key_type, key):
        if not key_type in self.key_types:
            if self.use_ecdsa is True:
                if not key_type in self.ecdsa_key_types:
                    log.msg("SOCKS: Invalid ssh host key type: " + key_type)
                    return
            else:
                if key_type in self.ecdsa_key_types:
                    return
                log.msg("SOCKS: Invalid ssh host key type: " + key_type)
                return

        if not host in self.known_hosts:
            self.known_hosts[host] = {}

        if (not key_type in self.known_hosts[host] or
                self.known_hosts[host][key_type] != key):
            self.known_hosts[host][key_type] = key
            self.known_hosts_dirty = True

    def write_known_hosts(self):
        if not self.known_hosts_dirty:
            return
        contents = []
        for host, keys in self.known_hosts.iteritems():
            # OpenSSH hashed known_hosts looks like:
            # |1|<Base 64 Salt>|<Base 64 Digest (HMAC-SHA1)> <key-type> <key>
            salt = os.urandom(20)
            digest = base64.b64encode(hmac.new(salt, host, sha1).digest())
            salt = base64.b64encode(salt)
            for key_type, key in keys.iteritems():
                contents.append("|1|")      # Hash Magic (SHA-1)
                contents.append(salt)       # Base 64 encoded salt
                contents.append("|")
                contents.append(digest)     # Base 64 encoded digest
                contents.append(" ")
                contents.append(key_type)   # Key type
                contents.append(" ")
                contents.append(key)        # Key
                contents.append("\n")
        try:
            f = open(self.known_hosts_path, "w")
            try:
                f.write(''.join(contents).strip())
            finally:
                f.close()
        except IOError as err:
            log.msg("SSH: Failed to write know_hosts file: ", err.errno)
            raise

    def add_auth_credentials(self, host, user, key_pem):
        key = user + "@" + host
        real_pem = arg_to_pem(key_pem)

        if key in self.cached_credentials:
            if self.cached_credentials[key]["body"] != real_pem:
                log.msg("SSH: Authentication credentials changed")
                os.unlink(self.cached_credentials[key])
            else:
                # Cache hit!
                return
        self.cached_credentials[key] = {}
        self.cached_credentials[key]["body"] = real_pem
        self.cached_credentials[key]["file"] = self.write_credentials(real_pem)

    def write_credentials(self, key_pem):
        try:
            f, f_name = mkstemp(prefix="id_rsa-", dir=self.temp_path,
                                text=True)
            fh = os.fdopen(f, "w")
            try:
                fh.write(key_pem)
            finally:
                fh.close()
        except IOError:
            log.msg("SSH: Failed to write id file: ", err.errno)
            raise
        return os.path.abspath(os.path.join(self.temp_path, f_name))

    def get_auth_credentials(self, user, host):
        key = user + "@" + host
        if key in self.cached_credentials:
            return self.cached_credentials[key]["file"]
        return None


def arg_to_pem(key):
    pem = []
    pem.append("-----BEGIN RSA PRIVATE KEY-----\n")
    for i in range(0, len(key), 64):
        pem.append(key[i:i+64])
        pem.append("\n")
    pem.append("-----END RSA PRIVATE KEY-----\n")
    return ''.join(pem)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
