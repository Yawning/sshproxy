#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = "sshproxy",
    author = "yawning",
    version = "0.0.1",
    description = ("A SSH pluggable transport proxy written in Python"),
    license = "BSD",
    keywords = ['tor', 'obfusication', 'twisted', 'ssh'],

    packages = find_packages(),
    entry_points = {
        'console_scripts' : [
            'sshproxy = sshproxy.pysshproxy:run'
        ]
    },

    install_requires = [
        'setuptools',
        'Twisted',
        'argparse',
        'pyptlib',
        ],
)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
