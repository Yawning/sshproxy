#!/usr/bin/env python

from distutils.core import setup
import py2exe
import os

topdir = "py2exe_bundle"
build_path = os.path.join(topdir, "build")
dist_path = os.path.join(topdir, "dist")

setup(
    console=["bin/sshproxy"],
    zipfile="sshproxy.zip",
    options={
        "build": {"build_base": build_path},
        "py2exe": {
            "includes": ["twisted", "pyptlib"],
            "dist_dir": dist_path,
            "unbuffered": True
        }
    }
)

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
