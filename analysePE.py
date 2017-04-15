#!/usr/bin/python
# coding: utf-8

"""
analysePE.py - v0.1 - 2014.04.10

Author : Jan Goebel - goebel@pi-one.net
Licence : GPL v2

Example Usage:
	# to extract PE header information
	python analysePE.py file.exe

"""

############################################################################
# General Information
############################################################################

__author__ = "jan goebel (goebel@pi-one.net)"
__version__ = "0.1"

############################################################################
# Imports
############################################################################

import sys
import struct
import time
import os

import classPEfile

############################################################################

def showFile(fn):
    t = classPEfile.pefile(fn)
    if not t.isPEfile:
        return
    t.printMSDOSHeader()
    t.printPEHeader()
    t.printPEOptHeader()
    t.printSectionHeader()

    t.readExportSymbols()
    t.readImportSymbols()

    t.printImportedDLLs()
    t.getImportedFunctions()
    t.getExportedFunctions()
    t.printResourceInformation()

    return

############################################################################

if __name__ == '__main__':
    try:
        fn = sys.argv[1]
    except:
        print("missing file/directory to analyse")
        sys.exit(255)

    if os.path.isfile(fn):
        print("reading from %s ..." % (fn))
        showFile(fn)
    else:
        for root, dirs, files in os.walk(fn):
            for fl in files:
                fn = os.path.join(root, fl)
                print("reading from %s ..." % (fn))
                showFile(fn)
