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

import classPEfile

############################################################################

if __name__ == '__main__':
	try:
		fn = sys.argv[1]
	except:
		print("missing file to analyse")
		sys.exit(255)
	print("reading from %s ..." % (fn))
	print

	t = classPEfile.pefile(fn)

	t.printMSDOSHeader()
	t.printPEHeader()
	t.printPEOptHeader()
	t.printSectionHeader()

	t.readExportSymbols()
	t.readImportSymbols()

	t.printImportedDLLs()
	t.getImportedFunctions()
	r = t.getExportedFunctions(True)
	print r
	t.printResourceInformation()
