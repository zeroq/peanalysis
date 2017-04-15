#!/usr/bin/python
# coding: utf-8

"""
classPEfile.py - v0.1 - 2014.04.10

Author : Jan Goebel - goebel@pi-one.net
Licence : GPL v2
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

############################################################################

class pefile:
	def __init__(self, fn, content=None):
		self.isPEfile = False
		if fn!=None:
			self.filename = fn
			self.filecontent = None
			self.filelength = None
			self.readFileContent()
		elif content!=None:
			self.filename = "contentOnly.bin"
			self.filecontent = content
			self.filelength = len(content)

		self.datadirNames = {}
		self.datadirNames[0] = "Export symbols table"
		self.datadirNames[1] = "Import symbols table"
		self.datadirNames[2] = "Resource table"
		self.datadirNames[3] = "Exception table"
		self.datadirNames[4] = "Certificate table"
		self.datadirNames[5] = "Base relocation table"
		self.datadirNames[6] = "Debugging information"
		self.datadirNames[7] = "Architecture-specific data"
		self.datadirNames[8] = "Global pointer register"
		self.datadirNames[9] = "Thread local storage table"
		self.datadirNames[10] = "Load configuration table"
		self.datadirNames[11] = "Bound import table"
		self.datadirNames[12] = "Import address table"
		self.datadirNames[13] = "Delay import descriptor"
		self.datadirNames[14] = "CLR header"
		self.datadirNames[15] = "Reserved"

		self.resourceData = None

		self.resourceInformation = {}
		self.resourceInformation[1] = "Cursor"
		self.resourceInformation[2] = "Bitmap"
		self.resourceInformation[3] = "Icon"
		self.resourceInformation[4] = "Menu"
		self.resourceInformation[5] = "Dialog"
		self.resourceInformation[6] = "String"
		self.resourceInformation[7] = "FontDir"
		self.resourceInformation[8] = "Font"
		self.resourceInformation[9] = "Accelerator"
		self.resourceInformation[10] = "RCData"
		self.resourceInformation[11] = "MessageTable"
		self.resourceInformation[12] = "Group Cursor"
		self.resourceInformation[14] = "Group Icon"
		self.resourceInformation[16] = "Version"
		self.resourceInformation[17] = "DLGInclude"
		self.resourceInformation[19] = "PlugPlay"
		self.resourceInformation[20] = "VXD"
		self.resourceInformation[21] = "AniCursor"
		self.resourceInformation[22] = "AniIcon"
		self.resourceInformation[23] = "HTML"
		self.resourceInformation[24] = "Manifest"

		self.peHeader = None

		if self.filelength>64:
			self.msdosDict = {}
			self.msdosHeader = self.filecontent[:64]
			if self.msdosHeader[0:2]==b'MZ':
				self.readMSDOSHeader(self.msdosHeader)
		else:
			print("file too small")

		try:
			PESignature = self.filecontent[self.msdosDict['15_pPEHeader']:self.msdosDict['15_pPEHeader']+4]
			self.isPEfile = True
		except:
			print("no PE file!")
		else:
			if PESignature == '\x50\x45\x00\x00':
				self.peHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4:self.msdosDict['15_pPEHeader']+4+20]
				self.peDict = {}
				self.readPEHeader(self.peHeader)

				self.peoptDict = {}
				self.peOptionalHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4+20:self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']]
				resourceRVA = self.readPEOptHeader(self.peOptionalHeader)

				beginFirstSection = self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']
				endFirstSection = self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']+40
				self.sectionDict = {}
				self.secionDataDict = {}
				for i in range(0, self.peDict['02_numberofsections']):
					self.sectionHeader = self.filecontent[beginFirstSection:endFirstSection]
					self.carvedFileSize = self.readSectionHeader(self.sectionHeader, i, resourceRVA)
					self.secionDataDict[i] = self.filecontent[self.sectionDict[i]['ptorawdata']:self.sectionDict[i]['ptorawdata']+self.sectionDict[i]['sizeofrawdata']]
					beginFirstSection += 40
					endFirstSection += 40

	def readFileContent(self):
		fp = open(self.filename, 'rb')
		self.filecontent = fp.read()
		fp.close()
		self.filelength = len(self.filecontent)

	def readExportSymbols(self):
		try:
			test = self.peoptDict['31_imageDataDirectory'][self.datadirNames[0]][0]
		except:
			self.exportSymbolDict = {}
			return
		if self.peoptDict['31_imageDataDirectory'][self.datadirNames[0]][0]!=0 and self.peoptDict['31_imageDataDirectory'][self.datadirNames[0]][1]!=0:
			rva = self.peoptDict['31_imageDataDirectory'][self.datadirNames[0]][0]
			size = self.peoptDict['31_imageDataDirectory'][self.datadirNames[0]][1]
			### find section
			lastSecId = None
			for i in range(0, len(self.sectionDict)):
				sec = self.sectionDict[i]
				if sec['virtualaddress']<=rva and rva <= sec['virtualaddress']+sec['virtualsize']:
					lastSecId = i
			if lastSecId!=None:
				beginIndex = int(rva) - int(self.sectionDict[lastSecId]['virtualaddress'])
				self.exportSymbolDict = {}
				counter = 0
				while True:
					try:
						characteristics = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex:beginIndex+4])[0]
						TimeDateStamp = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+4:beginIndex+8])[0]
						MajorVersion = struct.unpack('H', self.secionDataDict[lastSecId][beginIndex+8:beginIndex+10])[0]
						MinorVersion = struct.unpack('H', self.secionDataDict[lastSecId][beginIndex+10:beginIndex+12])[0]
						Name = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+12:beginIndex+16])[0]
						Base = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+16:beginIndex+20])[0]
						NumberOfFunctions = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+20:beginIndex+24])[0]
						NumberOfNames = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+24:beginIndex+28])[0]
						AddressOfFunctions = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+28:beginIndex+32])[0]
						AddressOfNames = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+32:beginIndex+36])[0]
						AddressOfNamesOrdinals = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+36:beginIndex+40])[0]
					except:
						break
					self.exportSymbolDict[counter] = {}
					self.exportSymbolDict[counter]['Characteristics'] = characteristics
					self.exportSymbolDict[counter]['TimeDateStamp'] = TimeDateStamp
					self.exportSymbolDict[counter]['Major'] = MajorVersion
					self.exportSymbolDict[counter]['Minor'] = MinorVersion
					self.exportSymbolDict[counter]['Name'] = Name
					self.exportSymbolDict[counter]['Base'] = Base
					self.exportSymbolDict[counter]['numberOfFunctions'] = NumberOfFunctions
					self.exportSymbolDict[counter]['numberOfNames'] = NumberOfNames
					self.exportSymbolDict[counter]['AddressOfFunctions'] = AddressOfFunctions
					self.exportSymbolDict[counter]['AddressOfNames'] = AddressOfNames
					self.exportSymbolDict[counter]['AddressOfNamesOrdinals'] = AddressOfNamesOrdinals
					self.exportSymbolDict[counter]['sectionID'] = lastSecId
					if Name!=0:
						try:
							index = int(Name - self.sectionDict[lastSecId]['virtualaddress'])
							nameVal = ""
							while True:
								if self.secionDataDict[lastSecId][index]=='\x00':
									break
								nameVal += struct.unpack('c', self.secionDataDict[lastSecId][index])[0]
								index += 1
							self.exportSymbolDict[counter]['NameDLL'] = nameVal
						except:
							self.exportSymbolDict[counter]['NameDLL'] = 'Unknown'
					else:
						self.exportSymbolDict[counter]['NameDLL'] = 'Unknown'
					break
			else:
				#print("\t unable to determine correct section")
				self.exportSymbolDict = {}
		else:
			#print("Exported Symbols:")
			#print("\t no export symbols available")
			self.exportSymbolDict = {}

	def readImportSymbols(self):
		if self.peoptDict['31_imageDataDirectory'][self.datadirNames[1]][0]!=0 and self.peoptDict['31_imageDataDirectory'][self.datadirNames[1]][1]!=0:
			rva = self.peoptDict['31_imageDataDirectory'][self.datadirNames[1]][0]
			size = self.peoptDict['31_imageDataDirectory'][self.datadirNames[1]][1]
			### find section
			lastSecId = None
			for i in range(0, len(self.sectionDict)):
				sec = self.sectionDict[i]
				if sec['virtualaddress']<=rva and rva <= sec['virtualaddress']+sec['virtualsize']:
					lastSecId = i
			if lastSecId!=None:
				beginIndex = int(rva) - int(self.sectionDict[lastSecId]['virtualaddress'])
				self.importSymbolDict = {}
				counter = 0
				while True:
					origFstThunk = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex:beginIndex+4])[0]
					TimeDateStamp = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+4:beginIndex+8])[0]
					ForwarderChain = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+8:beginIndex+12])[0]
					Name = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+12:beginIndex+16])[0]
					FirstThunk = struct.unpack('I', self.secionDataDict[lastSecId][beginIndex+16:beginIndex+20])[0]
					if origFstThunk==0 and TimeDateStamp==0 and ForwarderChain==0 and Name==0 and FirstThunk==0:
						break
					self.importSymbolDict[counter] = {}
					self.importSymbolDict[counter]['origFstThunk'] = origFstThunk
					self.importSymbolDict[counter]['TimeDateStamp'] = TimeDateStamp
					self.importSymbolDict[counter]['ForwarderChain'] = ForwarderChain
					self.importSymbolDict[counter]['Name'] = Name
					self.importSymbolDict[counter]['FirstThunk'] = FirstThunk
					self.importSymbolDict[counter]['sectionID'] = lastSecId
					if Name!=0:
						try:
							index = int(Name - self.sectionDict[lastSecId]['virtualaddress'])
							nameVal = ""
							while True:
								if self.secionDataDict[lastSecId][index]=='\x00':
									break
								nameVal += struct.unpack('c', self.secionDataDict[lastSecId][index])[0]
								index += 1
							self.importSymbolDict[counter]['NameDLL'] = nameVal
						except:
							self.importSymbolDict[counter]['NameDLL'] = 'Unknown'
					else:
						self.importSymbolDict[counter]['NameDLL'] = 'Unknown'
					beginIndex += 20
					counter += 1
			else:
				#print("\t unable to determine correct section")
				self.importSymbolDict = {}
		else:
			#print("\t no import symbols available")
			self.importSymbolDict = {}

	def getImportedFunctions(self, retVal=False):
		if retVal:
			dllDict = {}
			currDLL = ""
		else:
			print
			print "Imported Functions:"
			print

		for item in self.importSymbolDict:
			index = None
			if self.importSymbolDict[item]['origFstThunk']!=0:
				index = self.importSymbolDict[item]['origFstThunk'] - self.sectionDict[self.importSymbolDict[item]['sectionID']]['virtualaddress']
			elif self.importSymbolDict[item]['FirstThunk']!=0:
				index = self.importSymbolDict[item]['FirstThunk'] - self.sectionDict[self.importSymbolDict[item]['sectionID']]['virtualaddress']
			if index!=None:
				if retVal:
					currDLL = self.importSymbolDict[item]['NameDLL']
					dllDict[currDLL] = []
				else:
					print("%s" % (self.importSymbolDict[item]['NameDLL']))
				while True:
					if [self.secionDataDict[self.importSymbolDict[item]['sectionID']][index:index+4]] == ['']:
						break
					fRVA = struct.unpack('I', self.secionDataDict[self.importSymbolDict[item]['sectionID']][index:index+4])[0]
					if fRVA==0:
						break
					if hex(fRVA).startswith('0x8000'):
						if retVal:
							dllDict[currDLL].append("Ordinal: %s" % (int(hex(fRVA), 16) ^ int('0x80000000', 16)))
						else:
							print("\t\t load by ordinal: %s" % (int(hex(fRVA), 16) ^ int('0x80000000', 16)))
					else:
						try:
							nindex = fRVA - self.sectionDict[self.importSymbolDict[item]['sectionID']]['virtualaddress']
							hint = struct.unpack('H', self.secionDataDict[self.importSymbolDict[item]['sectionID']][nindex:nindex+2])[0]
							funcName = ""
							nindex += 2
							while True:
								if self.secionDataDict[self.importSymbolDict[item]['sectionID']][nindex]=='\x00':
									break
								funcName += struct.unpack('c', self.secionDataDict[self.importSymbolDict[item]['sectionID']][nindex])[0]
								nindex += 1
							if retVal:
								dllDict[currDLL].append(funcName)
							else:
								print("\t\t Function: %s" % (funcName))
						except struct.error:
							if not retVal:
								print("\t\t no name found")
					index += 4
		if retVal:
			return dllDict

	def printImportedDLLs(self, item=None):
		if item==None:
			for item in self.importSymbolDict:
				print("%s" % (self.importSymbolDict[item]['NameDLL']))
				print("\t Original First Thunk: %s (%s)" % (self.importSymbolDict[item]['origFstThunk'], hex(self.importSymbolDict[item]['origFstThunk'])))
				print("\t TimeDateStamp: %s" % (self.importSymbolDict[item]['TimeDateStamp']))
				print("\t ForwarderChain: %s (%s)" % (self.importSymbolDict[item]['ForwarderChain'], hex(self.importSymbolDict[item]['ForwarderChain'])))
				print("\t Name: %s (%s)" % (self.importSymbolDict[item]['Name'], hex(self.importSymbolDict[item]['Name'])))
				print("\t First Thunk: %s (%s)" % (self.importSymbolDict[item]['FirstThunk'], hex(self.importSymbolDict[item]['FirstThunk'])))
		else:
			print("%s" % (self.importSymbolDict[item]['NameDLL']))
			print("\t Original First Thunk: %s (%s)" % (self.importSymbolDict[item]['origFstThunk'], hex(self.importSymbolDict[item]['origFstThunk'])))
			print("\t TimeDateStamp: %s" % (self.importSymbolDict[item]['TimeDateStamp']))
			print("\t ForwarderChain: %s (%s)" % (self.importSymbolDict[item]['ForwarderChain'], hex(self.importSymbolDict[item]['ForwarderChain'])))
			print("\t Name: %s (%s)" % (self.importSymbolDict[item]['Name'], hex(self.importSymbolDict[item]['Name'])))
			print("\t First Thunk: %s (%s)" % (self.importSymbolDict[item]['FirstThunk'], hex(self.importSymbolDict[item]['FirstThunk'])))

	def getExportedFunctions(self, retVal=False):
		if retVal:
			dllDict = {}
			currDLL = ""
		else:
			print
			print "Exported Functions:"
			print
		for item in self.exportSymbolDict:
			index = None
			if self.exportSymbolDict[item]['AddressOfNames']!=0:
				index = self.exportSymbolDict[item]['AddressOfNames'] - self.sectionDict[self.exportSymbolDict[item]['sectionID']]['virtualaddress']
			if index!=None:
				if retVal:
					currDLL = self.exportSymbolDict[item]['NameDLL']
					dllDict[currDLL] = []
				else:
					print("- %s" % (self.exportSymbolDict[item]['NameDLL']))
					#print("- %s" % (self.exportSymbolDict[item]['AddressOfNames']))
					#print("- %s" % (self.exportSymbolDict[item]['AddressOfFunctions']))
					#print
				numNames = 0
				while numNames<self.exportSymbolDict[item]['numberOfNames']:
					if [self.secionDataDict[self.exportSymbolDict[item]['sectionID']][index:index+4]] == ['']:
						break
					fRVA = struct.unpack('I', self.secionDataDict[self.exportSymbolDict[item]['sectionID']][index:index+4])[0]
					if fRVA==0:
						break
					if hex(fRVA).startswith('0x8000'):
						if retVal:
							dllDict[currDLL].append("Ordinal: %s" % (int(hex(fRVA), 16) ^ int('0x80000000', 16)))
						else:
							print("\t\t load by ordinal: %s" % (int(hex(fRVA), 16) ^ int('0x80000000', 16)))
					else:
						try:
							nindex = fRVA - self.sectionDict[self.exportSymbolDict[item]['sectionID']]['virtualaddress']
							hint = struct.unpack('H', self.secionDataDict[self.exportSymbolDict[item]['sectionID']][nindex:nindex+2])[0]
							funcName = ""
							while True:
								if self.secionDataDict[self.exportSymbolDict[item]['sectionID']][nindex]=='\x00':
									break
								funcName += struct.unpack('c', self.secionDataDict[self.exportSymbolDict[item]['sectionID']][nindex])[0]
								nindex += 1
							if retVal:
								dllDict[currDLL].append(funcName)
							else:
								print("\t\t Function: %s" % (funcName))
						except struct.error:
							if not retVal:
								print("\t\t no name found")
					index += 4
					numNames += 1
		if retVal:
			return dllDict

	def readSectionHeader(self, sectionHeader, i, resourceRVA=None):
		self.sectionDict[i] = {}
		self.sectionDict[i]['name'] = "".join(struct.unpack('8c', sectionHeader[0:8]))
		self.sectionDict[i]['misc'] = struct.unpack('I', sectionHeader[8:12])[0]
		self.sectionDict[i]['physaddress'] = struct.unpack('I', sectionHeader[8:12])[0]
		self.sectionDict[i]['virtualsize'] = struct.unpack('I', sectionHeader[8:12])[0]
		self.sectionDict[i]['virtualaddress'] = struct.unpack('I', sectionHeader[12:16])[0]
		self.sectionDict[i]['sizeofrawdata'] = struct.unpack('I', sectionHeader[16:20])[0]
		self.sectionDict[i]['ptorawdata'] = struct.unpack('I', sectionHeader[20:24])[0]
		self.sectionDict[i]['ptorelocations'] = struct.unpack('I', sectionHeader[24:28])[0]
		self.sectionDict[i]['ptolinenumbers'] = struct.unpack('I', sectionHeader[28:32])[0]
		self.sectionDict[i]['numofrelocs'] = struct.unpack('H', sectionHeader[32:34])[0]
		self.sectionDict[i]['numoflinenums'] = struct.unpack('H', sectionHeader[34:36])[0]
		self.sectionDict[i]['characteristics'] = struct.unpack('I', sectionHeader[36:40])[0]
		self.sectionDict[i]['data'] = self.filecontent[self.sectionDict[i]['ptorawdata']:self.sectionDict[i]['ptorawdata']+self.sectionDict[i]['sizeofrawdata']]
		""" check for meta information """
		if resourceRVA != None:
			if self.sectionDict[i]['virtualaddress'] == resourceRVA:
				self.resourceData = {}
				#print "Size:", len(self.sectionDict[i]['data'])
				rootDir_Characteristics = self.sectionDict[i]['data'][0:4]
				rootDir_Timestamp = struct.unpack('I', self.sectionDict[i]['data'][4:8])[0]
				#print "RootDir Timestamp:", rootDir_Timestamp
				rootDir_MajorVersion = self.sectionDict[i]['data'][8:10]
				rootDir_MinorVersion = self.sectionDict[i]['data'][10:12]
				rootDir_NumberOfNamedEntries = struct.unpack('H', self.sectionDict[i]['data'][12:14])[0]
				rootDir_NumberOfIdEntries = struct.unpack('H', self.sectionDict[i]['data'][14:16])[0]
				index = 16
				if rootDir_NumberOfNamedEntries>0:
					counter = 0
					while counter < rootDir_NumberOfIdEntries:
						counter += 1
						index += 8
				if rootDir_NumberOfIdEntries>0:
					counter = 0
					while counter < rootDir_NumberOfIdEntries:
						result = self.recursiveReadTree(i, index, 8, spaces = 2)
						if result != None:
							self.resourceData[counter] = result
						#print
						counter += 1
						index += 8
		return self.sectionDict[i]['virtualaddress']+self.sectionDict[i]['virtualsize']

	def recursiveReadTree(self, i, offset, size, isDataEntry = False, spaces = 0, result = None):
			mes = ""
			initMes = ""
			for sp in range(0, spaces):
				initMes += " "
			if size == 8 and not isDataEntry:
				""" _IMAGE_RESOURCE_DIRECTORY_ENTRY """
				name = struct.unpack('I', self.sectionDict[i]['data'][offset:offset+4])[0]
				offsetToData = struct.unpack('H', self.sectionDict[i]['data'][offset+4:offset+6])[0]
				type = struct.unpack('H', self.sectionDict[i]['data'][offset+6:offset+8])[0]
				#mes = initMes
				#try:
				#	mes += "Name/ID: %s (%s)" % (name, self.resourceInformation[name])
				#except KeyError as e:
				#	mes += "Name/ID: %s (%s)" % (name, [self.sectionDict[i]['data'][offset:offset+4]])
				#print(mes)
				#mes = initMes
				#mes += "OffsetToData: %s" % (offsetToData)
				#print(mes)
				#mes = initMes
				#mes += "Type: %s" % (type)
				#print(mes)
				#mes = initMes
				newData = [name, offsetToData, type]
				if not result:
					result = newData
				else:
					result.append(newData)
				if type != 0:
					return self.recursiveReadTree(i, offsetToData, 16, spaces = spaces + 2, result = result)
				else:
					return self.recursiveReadTree(i, offsetToData, 16, isDataEntry = True, spaces = spaces + 2, result = result)
			elif size == 16 and not isDataEntry:
				""" _IMAGE_RESOURCE_DIRECTORY """
				Characteristics = struct.unpack('I', self.sectionDict[i]['data'][offset:offset+4])[0]
				Timestamp = struct.unpack('I', self.sectionDict[i]['data'][offset+4:offset+8])[0]
				MajorVersion = self.sectionDict[i]['data'][offset+8:offset+10]
				MinorVersion = self.sectionDict[i]['data'][offset+10:offset+12]
				NumberOfNamedEntries = struct.unpack('H', self.sectionDict[i]['data'][offset+12:offset+14])[0]
				NumberOfIdEntries = struct.unpack('H', self.sectionDict[i]['data'][offset+14:offset+16])[0]
				#mes = initMes
				#mes += "Timestamp: %s" % (Timestamp)
				#print(mes)
				#mes = initMes
				#mes += "NumberOfNamedEntries: %s" % (NumberOfNamedEntries)
				#print(mes)
				#mes = initMes
				#mes += "NumberOfIdEntries: %s" % (NumberOfIdEntries)
				#print(mes)
				#mes = initMes
				counter = 0
				newData = [Characteristics, Timestamp, MajorVersion, MinorVersion, NumberOfNamedEntries, NumberOfIdEntries]
				result.append(newData)
				while counter < NumberOfIdEntries:
					return self.recursiveReadTree(i, offset+16, 8, spaces = spaces + 2, result = result)
					counter += 1
			elif size == 16 and isDataEntry:
				OffsetToData = self.sectionDict[i]['data'][offset:offset+4]
				Size = self.sectionDict[i]['data'][offset+4:offset+8]
				CodePage = self.sectionDict[i]['data'][offset+8:offset+12]
				Reserved = self.sectionDict[i]['data'][offset+12:offset+16]
				#mes = initMes
				#mes += "Next Offset: %s (%s)" % (OffsetToData.encode('hex'), self.sectionDict[i]['virtualaddress'])
				#print(mes)
				#mes = initMes
				#mes += "Size: %s (%s)" % ([Size], struct.unpack('I', Size)[0])
				#print(mes)
				#mes = initMes
				#mes += "CodePage: %s" % (CodePage.encode('hex'))
				#print(mes)
				#mes = initMes
				#mes += "Reserved: %s" % (Reserved.encode('hex'))
				#print(mes)
				#mes = initMes
				newData = [OffsetToData, Size, CodePage, Reserved]
				result.append(newData)
				return self.recursiveReadTree(i, struct.unpack('I', OffsetToData)[0], struct.unpack('I', Size)[0], isDataEntry = True, spaces = spaces + 2, result = result)
			elif isDataEntry:
				#print offset, offset-self.sectionDict[i]['virtualaddress']
				rva = offset-self.sectionDict[i]['virtualaddress']
				resourceData = self.sectionDict[i]['data'][rva:rva+size]
				#print [resourceData]
				result.append([resourceData])
				return result
			return result

	def readPEOptHeader(self, peOptionalHeader):
		self.peoptDict['01_optionalHeaderMagic'] = peOptionalHeader[0:2]
		if self.peoptDict['01_optionalHeaderMagic']=='\x0b\x01':
			self.peoptDict['01_optionalHeaderMagic']='PE32'
		elif self.peoptDict['01_optionalHeaderMagic']=='\x0b\x02':
			self.peoptDict['01_optionalHeaderMagic']='PE32+'
		self.peoptDict['02_majorlnkv'] = struct.unpack('b', peOptionalHeader[2])[0]
		self.peoptDict['03_minorlnkv'] = struct.unpack('b', peOptionalHeader[3])[0]
		self.peoptDict['04_codesize'] = struct.unpack('i', peOptionalHeader[4:8])[0]
		self.peoptDict['05_initsize'] = struct.unpack('i', peOptionalHeader[8:12])[0]
		self.peoptDict['06_uninitsize'] = struct.unpack('i', peOptionalHeader[12:16])[0]
		self.peoptDict['07_entrypoint'] = struct.unpack('i', peOptionalHeader[16:20])[0]
		self.peoptDict['08_baseofcode'] = struct.unpack('i', peOptionalHeader[20:24])[0]
		self.peoptDict['09_baseofdata'] = struct.unpack('i', peOptionalHeader[24:28])[0]
		self.peoptDict['10_imagebase'] = struct.unpack('i', peOptionalHeader[28:32])[0]
		self.peoptDict['11_sectionalignment'] = struct.unpack('i', peOptionalHeader[32:36])[0]
		self.peoptDict['12_filealignment'] = struct.unpack('I', peOptionalHeader[36:40])[0]
		self.peoptDict['13_majorop'] = struct.unpack('h', peOptionalHeader[40:42])[0]
		self.peoptDict['14_minorop'] = struct.unpack('h', peOptionalHeader[42:44])[0]
		self.peoptDict['15_majorimage'] = struct.unpack('h', peOptionalHeader[44:46])[0]
		self.peoptDict['16_minorimage'] = struct.unpack('h', peOptionalHeader[46:48])[0]
		self.peoptDict['17_majorsubver'] = struct.unpack('h', peOptionalHeader[48:50])[0]
		self.peoptDict['18_minorsubver'] = struct.unpack('h', peOptionalHeader[50:52])[0]
		self.peoptDict['19_win32verval'] = struct.unpack('i', peOptionalHeader[52:56])[0]
		self.peoptDict['20_sizeofimage'] = struct.unpack('i', peOptionalHeader[56:60])[0]
		self.peoptDict['21_sizeofheaders'] = struct.unpack('i', peOptionalHeader[60:64])[0]
		self.peoptDict['22_checksum'] = struct.unpack('i', peOptionalHeader[64:68])[0]
		self.peoptDict['23_subsystem'] = struct.unpack('h', peOptionalHeader[68:70])[0]
		self.peoptDict['24_DllCharacteristics'] = bin(int(hex(struct.unpack('h', peOptionalHeader[70:72])[0]), 16))[2:]
		self.peoptDict['25_SizeOfStackReserve'] = struct.unpack('i', peOptionalHeader[72:76])[0]
		self.peoptDict['26_SizeOfStackCommit'] = struct.unpack('i', peOptionalHeader[76:80])[0]
		self.peoptDict['27_SizeOfHeapReserve'] = struct.unpack('i', peOptionalHeader[80:84])[0]
		self.peoptDict['28_SizeOfHeapCommit'] = struct.unpack('i', peOptionalHeader[84:88])[0]
		self.peoptDict['29_loaderflags'] = struct.unpack('I', peOptionalHeader[88:92])[0]
		self.peoptDict['30_NumberOfRvaAndSizes'] = struct.unpack('I', peOptionalHeader[92:96])[0]

		self.peoptDict['31_imageDataDirectory'] = {}
		init1 = 96
		init2 = 100
		resourceRVA = None
		#for i in range(0,  self.peoptDict['NumberOfRvaAndSizes']):
		for i in range(0,  16):
			try:
				rva = struct.unpack('I', peOptionalHeader[init1:init2])[0]
				size = struct.unpack('I', peOptionalHeader[init2:init2+4])[0]
				self.peoptDict['31_imageDataDirectory'][self.datadirNames[i]] = (rva, size)
				if self.datadirNames[i] == 'Resource table':
					resourceRVA = rva
			except:
				pass
			init1 += 8
			init2 += 8

		#print self.peoptDict['imageDataDirectory']
		#print [peOptionalHeader[96:]], len(peOptionalHeader[96:])
		return resourceRVA

	def readPEHeader(self, peHeader):
		self.peDict['01_machine'] = peHeader[0:2].encode('hex')
		if self.peDict['01_machine'] == '4c01':
			self.peDict['01_machine'] = "i386"
		self.peDict['02_numberofsections'] = struct.unpack('h', peHeader[2:4])[0]
		self.peDict['03_timedatestamp'] = struct.unpack('i', peHeader[4:8])[0]
		self.peDict['04_pSymbolTable'] = struct.unpack('I', peHeader[8:12])[0]
		self.peDict['05_numSymbols'] = struct.unpack('I', peHeader[12:16])[0]
		self.peDict['06_sizeoptheader'] = struct.unpack('h', peHeader[16:18])[0]
		self.peDict['07_chars'] = bin(int(hex(struct.unpack('H', peHeader[18:20])[0]), 16))


	def readMSDOSHeader(self, msdosHeader):
		self.msdosDict['01_magicnumber'] = struct.unpack('H', msdosHeader[0:2])[0]
		self.msdosDict['02_bytesLastPage'] = struct.unpack('H', msdosHeader[2:4])[0]
		self.msdosDict['03_pagesInFile'] = struct.unpack('H', msdosHeader[4:6])[0]
		self.msdosDict['04_numRelocs'] = struct.unpack('H', msdosHeader[6:8])[0]
		self.msdosDict['05_paragraphs'] = struct.unpack('H', msdosHeader[8:10])[0]
		self.msdosDict['06_minpara'] = struct.unpack('H', msdosHeader[10:12])[0]
		self.msdosDict['07_maxpara'] = struct.unpack('H', msdosHeader[12:14])[0]
		self.msdosDict['08_stackmod'] = struct.unpack('H', msdosHeader[14:16])[0]
		self.msdosDict['09_spregister'] = struct.unpack('H', msdosHeader[16:18])[0]
		self.msdosDict['10_chksum'] = struct.unpack('H', msdosHeader[18:20])[0]
		self.msdosDict['11_ipregister'] = struct.unpack('H', msdosHeader[20:22])[0]
		self.msdosDict['12_codemod'] = struct.unpack('H', msdosHeader[22:24])[0]
		self.msdosDict['13_offsetfirstreloc'] = struct.unpack('H', msdosHeader[24:26])[0]
		self.msdosDict['14_overlaynum'] = struct.unpack('H', msdosHeader[26:28])[0]
		self.msdosDict['15_pPEHeader'] = struct.unpack('I', msdosHeader[60:64])[0]

	def printMSDOSHeader(self):
		print("found MZ header:")
		print("\t bytes of last page: %s" % (self.msdosDict['02_bytesLastPage']))
		print("\t pages in file: %s" % (self.msdosDict['03_pagesInFile']))
		print("\t number of relocations: %s" % (self.msdosDict['04_numRelocs']))
		print("\t msdos header size: %s" % (self.msdosDict['05_paragraphs']*16))
		print("\t minimum paragraphs: %s" % (self.msdosDict['06_minpara']))
		print("\t maximum paragraphs: %s" % (self.msdosDict['07_maxpara']))
		print("\t stack-segment modul: %s" % (self.msdosDict['08_stackmod']))
		print("\t SP register: %s" % (self.msdosDict['09_spregister']))
		print("\t checksumme: %s" % (self.msdosDict['10_chksum']))
		print("\t IP register: %s" % (self.msdosDict['11_ipregister']))
		print("\t code modul: %s" % (self.msdosDict['12_codemod']))
		print("\t offset first relocation: %s" % (self.msdosDict['13_offsetfirstreloc']))
		print("\t overlay number: %s" % (self.msdosDict['14_overlaynum']))
		print("\t PE header offset: %s" % (self.msdosDict['15_pPEHeader']))

	def printPEHeader(self):
		print("found PE header (size: %s)" % (len(self.peHeader)))
		print("\t machine: %s" % (self.peDict['01_machine']))
		print("\t number of sections: %s" % (self.peDict['02_numberofsections']))
		print("\t timedatestamp: %s (%s)" % (self.peDict['03_timedatestamp'], time.ctime(float(self.peDict['03_timedatestamp']))))
		print("\t pointer to symbol table: %s (%s)" % (self.peDict['04_pSymbolTable'], hex(self.peDict['04_pSymbolTable'])))
		print("\t number of symbols: %s (%s)" % (self.peDict['05_numSymbols'], hex(self.peDict['05_numSymbols'])))
		print("\t size of optional header: %s" % (self.peDict['06_sizeoptheader']))
		print("\t characteristics: %s (%s) (%s)" % (self.peDict['07_chars'], hex(struct.unpack('H', self.peHeader[18:20])[0]), len(self.peDict['07_chars'])))

	def printPEOptHeader(self):
		print("found PE optional header (size: %s)" % (len(self.peOptionalHeader)))
		print("\t Magic Number: %s" % (self.peoptDict['01_optionalHeaderMagic']))
		print("\t\t Magic: %s" % (hex(struct.unpack('h', self.peOptionalHeader[0:2])[0])))
		print("\t major linker version: %s" % (self.peoptDict['02_majorlnkv']))
		print("\t minor linker version: %s" % (self.peoptDict['03_minorlnkv']))
		print("\t size of code: %s" % (self.peoptDict['04_codesize']))
		print("\t size of initialized data: %s" % (self.peoptDict['05_initsize']))
		print("\t size of uninitialized data: %s" % (self.peoptDict['06_uninitsize']))
		print("\t code entry point: %s (execution starts here)" % (self.peoptDict['07_entrypoint']))
		print("\t base of code: %s" % (self.peoptDict['08_baseofcode']))
		print("\t base of data: %s" % (self.peoptDict['09_baseofdata']))
		print("\t image base: %s (%s)" % (self.peoptDict['10_imagebase'], hex(self.peoptDict['10_imagebase'])))
		if hex(self.peoptDict['10_imagebase'])=='0x400000':
			print("\t\t default for applications")
		else:
			print("\t\t uncommon image base")
		print("\t section alignment: %s" % (self.peoptDict['11_sectionalignment']))
		print("\t file alignment: %s" % (self.peoptDict['12_filealignment']))
		print("\t MajorOperatingSystemVersion: %s" % (self.peoptDict['13_majorop']))
		print("\t MinorOperatingSystemVersion: %s" % (self.peoptDict['14_minorop']))
		print("\t MajorImageVersion: %s" % (self.peoptDict['15_majorimage']))
		print("\t MinorImageVersion: %s" % (self.peoptDict['16_minorimage']))
		print("\t MajorSubSystemVersion: %s (%s)" % (self.peoptDict['17_majorsubver'], hex(self.peoptDict['17_majorsubver'])))
		print("\t MinorSubSystemVersion: %s (%s)" % (self.peoptDict['18_minorsubver'], hex(self.peoptDict['18_minorsubver'])))
		print("\t Win32VersionValue: %s" % (self.peoptDict['19_win32verval']))
		print("\t size of image (memory): %s" % (self.peoptDict['20_sizeofimage']))
		print("\t size of headers (offset to first section raw data): %s" % (self.peoptDict['21_sizeofheaders']))
		print("\t checksum (for drivers): %s" % (self.peoptDict['22_checksum']))
		print("\t subsystem: %s" % (self.peoptDict['23_subsystem']))
		if self.peoptDict['23_subsystem'] == 1:
			print("\t\t no subsystem required")
		elif self.peoptDict['23_subsystem'] == 2:
			print("\t\t win32 graphical binary")
		elif self.peoptDict['23_subsystem'] == 3:
			print("\t\t win32 console binary")
		elif self.peoptDict['23_subsystem'] == 4:
			print("\t\t unknown")
		elif self.peoptDict['23_subsystem'] == 5:
			print("\t\t OS/2 console binary")
		elif self.peoptDict['23_subsystem'] == 6:
			print("\t\t unknown")
		elif self.peoptDict['23_subsystem'] == 7:
			print("\t\t POSIX console subsystem")
		print("\t DllCharacteristics: %s" % (self.peoptDict['24_DllCharacteristics']))
		print("\t SizeOfStackReserve: %s" % (self.peoptDict['25_SizeOfStackReserve']))
		print("\t SizeOfStackCommit: %s" % (self.peoptDict['26_SizeOfStackCommit']))
		print("\t SizeOfHeapReserve: %s" % (self.peoptDict['27_SizeOfHeapReserve']))
		print("\t SizeOfHeapCommit: %s" % (self.peoptDict['28_SizeOfHeapCommit']))
		print("\t LoaderFlags: %s (%s)" % (self.peoptDict['29_loaderflags'], hex(self.peoptDict['29_loaderflags'])))
		print("\t NumberOfRvaAndSizes: %s (%s)" % (self.peoptDict['30_NumberOfRvaAndSizes'], hex(self.peoptDict['30_NumberOfRvaAndSizes'])))
		for name in self.peoptDict['31_imageDataDirectory']:
			if self.peoptDict['31_imageDataDirectory'][name][0]!=0 and self.peoptDict['31_imageDataDirectory'][name][1]!=0:
				print("\t\tName: %s RVA: %s (%s) Size: %s" % (name, self.peoptDict['31_imageDataDirectory'][name][0], hex(self.peoptDict['31_imageDataDirectory'][name][0]), self.peoptDict['31_imageDataDirectory'][name][1]))

	def printSectionHeader(self):
		for sec in self.sectionDict:
			print("found section name: %s" % (self.sectionDict[sec]['name']))
			print("\t PhysicalAddress: %s (%s)" % (self.sectionDict[sec]['physaddress'], hex(self.sectionDict[sec]['physaddress'])))
			print("\t VirtualSize: %s (%s)" % (self.sectionDict[sec]['virtualsize'], hex(self.sectionDict[sec]['virtualsize'])))
			print("\t VirtualAddress: %s (%s)" % (self.sectionDict[sec]['virtualaddress'], hex(self.sectionDict[sec]['virtualaddress'])))
			print("\t Size of Raw Data: %s (%s)" % (self.sectionDict[sec]['sizeofrawdata'], hex(self.sectionDict[sec]['sizeofrawdata'])))
			print("\t Pointer to Raw Data: %s (%s)" % (self.sectionDict[sec]['ptorawdata'], hex(self.sectionDict[sec]['ptorawdata'])))
			print("\t Pointer to Relocations: %s (%s)" % (self.sectionDict[sec]['ptorelocations'], hex(self.sectionDict[sec]['ptorelocations'])))
			print("\t Pointer to Linenumbers: %s (%s)" % (self.sectionDict[sec]['ptolinenumbers'], hex(self.sectionDict[sec]['ptolinenumbers'])))
			print("\t Number of Relocations: %s (%s)"  % (self.sectionDict[sec]['numofrelocs'], hex(self.sectionDict[sec]['numofrelocs'])))
			print("\t Number of Linenumbers: %s (%s)" % (self.sectionDict[sec]['numoflinenums'], hex(self.sectionDict[sec]['numoflinenums'])))
			print("\t Characteristics: %s (%s)" % (self.sectionDict[sec]['characteristics'], hex(self.sectionDict[sec]['characteristics'])))
			#if self.sectionDict[sec]['name'].strip('\x00') == '.rsrc':
			#	fp = open('textpart.bin', 'wb')
			#	fp.write(self.sectionDict[sec]['data'])
			#	fp.close()
			#	print("\t Data: %s (%s)" % (self.sectionDict[sec]['data'], len(self.sectionDict[sec]['data'])))
			#if self.sectionDict[sec]['name'].strip('\x00') == '.text':
			#	print("\t Data: %s (%s)" % ([self.sectionDict[sec]['data']], len(self.sectionDict[sec]['data'])))
			#	fp = open('textpart.bin', 'wb')
			#	fp.write(self.sectionDict[sec]['data'])
			#	fp.close()

	def printResourceInformation(self):
		if self.resourceData:
			print("found PE resource information")
			for rootDir in self.resourceData:
				nameID = self.resourceData[rootDir][0]
				try:
					name = self.resourceInformation[nameID]
				except:
					name = str(nameID)
				if name.lower() == 'version':
					rawData = self.resourceData[rootDir][-1][0]
					length = rawData[0:2]
					valueLength = struct.unpack('H', rawData[2:4])[0]
					type = rawData[4:6]
					key = rawData[6:36] ### VS_VERSION_INFO (Unicode)
					print("%s" % (key))
					index = 36
					while rawData[index] == '\x00':
						index += 1
					### Member
					if valueLength>0:
						memberSignature = rawData[index:index+4]
						if memberSignature == '\xbd\x04\xef\xfe': # VS_FIXEDFILEINFO
							dwStrucVersion = rawData[index+4:index+8]
							print("structure version: %s.%s" % (struct.unpack('H', dwStrucVersion[2:4])[0], struct.unpack('H', dwStrucVersion[0:2])[0]))
							dwFileVersionMS = rawData[index+8:index+12]
							dwFileVersionLS = rawData[index+12:index+16]
							print("file version: %s.%s" % (struct.unpack('I', dwFileVersionLS)[0], struct.unpack('I', dwFileVersionMS)[0]))
							dwProductVersionMS = rawData[index+16:index+20]
							dwProductVersionLS = rawData[index+20:index+24]
							print("product version: %s.%s" % (struct.unpack('I', dwProductVersionLS)[0], struct.unpack('I', dwProductVersionMS)[0]))
							dwFileFlagsMask = rawData[index+24:index+28]
							print("file flags mask: %s" % ([dwFileFlagsMask]))
							dwFileFlags = rawData[index+28:index+32]
							print("file flags: %s" % ([dwFileFlags]))
							dwFileOS = rawData[index+32:index+36]
							print("designed for:")
							if dwFileOS == '\x04\x00\x00\x00':
								print("\t VOS__WINDOWS32")
							else:
								print('\t VOS_UNKNOWN (%s)' % ([dwFileOS]))
							dwFileType = rawData[index+36:index+40]
							print("file type:")
							if dwFileType == '\x01\x00\x00\x00':
								print("\t VFT_APP")
							else:
								print("\t VFT_UNKNOWN (%s)" % ([dwFileType]))
							dwFileSubtype = rawData[index+40:index+44]
							#print [dwFileSubtype]
							#dwFileDateMS = struct.unpack('I', rawData[index+44:index+48])[0]
							dwFileDateMS = rawData[index+44:index+48]
							print("Creation Date (MS): %s" % ([dwFileDateMS]))
							dwFileDateLS = rawData[index+48:index+52]
							print("Creation Date (LS): %s" % ([dwFileDateLS]))
							index = index + 52
						else:
							print("wrong member signature: %s" % ([memberSignature]))
					while rawData[index] == '\x00':
						index += 1
					### Children
					length = rawData[index:index+2]
					print("child length: %s" % (struct.unpack('H', length)[0]))
					valueLength = rawData[index+2:index+4]
					print("value length %s (should be zero)" % (struct.unpack('H', valueLength)[0]))
					type = rawData[index+4:index+6]
					stringFileInfoBlock = rawData[index+6:index+6+struct.unpack('H', length)[0]]
					varFileInfoBlock = rawData[index+6+struct.unpack('H', length)[0]:]
					if stringFileInfoBlock.startswith('S'):
						#key = rawData[index+6:index+34]
						key = stringFileInfoBlock[0:28]
						print("%s" % (key))
						self.stringTable(stringFileInfoBlock[28:])
					if varFileInfoBlock.startswith('V'):
						key = varFileInfoBlock[0:24]
						print("%s" % (key))
						self.analyseVarFileInfo(varFileInfoBlock[24:])
		else:
			print("no resource information found")

	def stringTable(self, datablock):
		index = 0
		### skip padding
		while datablock[index] == '\x00':
			index += 1
		wLength = datablock[index:index+2]
		print("  string table length: %s" % (struct.unpack('H', wLength)[0]))
		wValueLength = datablock[index+2:index+4]
		wType = datablock[index+4:index+6]
		szKey = datablock[index+6:index+22]
		print('  language:')
		if szKey[0:8] == '0\x008\x000\x009\x00':
			print('\t u.k. english')
		else:
			print("  %s" % ([szKey[0:8]]))
		print('  character set:')
		if szKey[8:] == '0\x004\x00B\x000\x00' or szKey[8:] == '0\x004\x00b\x000\x00':
			print("\t unicode")
		else:
			print("  %s" % ([szKey[8:]]))
		self.childString(datablock[index+22:struct.unpack('H', wLength)[0]])

	def childString(self, entry):
		index = 0
		### skip padding
		while entry[index] == '\x00':
			index += 1
		wLength = entry[index:index+2]
		#print("    string entry length: %s" % (struct.unpack('H', wLength)[0]))
		wValueLength = struct.unpack('H', entry[index+2:index+4])[0]
		#print("Value Length: %s" % ([wValueLength]))
		wType = entry[index+4:index+6]
		#print("wType: %s" % ([wType]))
		unicodeString = ""
		position = index + 6
		while entry[position] != '\x00' or entry[position+1] != '\x00':
			unicodeString += entry[position]
			position += 1
		#print("    %s %s" % (unicodeString, [unicodeString]))
		index = position
		### skip padding
		while entry[index] == '\x00':
			index += 1
		value = ""
		if wValueLength > 0:
			try:
				while entry[index] != '\x00' or entry[index+1] != '\x00':
					value += entry[index]
					index += 1
			except IndexError as e:
				pass
		#print("    %s" % (value))
		print("  %s: %s" % (unicodeString, value ))
		if len(entry[index:])>10:
			self.childString(entry[index:])
		return

	def analyseVarFileInfo(self, datablock):
		#print [datablock]
		pass


############################################################################



