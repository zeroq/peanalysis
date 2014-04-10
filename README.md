peanalysis
==========

Python script to parse PE header information. Sample output:

### found MZ header:
*	 bytes of last page: 144
*	 pages in file: 3
*	 number of relocations: 0
*	 msdos header size: 64
*	 minimum paragraphs: 0
*	 maximum paragraphs: 65535
*	 stack-segment modul: 0
*	 SP register: 184
*	 checksumme: 0
*	 IP register: 0
*	 code modul: 0
*	 offset first relocation: 64
*	 overlay number: 0
*	 PE header offset: 216
### found PE header (size: 20)
	 machine: i386
	 number of sections: 4
	 timedatestamp: 1343616786 (Mon Jul 30 04:53:06 2012)
	 pointer to symbol table: 0 (0x0)
	 number of symbols: 0 (0x0)
	 size of optional header: 224
	 characteristics: 0b100001111 (0x10f) (11)
### found PE optional header (size: 224)
	 Magic Number: PE32
		 Magic: 0x10b
	 major linker version: 6
	 minor linker version: 0
	 size of code: 24576
	 size of initialized data: 45056
	 size of uninitialized data: 0
	 code entry point: 6576 (execution starts here)
	 base of code: 4096
	 base of data: 28672
	 image base: 4194304 (0x400000)
		 default for applications
	 section alignment: 4096
	 file alignment: 4096
	 MajorOperatingSystemVersion: 4
	 MinorOperatingSystemVersion: 0
	 MajorImageVersion: 0
	 MinorImageVersion: 0
	 MajorSubSystemVersion: 4 (0x4)
	 MinorSubSystemVersion: 0 (0x0)
	 Win32VersionValue: 0
	 size of image (memory): 73728
	 size of headers (offset to first section raw data): 4096
	 checksum (for drivers): 0
	 subsystem: 2
		 win32 graphical binary
	 DllCharacteristics: 0
	 SizeOfStackReserve: 1048576
	 SizeOfStackCommit: 4096
	 SizeOfHeapReserve: 1048576
	 SizeOfHeapCommit: 4096
	 LoaderFlags: 0 (0x0)
	 NumberOfRvaAndSizes: 16 (0x10)
		Name: Import symbols table RVA: 29956 (0x7504) Size: 60
		Name: Resource table RVA: 49152 (0xc000) Size: 21600
		Name: Import address table RVA: 28672 (0x7000) Size: 244
found section name: .text
	 PhysicalAddress: 23404 (0x5b6c)
	 VirtualSize: 23404 (0x5b6c)
	 VirtualAddress: 4096 (0x1000)
	 Size of Raw Data: 24576 (0x6000)
	 Pointer to Raw Data: 4096 (0x1000)
	 Pointer to Relocations: 0 (0x0)
	 Pointer to Linenumbers: 0 (0x0)
	 Number of Relocations: 0 (0x0)
	 Number of Linenumbers: 0 (0x0)
	 Characteristics: 1610612768 (0x60000020)
found section name: .rdata
	 PhysicalAddress: 2604 (0xa2c)
	 VirtualSize: 2604 (0xa2c)
	 VirtualAddress: 28672 (0x7000)
	 Size of Raw Data: 4096 (0x1000)
	 Pointer to Raw Data: 28672 (0x7000)
	 Pointer to Relocations: 0 (0x0)
	 Pointer to Linenumbers: 0 (0x0)
	 Number of Relocations: 0 (0x0)
	 Number of Linenumbers: 0 (0x0)
	 Characteristics: 1073741888 (0x40000040)
found section name: .data
	 PhysicalAddress: 16156 (0x3f1c)
	 VirtualSize: 16156 (0x3f1c)
	 VirtualAddress: 32768 (0x8000)
	 Size of Raw Data: 12288 (0x3000)
	 Pointer to Raw Data: 32768 (0x8000)
	 Pointer to Relocations: 0 (0x0)
	 Pointer to Linenumbers: 0 (0x0)
	 Number of Relocations: 0 (0x0)
	 Number of Linenumbers: 0 (0x0)
	 Characteristics: 3221225536 (0xc0000040)
found section name: .rsrc
	 PhysicalAddress: 21600 (0x5460)
	 VirtualSize: 21600 (0x5460)
	 VirtualAddress: 49152 (0xc000)
	 Size of Raw Data: 24576 (0x6000)
	 Pointer to Raw Data: 45056 (0xb000)
	 Pointer to Relocations: 0 (0x0)
	 Pointer to Linenumbers: 0 (0x0)
	 Number of Relocations: 0 (0x0)
	 Number of Linenumbers: 0 (0x0)
	 Characteristics: 1073741888 (0x40000040)
Exported Symbols:
	 no export symbols available
KERNEL32.dll
	 Original First Thunk: 30032 (0x7550)
	 TimeDateStamp: 0
	 ForwarderChain: 0 (0x0)
	 Name: 30496 (0x7720)
	 First Thunk: 28688 (0x7010)
ADVAPI32.dll
	 Original First Thunk: 30016 (0x7540)
	 TimeDateStamp: 0
	 ForwarderChain: 0 (0x0)
	 Name: 30558 (0x775e)
	 First Thunk: 28672 (0x7000)

Imported Functions:

KERNEL32.dll
		 Function: CreateFileA
		 Function: FindClose
		 Function: FindNextFileA
		 Function: FindFirstFileA
		 Function: lstrlenA
		 Function: SetFileTime
		 Function: LockResource
		 Function: GetEnvironmentVariableA
		 Function: LoadResource
		 Function: SizeofResource
		 Function: FindResourceA
		 Function: CloseHandle
		 Function: GetModuleFileNameA
		 Function: WriteFile
		 Function: WinExec
		 Function: GetModuleHandleA
		 Function: GetStartupInfoA
		 Function: GetCommandLineA
		 Function: GetVersion
		 Function: ExitProcess
		 Function: HeapFree
		 Function: GetLastError
		 Function: HeapAlloc
		 Function: TerminateProcess
		 Function: GetCurrentProcess
		 Function: UnhandledExceptionFilter
		 Function: FreeEnvironmentStringsA
		 Function: FreeEnvironmentStringsW
		 Function: WideCharToMultiByte
		 Function: GetEnvironmentStrings
		 Function: GetEnvironmentStringsW
		 Function: SetHandleCount
		 Function: GetStdHandle
		 Function: GetFileType
		 Function: GetVersionExA
		 Function: HeapDestroy
		 Function: HeapCreate
		 Function: VirtualFree
		 Function: RtlUnwind
		 Function: VirtualAlloc
		 Function: HeapReAlloc
		 Function: SetStdHandle
		 Function: FlushFileBuffers
		 Function: SetFilePointer
		 Function: GetCPInfo
		 Function: GetACP
		 Function: GetOEMCP
		 Function: GetProcAddress
		 Function: LoadLibraryA
		 Function: SetEndOfFile
		 Function: ReadFile
		 Function: MultiByteToWideChar
		 Function: LCMapStringA
		 Function: LCMapStringW
		 Function: GetStringTypeA
		 Function: GetStringTypeW
ADVAPI32.dll
		 Function: RegSetValueExA
		 Function: RegCloseKey
		 Function: RegCreateKeyA
{}
no resource information found
