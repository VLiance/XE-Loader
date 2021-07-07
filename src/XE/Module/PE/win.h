 /*  -== XE-Loader ==-
 *
 *  Load [.exe .elf / .dll .so] from memory and remap functions
 *  Run your binaries on any x86 hardware
 *
 *  @autors
 *   - Maeiky
 *  
 * Copyright (c) 2021 - V·Liance
 *
 * The contents of this file are subject to the Apache License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * If a copy of the Apache License Version 2.0 was not distributed with this file,
 * You can obtain one at https://www.apache.org/licenses/LICENSE-2.0.html
 *
*/
#ifndef HDEF_WIN
#define HDEF_WIN

#if defined( ImWin) && !defined(No_FullWinHeader)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#include <windows.h>
//#include "full_windows.h"

#define HDEF_Win  //Desactivate following
#else // RealWin

	#ifdef ImWin
	#define STDCALL __stdcall
	#else // CpcDos
	#define STDCALL __attribute__((stdcall))
	#endif
	#define NTAPI STDCALL
	#define CALLBACK STDCALL

	#ifdef ImWin
	#undef CDECL
	#define CDECL  __cdecl
	#else // CpcDos
	#define CDECL __attribute__((cdecl))
	#endif

	#ifndef HDEF_Win
	#define HDEF_Win


	#define WINAPI STDCALL

	#include <stdlib.h>
	#include <string.h>

	#define BOOL bool
	#define FALSE false
	#define TRUE true

	#define CONST const
	#define VOID void
	
	#define WINAPIV __cdecl
	#define APIENTRY WINAPI

#ifndef __LP64__
#define __LONG32 long
#else
#define __LONG32 int
#endif

typedef char CHAR;
typedef short SHORT;
typedef __LONG32 LONG;

	#ifndef __SIZE_TYPE__
	#  ifdef _WIN64
	#    define __SIZE_TYPE__ long long unsigned int
	#  else
	#    define __SIZE_TYPE__ long unsigned int
	#  endif
	#endif
	  typedef int INT;
	  typedef unsigned int UINT;
	  typedef unsigned int *PUINT;

	#ifndef _LPCVOID_DEFINED
	#define _LPCVOID_DEFINED
	  typedef CONST void *LPCVOID;
	#endif

	#ifdef _WIN64
	  __MINGW_EXTENSION typedef __int64 INT_PTR,*PINT_PTR;
	  __MINGW_EXTENSION typedef unsigned __int64 UINT_PTR,*PUINT_PTR;
	  __MINGW_EXTENSION typedef __int64 LONG_PTR,*PLONG_PTR;
	  __MINGW_EXTENSION typedef unsigned __int64 ULONG_PTR,*PULONG_PTR;
	#define __int3264 __int64
	#else
	  typedef int INT_PTR,*PINT_PTR;
	  typedef unsigned int UINT_PTR,*PUINT_PTR;
	  typedef long LONG_PTR,*PLONG_PTR;
	  typedef unsigned long ULONG_PTR,*PULONG_PTR;
	#define __int3264 int
	#endif


	typedef ULONG_PTR SIZE_T,*PSIZE_T;
	typedef LONG_PTR SSIZE_T,*PSSIZE_T;

	#define UNREFERENCED_PARAMETER(P) {(P) = (P);}
	
#define __MINGW_TYPEDEF_AW(type) typedef __MINGW_NAME_AW(type) type;
#define __MINGW_TYPEDEF_UAW(type) typedef __MINGW_NAME_UAW(type) type;

#ifndef __LP64__	/* 32 bit target, 64 bit Mingw target */
#define __LONG32 long
#else			/* 64 bit Cygwin target */
#define __LONG32 int
#endif

#ifndef WINUSERAPI
#define WINUSERAPI
#endif



	#ifdef _WIN64
	#define MAX_NATURAL_ALIGNMENT sizeof(ULONGLONG)
	#define MEMORY_ALLOCATION_ALIGNMENT 16
	#else
	#define MAX_NATURAL_ALIGNMENT sizeof(DWORD)
	#define MEMORY_ALLOCATION_ALIGNMENT 8
	#endif

	#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x0600
	#endif


	#define __int8 char
	#define __int16 short
	#define __int32 int
	#define __int64 long long

	typedef __int64 LONGLONG;
	typedef unsigned __int64 ULONGLONG;

	#define MAXLONGLONG (0x7fffffffffffffffll)

	typedef LONGLONG *PLONGLONG;
	typedef ULONGLONG *PULONGLONG;
	typedef LONGLONG USN;

	#define _DWORDLONG_
	typedef ULONGLONG DWORDLONG;
	typedef DWORDLONG *PDWORDLONG;
	
	
	
	typedef char CHAR;
	typedef CHAR *NPSTR,*LPSTR,*PSTR;
	typedef unsigned char BYTE;
	typedef void *PVOID;
	typedef void *PVOID64;
	typedef PVOID HANDLE;
	typedef void *LPVOID;


	typedef unsigned short WORD;
	typedef unsigned __LONG32 DWORD;
	typedef float FLOAT;
	typedef FLOAT *PFLOAT;
	typedef BYTE *PBYTE;
	typedef BYTE *LPBYTE;
	typedef int *PINT;
	typedef int *LPINT;
	typedef WORD *PWORD;
	typedef WORD *LPWORD;
	typedef __LONG32 *LPLONG;
	typedef DWORD *PDWORD;
	typedef DWORD *LPDWORD;
		
	#ifndef _LARGE_INTEGER_DEFINED
	#define _LARGE_INTEGER_DEFINED
	#if defined (__WIDL__)
	typedef struct _LARGE_INTEGER
	{
	#else
	typedef union _LARGE_INTEGER
	{
	struct
	{
	DWORD LowPart;
	LONG HighPart;
	}
	DUMMYSTRUCTNAME;
	struct
	{
	DWORD LowPart;
	LONG HighPart;
	}
	u;
	#endif
	LONGLONG QuadPart;
	}
	LARGE_INTEGER;
	typedef LARGE_INTEGER *PLARGE_INTEGER;
	#if defined (__WIDL__)
	typedef struct _ULARGE_INTEGER
	{
	#else
	typedef union _ULARGE_INTEGER
	{
	struct
	{
	DWORD LowPart;
	DWORD HighPart;
	}
	DUMMYSTRUCTNAME;
	struct
	{
	DWORD LowPart;
	DWORD HighPart;
	}
	u;
	#endif
	ULONGLONG QuadPart;
	}
	ULARGE_INTEGER;
	typedef ULARGE_INTEGER *PULARGE_INTEGER;
	typedef struct _LUID
	{
	DWORD LowPart;
	LONG HighPart;
	}
	LUID,*PLUID;
	#endif
	#define _DWORDLONG_
	typedef ULONGLONG DWORDLONG;
	typedef DWORDLONG *PDWORDLONG;

	
	#ifndef DECLSPEC_ALIGN
	#ifndef __WIDL__
		#if defined(_MSC_VER) && (_MSC_VER >= 1300) && !defined(MIDL_PASS)
		#define DECLSPEC_ALIGN(x) __declspec(align(x))
		#elif defined(__GNUC__)
		#define DECLSPEC_ALIGN(x) __attribute__ ((__aligned__ (x)))
		#else
		#define DECLSPEC_ALIGN(x)
		#endif
	#else
	#define DECLSPEC_ALIGN(x)
	#endif
	#endif

	typedef struct _RTL_SRWLOCK { PVOID Ptr; } RTL_SRWLOCK,*PRTL_SRWLOCK;
	typedef struct _RTL_CONDITION_VARIABLE { PVOID Ptr; } RTL_CONDITION_VARIABLE,*PRTL_CONDITION_VARIABLE;
	typedef RTL_CONDITION_VARIABLE CONDITION_VARIABLE, *PCONDITION_VARIABLE;


	#ifndef WINBASEAPI
	#define WINBASEAPI
	#endif
	#ifndef WINGDIAPI
	#define WINGDIAPI
	#endif

	#define DECLARE_HANDLE(name) typedef HANDLE name
	DECLARE_HANDLE (HINSTANCE);

	typedef CONST CHAR *LPCSTR,*PCSTR;

	#ifndef UNALIGNED
	#define UNALIGNED
	#endif
	
	//typedef HINSTANCE HMODULE;
	typedef unsigned short WORD;
	typedef void *HANDLE;
	typedef unsigned long DWORD;
	typedef DWORD *LPDWORD;

	typedef struct _IMAGE_BASE_RELOCATION {
	  DWORD VirtualAddress;
	  DWORD SizeOfBlock;
	} IMAGE_BASE_RELOCATION;
	typedef IMAGE_BASE_RELOCATION UNALIGNED *PIMAGE_BASE_RELOCATION;

		typedef struct _IMAGE_FILE_HEADER {
	  WORD Machine;
	  WORD NumberOfSections;
	  DWORD TimeDateStamp;
	  DWORD PointerToSymbolTable;
	  DWORD NumberOfSymbols;
	  WORD SizeOfOptionalHeader;
	  WORD Characteristics;
	} IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

	typedef struct _IMAGE_DATA_DIRECTORY {
	  DWORD VirtualAddress;
	  DWORD Size;
	} IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

	#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
	typedef struct _IMAGE_OPTIONAL_HEADER {
	  WORD Magic;
	  BYTE MajorLinkerVersion;
	  BYTE MinorLinkerVersion;
	  DWORD SizeOfCode;
	  DWORD SizeOfInitializedData;
	  DWORD SizeOfUninitializedData;
	  DWORD AddressOfEntryPoint;
	  DWORD BaseOfCode;
	  DWORD BaseOfData;
	  DWORD ImageBase;
	  DWORD SectionAlignment;
	  DWORD FileAlignment;
	  WORD MajorOperatingSystemVersion;
	  WORD MinorOperatingSystemVersion;
	  WORD MajorImageVersion;
	  WORD MinorImageVersion;
	  WORD MajorSubsystemVersion;
	  WORD MinorSubsystemVersion;
	  DWORD Win32VersionValue;
	  DWORD SizeOfImage;
	  DWORD SizeOfHeaders;
	  DWORD CheckSum;
	  WORD Subsystem;
	  WORD DllCharacteristics;
	  DWORD SizeOfStackReserve;
	  DWORD SizeOfStackCommit;
	  DWORD SizeOfHeapReserve;
	  DWORD SizeOfHeapCommit;
	  DWORD LoaderFlags;
	  DWORD NumberOfRvaAndSizes;
	  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	} IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;

	typedef struct _IMAGE_NT_HEADERS {
	  DWORD Signature;
	  IMAGE_FILE_HEADER FileHeader;
	  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	} IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;

	typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
	typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;

	#define IMAGE_SIZEOF_SHORT_NAME 8

	typedef struct _IMAGE_SECTION_HEADER {
	  BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	  union {
	DWORD PhysicalAddress;
	DWORD VirtualSize;
	  } Misc;
	  DWORD VirtualAddress;
	  DWORD SizeOfRawData;
	  DWORD PointerToRawData;
	  DWORD PointerToRelocations;
	  DWORD PointerToLinenumbers;
	  WORD NumberOfRelocations;
	  WORD NumberOfLinenumbers;
	  DWORD Characteristics;
	} IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

	#ifndef __MSABI_LONG
	#define __MSABI_LONG(x) x
	#endif
	
	#define GENERIC_READ (__MSABI_LONG(0x80000000))
	#define GENERIC_WRITE (__MSABI_LONG(0x40000000))
	#define GENERIC_EXECUTE (__MSABI_LONG(0x20000000))
	#define GENERIC_ALL (__MSABI_LONG(0x10000000))

	#define OPEN_EXISTING 3
	#define FILE_ATTRIBUTE_NORMAL 0x00000080

	typedef __LONG32 LONG;

	typedef struct _IMAGE_DOS_HEADER {
	  WORD e_magic;
	  WORD e_cblp;
	  WORD e_cp;
	  WORD e_crlc;
	  WORD e_cparhdr;
	  WORD e_minalloc;
	  WORD e_maxalloc;
	  WORD e_ss;
	  WORD e_sp;
	  WORD e_csum;
	  WORD e_ip;
	  WORD e_cs;
	  WORD e_lfarlc;
	  WORD e_ovno;
	  WORD e_res[4];
	  WORD e_oemid;
	  WORD e_oeminfo;
	  WORD e_res2[10];
	  LONG e_lfanew;
	} IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

	//typedef unsigned long ULONG_PTR,*PULONG_PTR;
	#define FIELD_OFFSET(Type, Field) ((LONG) __builtin_offsetof(Type, Field))
	#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))

	#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
	#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
	#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
	#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
	#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
	#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
	#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
	#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
	#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
	#define IMAGE_DIRECTORY_ENTRY_TLS 9
	#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
	#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
	#define IMAGE_DIRECTORY_ENTRY_IAT 12
	#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
	#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14


	#define PAGE_NOACCESS 0x01
	#define PAGE_READONLY 0x02
	#define PAGE_READWRITE 0x04
	#define PAGE_WRITECOPY 0x08
	#define PAGE_EXECUTE 0x10
	#define PAGE_EXECUTE_READ 0x20
	#define PAGE_EXECUTE_READWRITE 0x40
	#define PAGE_EXECUTE_WRITECOPY 0x80
	#define PAGE_GUARD 0x100
	#define PAGE_NOCACHE 0x200
	#define PAGE_WRITECOMBINE 0x400
	#define MEM_COMMIT 0x1000
	#define MEM_RESERVE 0x2000
	#define MEM_DECOMMIT 0x4000
	#define MEM_RELEASE 0x8000
	#define MEM_FREE 0x10000
	#define MEM_PRIVATE 0x20000
	#define MEM_MAPPED 0x40000
	#define MEM_RESET 0x80000
	#define MEM_TOP_DOWN 0x100000
	#define MEM_WRITE_WATCH 0x200000
	#define MEM_PHYSICAL 0x400000
	#define MEM_ROTATE 0x800000
	#define MEM_LARGE_PAGES 0x20000000
	#define MEM_4MB_PAGES 0x80000000
	#define SEC_FILE 0x800000
	#define SEC_IMAGE 0x1000000
	#define SEC_PROTECTED_IMAGE 0x2000000
	#define SEC_RESERVE 0x4000000
	#define SEC_COMMIT 0x8000000
	#define SEC_NOCACHE 0x10000000
	#define SEC_WRITECOMBINE 0x40000000
	#define SEC_LARGE_PAGES 0x80000000

	  typedef unsigned __LONG32 ULONG;
	  typedef CHAR *PCHAR,*LPCH,*PCH;
		#ifndef __C89_NAMELESS
		#define __C89_NAMELESS
		#endif
		
		  typedef struct _IMAGE_IMPORT_DESCRIPTOR {

		  __C89_NAMELESS union {
			DWORD Characteristics;
			DWORD OriginalFirstThunk;
		  } ;

		  DWORD TimeDateStamp;

		  DWORD ForwarderChain;
		  DWORD Name;
		  DWORD FirstThunk;
		} IMAGE_IMPORT_DESCRIPTOR;
		
		typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
		typedef struct _IMAGE_IMPORT_BY_NAME {
		  WORD Hint;
		  BYTE Name[1];
		} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

	#define IMAGE_REL_BASED_ABSOLUTE 0
	#define IMAGE_REL_BASED_HIGH 1
	#define IMAGE_REL_BASED_LOW 2
	#define IMAGE_REL_BASED_HIGHLOW 3
	#define IMAGE_REL_BASED_HIGHADJ 4
	#define IMAGE_REL_BASED_MIPS_JMPADDR 5
	#define IMAGE_REL_BASED_ARM_MOV32 5
	#define IMAGE_REL_BASED_THUMB_MOV32 7
	#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
	#define IMAGE_REL_BASED_IA64_IMM64 9
	#define IMAGE_REL_BASED_DIR64 10

	#ifndef _TCHAR_DEFINED
	#define _TCHAR_DEFINED
	  typedef char TCHAR, *PTCHAR;
	  typedef unsigned char TBYTE, *PTBYTE;
	#endif
	#ifndef __WCHAR_DEFINED
	#define __WCHAR_DEFINED
	  typedef wchar_t WCHAR;
	#endif
	  typedef WCHAR *NWPSTR,*LPWSTR,*PWSTR;
	  typedef LPWSTR PTSTR,LPTSTR;
	  typedef CONST WCHAR *LPCWSTR,*PCWSTR;
	#ifdef _WIN64
	  typedef INT_PTR (WINAPI *FARPROC) ();
	  typedef INT_PTR (WINAPI *NEARPROC) ();
	  typedef INT_PTR (WINAPI *PROC) ();
	#else
	  typedef int (WINAPI *FARPROC) ();
	  typedef int (WINAPI *NEARPROC) ();
	  typedef int (WINAPI *PROC) ();
	#endif
	  typedef  char* LPCTSTR;

	#define IMAGE_SCN_CNT_CODE 0x00000020
	#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
	#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
	#define IMAGE_SCN_LNK_OTHER 0x00000100
	#define IMAGE_SCN_LNK_INFO 0x00000200
	#define IMAGE_SCN_LNK_REMOVE 0x00000800
	#define IMAGE_SCN_LNK_COMDAT 0x00001000
	#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
	#define IMAGE_SCN_GPREL 0x00008000
	#define IMAGE_SCN_MEM_FARDATA 0x00008000
	#define IMAGE_SCN_MEM_PURGEABLE 0x00020000
	#define IMAGE_SCN_MEM_16BIT 0x00020000
	#define IMAGE_SCN_MEM_LOCKED 0x00040000
	#define IMAGE_SCN_MEM_PRELOAD 0x00080000

	#define IMAGE_SCN_ALIGN_1BYTES 0x00100000
	#define IMAGE_SCN_ALIGN_2BYTES 0x00200000
	#define IMAGE_SCN_ALIGN_4BYTES 0x00300000
	#define IMAGE_SCN_ALIGN_8BYTES 0x00400000
	#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
	#define IMAGE_SCN_ALIGN_32BYTES 0x00600000
	#define IMAGE_SCN_ALIGN_64BYTES 0x00700000
	#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
	#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
	#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
	#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
	#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
	#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
	#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000

	#define IMAGE_SCN_ALIGN_MASK 0x00F00000

	#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
	#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
	#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
	#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
	#define IMAGE_SCN_MEM_SHARED 0x10000000
	#define IMAGE_SCN_MEM_EXECUTE 0x20000000
	#define IMAGE_SCN_MEM_READ 0x40000000
	#define IMAGE_SCN_MEM_WRITE 0x80000000

	#define IMAGE_SCN_SCALE_INDEX 0x00000001

	   typedef struct _IMAGE_TLS_DIRECTORY32 {
		  DWORD StartAddressOfRawData;
		  DWORD EndAddressOfRawData;
		  DWORD AddressOfIndex;
		  DWORD AddressOfCallBacks;
		  DWORD SizeOfZeroFill;
		  DWORD Characteristics;
		} IMAGE_TLS_DIRECTORY32;
		typedef IMAGE_TLS_DIRECTORY32 *PIMAGE_TLS_DIRECTORY32;

		typedef struct _IMAGE_TLS_DIRECTORY64
		{
		ULONGLONG StartAddressOfRawData;
		ULONGLONG EndAddressOfRawData;
		ULONGLONG AddressOfIndex;
		ULONGLONG AddressOfCallBacks;
		DWORD SizeOfZeroFill;
		DWORD Characteristics;
		}
		IMAGE_TLS_DIRECTORY64;
		typedef IMAGE_TLS_DIRECTORY64 *PIMAGE_TLS_DIRECTORY64;

		typedef struct _IMAGE_THUNK_DATA32 {
		  union {
		DWORD ForwarderString;
		DWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
		  } u1;
		} IMAGE_THUNK_DATA32;
		typedef IMAGE_THUNK_DATA32 *PIMAGE_THUNK_DATA32;


	typedef struct _IMAGE_THUNK_DATA64
	{
	union
	{
	ULONGLONG ForwarderString;
	ULONGLONG Function;
	ULONGLONG Ordinal;
	ULONGLONG AddressOfData;
	}
	u1;
	}
	IMAGE_THUNK_DATA64;
	typedef IMAGE_THUNK_DATA64 *PIMAGE_THUNK_DATA64;
	

	#ifdef _WIN64
	#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG64
	#define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL64(Ordinal)
		typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
		typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;
	#define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL64(Ordinal)
		typedef IMAGE_TLS_DIRECTORY64 IMAGE_TLS_DIRECTORY;
		typedef PIMAGE_TLS_DIRECTORY64 PIMAGE_TLS_DIRECTORY;
	#else  /* _WIN64 */
	#define IMAGE_ORDINAL_FLAG IMAGE_ORDINAL_FLAG32
	#define IMAGE_ORDINAL(Ordinal) IMAGE_ORDINAL32(Ordinal)
		typedef IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA;
		typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
	#define IMAGE_SNAP_BY_ORDINAL(Ordinal) IMAGE_SNAP_BY_ORDINAL32(Ordinal)
		typedef IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;
		typedef PIMAGE_TLS_DIRECTORY32 PIMAGE_TLS_DIRECTORY;
	#endif /* _WIN64 */
		typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID DllHandle,DWORD Reason,PVOID Reserved);


		#define DLL_PROCESS_ATTACH 1
	#define DLL_THREAD_ATTACH 2
	#define DLL_THREAD_DETACH 3
	#define DLL_PROCESS_DETACH 0
	#define DLL_PROCESS_VERIFIER 4


	#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ull
	#define IMAGE_ORDINAL_FLAG32 0x80000000
	#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffffull)
	#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
	#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64)!=0)
	#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32)!=0)
	  typedef HINSTANCE HMODULE;

		typedef ULONG_PTR DWORD_PTR,*PDWORD_PTR;
	  #define IMAGE_DOS_SIGNATURE 0x5A4D
	#define IMAGE_OS2_SIGNATURE 0x454E
	#define IMAGE_OS2_SIGNATURE_LE 0x454C
	#define IMAGE_VXD_SIGNATURE 0x454C
	#define IMAGE_NT_SIGNATURE 0x00004550
	typedef struct _SYSTEM_INFO {
		__C89_NAMELESS union {
		  DWORD dwOemId;
		  __C89_NAMELESS struct {
		WORD wProcessorArchitecture;
		WORD wReserved;
		  } ;
		} ;
		DWORD dwPageSize;
		LPVOID lpMinimumApplicationAddress;
		LPVOID lpMaximumApplicationAddress;
		DWORD_PTR dwActiveProcessorMask;
		DWORD dwNumberOfProcessors;
		DWORD dwProcessorType;
		DWORD dwAllocationGranularity;
		WORD wProcessorLevel;
		WORD wProcessorRevision;
	  } SYSTEM_INFO, *LPSYSTEM_INFO;



		#define IMAGE_SIZEOF_FILE_HEADER 20
		#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
		#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
		#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
		#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
		#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
		#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
		#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
		#define IMAGE_FILE_32BIT_MACHINE 0x0100
		#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
		#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
		#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
		#define IMAGE_FILE_SYSTEM 0x1000
		#define IMAGE_FILE_DLL 0x2000
		#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
		#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000
		#define IMAGE_FILE_MACHINE_UNKNOWN 0
		#define IMAGE_FILE_MACHINE_I386 0x014c
		#define IMAGE_FILE_MACHINE_R3000 0x0162
		#define IMAGE_FILE_MACHINE_R4000 0x0166
		#define IMAGE_FILE_MACHINE_R10000 0x0168
		#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
		#define IMAGE_FILE_MACHINE_ALPHA 0x0184
		#define IMAGE_FILE_MACHINE_SH3 0x01a2
		#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
		#define IMAGE_FILE_MACHINE_SH3E 0x01a4
		#define IMAGE_FILE_MACHINE_SH4 0x01a6
		#define IMAGE_FILE_MACHINE_SH5 0x01a8
		#define IMAGE_FILE_MACHINE_ARM 0x01c0
		#define IMAGE_FILE_MACHINE_ARMV7 0x01c4
		#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
		#define IMAGE_FILE_MACHINE_THUMB 0x01c2
		#define IMAGE_FILE_MACHINE_AM33 0x01d3
		#define IMAGE_FILE_MACHINE_POWERPC 0x01F0
		#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
		#define IMAGE_FILE_MACHINE_IA64 0x0200
		#define IMAGE_FILE_MACHINE_MIPS16 0x0266
		#define IMAGE_FILE_MACHINE_ALPHA64 0x0284
		#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366
		#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
		#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
		#define IMAGE_FILE_MACHINE_TRICORE 0x0520
		#define IMAGE_FILE_MACHINE_CEF 0x0CEF
		#define IMAGE_FILE_MACHINE_EBC 0x0EBC
		#define IMAGE_FILE_MACHINE_AMD64 0x8664
		#define IMAGE_FILE_MACHINE_M32R 0x9041
		#define IMAGE_FILE_MACHINE_CEE 0xc0ee

		#define HEAP_ZERO_MEMORY 0x00000008
		#define IMAGE_FILE_DLL 0x2000


	 typedef struct _IMAGE_EXPORT_DIRECTORY {
		  DWORD Characteristics;
		  DWORD TimeDateStamp;
		  WORD MajorVersion;
		  WORD MinorVersion;
		  DWORD Name;
		  DWORD Base;
		  DWORD NumberOfFunctions;
		  DWORD NumberOfNames;
		  DWORD AddressOfFunctions;
		  DWORD AddressOfNames;
		  DWORD AddressOfNameOrdinals;
		} IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

		#define MAKEWORD(a,b) ((WORD) (((BYTE) (((DWORD_PTR) (a)) & 0xff)) | ((WORD) ((BYTE) (((DWORD_PTR) (b)) & 0xff))) << 8))
	#define MAKELONG(a, b) ((LONG) (((WORD) (((DWORD_PTR) (a)) & 0xffff)) | ((DWORD) ((WORD) (((DWORD_PTR) (b)) & 0xffff))) << 16))
	#define LOWORD(l) ((WORD) (((DWORD_PTR) (l)) & 0xffff))
	#define HIWORD(l) ((WORD) ((((DWORD_PTR) (l)) >> 16) & 0xffff))
	#define LOBYTE(w) ((BYTE) (((DWORD_PTR) (w)) & 0xff))
	#define HIBYTE(w) ((BYTE) ((((DWORD_PTR) (w)) >> 8) & 0xff))

	#define IMAGE_RESOURCE_NAME_IS_STRING 0x80000000
	#define IMAGE_RESOURCE_DATA_IS_DIRECTORY 0x80000000

		typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
		  __C89_NAMELESS union {
		__C89_NAMELESS struct {
		  DWORD NameOffset:31;
		  DWORD NameIsString:1;
		} ;
		DWORD Name;
		WORD Id;
		  } ;
		  __C89_NAMELESS union {
		DWORD OffsetToData;
		__C89_NAMELESS struct {
		  DWORD OffsetToDirectory:31;
		  DWORD DataIsDirectory:1;
		} DUMMYSTRUCTNAME2;
		  } DUMMYUNIONNAME2;
		} IMAGE_RESOURCE_DIRECTORY_ENTRY,*PIMAGE_RESOURCE_DIRECTORY_ENTRY;


		#define LANG_NEUTRAL                              0x00
	#define LANG_INVARIANT                            0x7f
	#define MAKELANGID(p,s) ((((WORD)(s)) << 10) | (WORD)(p))
	#define PRIMARYLANGID(lgid) ((WORD)(lgid) & 0x3ff)
	#define SUBLANGID(lgid) ((WORD)(lgid) >> 10)


	#define SUBLANG_NEUTRAL                           0x00
	#define SUBLANG_DEFAULT                           0x01
	#define SUBLANG_SYS_DEFAULT                       0x02
	#define SUBLANG_CUSTOM_DEFAULT                    0x03
	#define SUBLANG_CUSTOM_UNSPECIFIED                0x04
	#define SUBLANG_UI_CUSTOM_DEFAULT                 0x05

		typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
		  WORD Length;
		  WCHAR NameString[1];
		} IMAGE_RESOURCE_DIR_STRING_U,*PIMAGE_RESOURCE_DIR_STRING_U;

		   typedef struct _IMAGE_RESOURCE_DIRECTORY {
		  DWORD Characteristics;
		  DWORD TimeDateStamp;
		  WORD MajorVersion;
		  WORD MinorVersion;
		  WORD NumberOfNamedEntries;
		  WORD NumberOfIdEntries;
		} IMAGE_RESOURCE_DIRECTORY,*PIMAGE_RESOURCE_DIRECTORY;


	# define __MINGW_NAME_AW(fn) fn##A
		#define IS_INTRESOURCE(_r) ((((ULONG_PTR)(_r)) >> 16)==0)
	#define MAKEINTRESOURCEA(i) ((LPSTR)((ULONG_PTR)((WORD)(i))))
	#define MAKEINTRESOURCEW(i) ((LPWSTR)((ULONG_PTR)((WORD)(i))))
	#define MAKEINTRESOURCE __MINGW_NAME_AW(MAKEINTRESOURCE)



	#define __TEXT(quote) quote
	#define TEXT(quote) __TEXT(quote)
	#define NUL '\0'

	#define IMAGE_RESOURCE_NAME_IS_STRING 0x80000000
	#define IMAGE_RESOURCE_DATA_IS_DIRECTORY 0x80000000



		typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
		  WORD Length;
		  CHAR NameString[1];
		} IMAGE_RESOURCE_DIRECTORY_STRING,*PIMAGE_RESOURCE_DIRECTORY_STRING;


		typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
		  DWORD OffsetToData;
		  DWORD Size;
		  DWORD CodePage;
		  DWORD Reserved;
		} IMAGE_RESOURCE_DATA_ENTRY,*PIMAGE_RESOURCE_DATA_ENTRY;



	  typedef BYTE *LPBYTE;
		typedef struct _STARTUPINFO {
	  DWORD  cb;
	  LPTSTR lpReserved;
	  LPTSTR lpDesktop;
	  LPTSTR lpTitle;
	  DWORD  dwX;
	  DWORD  dwY;
	  DWORD  dwXSize;
	  DWORD  dwYSize;
	  DWORD  dwXCountChars;
	  DWORD  dwYCountChars;
	  DWORD  dwFillAttribute;
	  DWORD  dwFlags;
	  WORD   wShowWindow;
	  WORD   cbReserved2;
	  LPBYTE lpReserved2;
	  HANDLE hStdInput;
	  HANDLE hStdOutput;
	  HANDLE hStdError;
	} STARTUPINFO, *LPSTARTUPINFO;

	typedef LONG (WINAPI *PTOP_LEVEL_EXCEPTION_FILTER) (void* ExceptionInfo);
	typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;



	typedef int WINBOOL;

		  typedef struct _SECURITY_ATTRIBUTES {
		DWORD nLength;
		LPVOID lpSecurityDescriptor;
		WINBOOL bInheritHandle;
	  } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;




	  typedef WORD ATOM;


			typedef struct _FILETIME {
			DWORD dwLowDateTime;
			DWORD dwHighDateTime;
		  } FILETIME,*PFILETIME,*LPFILETIME;


	/*
	//#ifndef CpcDos
				  typedef enum _GET_FILEEX_INFO_LEVELS {
					GetFileExInfoStandard,
					GetFileExMaxInfoLevel
				  } GET_FILEEX_INFO_LEVELS;
				

				#define WINAPI __stdcall
				#define WINBASEAPI
				  typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
					DWORD dwFileAttributes;
					FILETIME ftCreationTime;
					FILETIME ftLastAccessTime;
					FILETIME ftLastWriteTime;
					DWORD nFileSizeHigh;
					DWORD nFileSizeLow;
				  } WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;
				 extern "C" WINBASEAPI WINBOOL WINAPI GetFileAttributesExW (LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation);
	//#endif // CpcDos
	*/

  VOID WINAPI SetLastError (DWORD dwErrCode);

	  typedef unsigned long long  ULONGLONG;


	#ifndef _LIST_ENTRY_DEFINED
	#define _LIST_ENTRY_DEFINED

	  typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY *Flink;
		struct _LIST_ENTRY *Blink;
	  } LIST_ENTRY,*PLIST_ENTRY;

	  typedef struct _SINGLE_LIST_ENTRY {
		struct _SINGLE_LIST_ENTRY *Next;
	  } SINGLE_LIST_ENTRY,*PSINGLE_LIST_ENTRY;

	  typedef struct LIST_ENTRY32 {
		DWORD Flink;
		DWORD Blink;
	  } LIST_ENTRY32;
	  typedef LIST_ENTRY32 *PLIST_ENTRY32;

	  typedef struct LIST_ENTRY64 {
		ULONGLONG Flink;
		ULONGLONG Blink;
	  } LIST_ENTRY64;
	  typedef LIST_ENTRY64 *PLIST_ENTRY64;

	#endif /* _LIST_ENTRY_DEFINED */
		typedef struct _RTL_CRITICAL_SECTION_DEBUG {
		  WORD Type;
		  WORD CreatorBackTraceIndex;
		  struct _RTL_CRITICAL_SECTION *CriticalSection;
		  LIST_ENTRY ProcessLocksList;
		  DWORD EntryCount;
		  DWORD ContentionCount;
		  DWORD Flags;
		  WORD CreatorBackTraceIndexHigh;
		  WORD SpareWORD;
		} RTL_CRITICAL_SECTION_DEBUG,*PRTL_CRITICAL_SECTION_DEBUG,RTL_RESOURCE_DEBUG,*PRTL_RESOURCE_DEBUG;


	typedef struct _RTL_CRITICAL_SECTION {
		  PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
		  LONG LockCount;
		  LONG RecursionCount;
		  HANDLE OwningThread;
		  HANDLE LockSemaphore;
		  ULONG_PTR SpinCount;
		} RTL_CRITICAL_SECTION,*PRTL_CRITICAL_SECTION;
	  typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

	

	#define SHORT  short int

	  #define _In_
	#define _In_opt_
	#define _Out_
	#define _Inout_

	  typedef struct _COORD {
		SHORT X;
		SHORT Y;
	  } COORD,*PCOORD;

	  typedef struct _SMALL_RECT {
		SHORT Left;
		SHORT Top;
		SHORT Right;
		SHORT Bottom;
	  } SMALL_RECT,*PSMALL_RECT;

	#define DECLARE_HANDLE(name) typedef HANDLE name
	DECLARE_HANDLE (HWND);
	DECLARE_HANDLE (HHOOK);


	  typedef UINT_PTR WPARAM;
	  typedef LONG_PTR LPARAM;
	  typedef LONG_PTR LRESULT;


	DECLARE_HANDLE(HACCEL);
	DECLARE_HANDLE(HBITMAP);
	DECLARE_HANDLE(HBRUSH);
	DECLARE_HANDLE(HCOLORSPACE);
	DECLARE_HANDLE(HDC);
	DECLARE_HANDLE(HGLRC);
	DECLARE_HANDLE(HDESK);
	DECLARE_HANDLE(HENHMETAFILE);
	DECLARE_HANDLE(HFONT);
	DECLARE_HANDLE(HICON);
	DECLARE_HANDLE(HMENU);
	DECLARE_HANDLE(HPALETTE);
	DECLARE_HANDLE(HPEN);
	DECLARE_HANDLE(HMONITOR);
	DECLARE_HANDLE(HWINEVENTHOOK);


	  typedef struct tagRECT {
	  LONG left;
	  LONG top;
	  LONG right;
	  LONG bottom;
	} RECT,*PRECT,*NPRECT,*LPRECT;

	  typedef struct tagPOINT {
	  LONG x;
	  LONG y;
	} POINT,*PPOINT,*NPPOINT,*LPPOINT;

		typedef struct tagMSG {
		HWND hwnd;
		UINT message;
		WPARAM wParam;
		LPARAM lParam;
		DWORD time;
		POINT pt;
	  } MSG,*PMSG,*NPMSG,*LPMSG;
	#endif


	//////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////

	#define MAKEWORD(a,b) ((WORD) (((BYTE) (((DWORD_PTR) (a)) & 0xff)) | ((WORD) ((BYTE) (((DWORD_PTR) (b)) & 0xff))) << 8))
	#define MAKELONG(a, b) ((LONG) (((WORD) (((DWORD_PTR) (a)) & 0xffff)) | ((DWORD) ((WORD) (((DWORD_PTR) (b)) & 0xffff))) << 16))
	#define LOWORD(l) ((WORD) (((DWORD_PTR) (l)) & 0xffff))
	#define HIWORD(l) ((WORD) ((((DWORD_PTR) (l)) >> 16) & 0xffff))
	#define LOBYTE(w) ((BYTE) (((DWORD_PTR) (w)) & 0xff))
	#define HIBYTE(w) ((BYTE) ((((DWORD_PTR) (w)) >> 8) & 0xff))

	typedef HANDLE *SPHANDLE;
	typedef HANDLE *LPHANDLE;
	typedef HANDLE HGLOBAL;
	typedef HANDLE HLOCAL;
	typedef HANDLE GLOBALHANDLE;
	typedef HANDLE LOCALHANDLE;

	#ifndef _HRESULT_DEFINED
	#define _HRESULT_DEFINED
	  typedef LONG HRESULT;
	#endif

	typedef struct tagPIXELFORMATDESCRIPTOR {
	WORD nSize;
	WORD nVersion;
	DWORD dwFlags;
	BYTE iPixelType;
	BYTE cColorBits;
	BYTE cRedBits;
	BYTE cRedShift;
	BYTE cGreenBits;
	BYTE cGreenShift;
	BYTE cBlueBits;
	BYTE cBlueShift;
	BYTE cAlphaBits;
	BYTE cAlphaShift;
	BYTE cAccumBits;
	BYTE cAccumRedBits;
	BYTE cAccumGreenBits;
	BYTE cAccumBlueBits;
	BYTE cAccumAlphaBits;
	BYTE cDepthBits;
	BYTE cStencilBits;
	BYTE cAuxBuffers;
	BYTE iLayerType;
	BYTE bReserved;
	DWORD dwLayerMask;
	DWORD dwVisibleMask;
	DWORD dwDamageMask;
	} PIXELFORMATDESCRIPTOR,*PPIXELFORMATDESCRIPTOR,*LPPIXELFORMATDESCRIPTOR;

	typedef struct tagBITMAPINFOHEADER {
	DWORD biSize;
	LONG biWidth;
	LONG biHeight;
	WORD biPlanes;
	WORD biBitCount;
	DWORD biCompression;
	DWORD biSizeImage;
	LONG biXPelsPerMeter;
	LONG biYPelsPerMeter;
	DWORD biClrUsed;
	DWORD biClrImportant;
	} BITMAPINFOHEADER,*LPBITMAPINFOHEADER,*PBITMAPINFOHEADER;

	typedef struct tagBITMAPCOREHEADER {
	DWORD bcSize;
	WORD bcWidth;
	WORD bcHeight;
	WORD bcPlanes;
	WORD bcBitCount;
	} BITMAPCOREHEADER,*LPBITMAPCOREHEADER,*PBITMAPCOREHEADER;
	typedef struct tagRGBQUAD {
	BYTE rgbBlue;
	BYTE rgbGreen;
	BYTE rgbRed;
	BYTE rgbReserved;
	} RGBQUAD;
	typedef struct tagBITMAPINFO {
	BITMAPINFOHEADER bmiHeader;
	RGBQUAD bmiColors[1];
	} BITMAPINFO,*LPBITMAPINFO,*PBITMAPINFO;
	typedef struct tagRGBTRIPLE {
	BYTE rgbtBlue;
	BYTE rgbtGreen;
	BYTE rgbtRed;
	} RGBTRIPLE;
	typedef struct tagBITMAPCOREINFO {
	BITMAPCOREHEADER bmciHeader;
	RGBTRIPLE bmciColors[1];
	} BITMAPCOREINFO,*LPBITMAPCOREINFO,*PBITMAPCOREINFO;

	typedef HICON HCURSOR;
	typedef DWORD COLORREF;
	typedef FARPROC TIMERPROC;
	typedef FARPROC GRAYSTRINGPROC;
	typedef FARPROC WNDENUMPROC;
	typedef FARPROC HOOKPROC;
	typedef FARPROC SENDASYNCPROC;

	typedef FARPROC EDITWORDBREAKPROCA;
	typedef FARPROC EDITWORDBREAKPROCW;

	typedef FARPROC PROPENUMPROCA;
	typedef FARPROC PROPENUMPROCW;

	typedef FARPROC PROPENUMPROCEXA;
	typedef FARPROC PROPENUMPROCEXW;

	typedef FARPROC DRAWSTATEPROC;


	#define RC_NONE
	#define RC_BITBLT 1
	#define RC_BANDING 2
	#define RC_SCALING 4
	#define RC_BITMAP64 8
	#define RC_GDI20_OUTPUT 0x0010
	#define RC_GDI20_STATE 0x0020
	#define RC_SAVEBITMAP 0x0040
	#define RC_DI_BITMAP 0x0080
	#define RC_PALETTE 0x0100
	#define RC_DIBTODEV 0x0200
	#define RC_BIGFONT 0x0400
	#define RC_STRETCHBLT 0x0800
	#define RC_FLOODFILL 0x1000
	#define RC_STRETCHDIB 0x2000
	#define RC_OP_DX_OUTPUT 0x4000
	#define RC_DEVBITS 0x8000

	#define SB_NONE 0x00000000
	#define SB_CONST_ALPHA 0x00000001
	#define SB_PIXEL_ALPHA 0x00000002
	#define SB_PREMULT_ALPHA 0x00000004

	#define SB_GRAD_RECT 0x00000010
	#define SB_GRAD_TRI 0x00000020

	#define CM_NONE 0x00000000
	#define CM_DEVICE_ICM 0x00000001
	#define CM_GAMMA_RAMP 0x00000002
	#define CM_CMYK_COLOR 0x00000004

	#define DIB_RGB_COLORS 0
	#define DIB_PAL_COLORS 1

	#define SYSPAL_ERROR 0
	#define SYSPAL_STATIC 1
	#define SYSPAL_NOSTATIC 2
	#define SYSPAL_NOSTATIC256 3

	#define CBM_INIT __MSABI_LONG(0x04)

	#define FLOODFILLBORDER 0
	#define FLOODFILLSURFACE 1

	#define CCHDEVICENAME 32

	#define CCHFORMNAME 32

	typedef struct _POINTL {
	  LONG x;
	  LONG y;
	} POINTL,*PPOINTL;


	typedef struct _devicemodeA {
	BYTE dmDeviceName[CCHDEVICENAME];
	WORD dmSpecVersion;
	WORD dmDriverVersion;
	WORD dmSize;
	WORD dmDriverExtra;
	DWORD dmFields;
	__C89_NAMELESS union {
	  __C89_NAMELESS struct {
	short dmOrientation;
	short dmPaperSize;
	short dmPaperLength;
	short dmPaperWidth;
	short dmScale;
	short dmCopies;
	short dmDefaultSource;
	short dmPrintQuality;
	  };
	  struct {
	POINTL dmPosition;
	DWORD dmDisplayOrientation;
	DWORD dmDisplayFixedOutput;
	  };
	};
	short dmColor;
	short dmDuplex;
	short dmYResolution;
	short dmTTOption;
	short dmCollate;
	BYTE dmFormName[CCHFORMNAME];
	WORD dmLogPixels;
	DWORD dmBitsPerPel;
	DWORD dmPelsWidth;
	DWORD dmPelsHeight;
	__C89_NAMELESS union {
	  DWORD dmDisplayFlags;
	  DWORD dmNup;
	};
	DWORD dmDisplayFrequency;
	DWORD dmICMMethod;
	DWORD dmICMIntent;
	DWORD dmMediaType;
	DWORD dmDitherType;
	DWORD dmReserved1;
	DWORD dmReserved2;
	DWORD dmPanningWidth;
	DWORD dmPanningHeight;
	} DEVMODEA,*PDEVMODEA,*NPDEVMODEA,*LPDEVMODEA;

	typedef struct _devicemodeW {
	WCHAR dmDeviceName[CCHDEVICENAME];
	WORD dmSpecVersion;
	WORD dmDriverVersion;
	WORD dmSize;
	WORD dmDriverExtra;
	DWORD dmFields;
	__C89_NAMELESS union {
	  __C89_NAMELESS struct {
	short dmOrientation;
	short dmPaperSize;
	short dmPaperLength;
	short dmPaperWidth;
	short dmScale;
	short dmCopies;
	short dmDefaultSource;
	short dmPrintQuality;
	  };
	  __C89_NAMELESS struct {
	POINTL dmPosition;
	DWORD dmDisplayOrientation;
	DWORD dmDisplayFixedOutput;
	  };
	};
	short dmColor;
	short dmDuplex;
	short dmYResolution;
	short dmTTOption;
	short dmCollate;
	WCHAR dmFormName[CCHFORMNAME];
	WORD dmLogPixels;
	DWORD dmBitsPerPel;
	DWORD dmPelsWidth;
	DWORD dmPelsHeight;
	__C89_NAMELESS union {
	  DWORD dmDisplayFlags;
	  DWORD dmNup;
	};
	DWORD dmDisplayFrequency;
	DWORD dmICMMethod;
	DWORD dmICMIntent;
	DWORD dmMediaType;
	DWORD dmDitherType;
	DWORD dmReserved1;
	DWORD dmReserved2;
	DWORD dmPanningWidth;
	DWORD dmPanningHeight;
	} DEVMODEW,*PDEVMODEW,*NPDEVMODEW,*LPDEVMODEW;

	  typedef struct tagCURSORINFO {
		DWORD cbSize;
		DWORD flags;
		HCURSOR hCursor;
		POINT ptScreenPos;
	  } CURSORINFO,*PCURSORINFO,*LPCURSORINFO;

	#define CURSOR_SHOWING 0x00000001

	typedef const RECT *LPCRECT;
	typedef struct tagTOGGLEKEYS {
		UINT cbSize;
		DWORD dwFlags;
	  } TOGGLEKEYS,*LPTOGGLEKEYS;

	  typedef struct tagMONITORINFO {
		DWORD cbSize;
		RECT rcMonitor;
		RECT rcWork;
		DWORD dwFlags;
	  } MONITORINFO,*LPMONITORINFO;
	  
	  #ifndef FLS_OUT_OF_INDEXES
	#define FLS_OUT_OF_INDEXES ((DWORD)0xffffffff)
	#endif

	#define TLS_OUT_OF_INDEXES ((DWORD)0xffffffff)

	  typedef struct _PROCESS_INFORMATION {
		HANDLE hProcess;
		HANDLE hThread;
		DWORD dwProcessId;
		DWORD dwThreadId;
	  } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

	  typedef struct _STARTUPINFOA {
		DWORD cb;
		LPSTR lpReserved;
		LPSTR lpDesktop;
		LPSTR lpTitle;
		DWORD dwX;
		DWORD dwY;
		DWORD dwXSize;
		DWORD dwYSize;
		DWORD dwXCountChars;
		DWORD dwYCountChars;
		DWORD dwFillAttribute;
		DWORD dwFlags;
		WORD wShowWindow;
		WORD cbReserved2;
		LPBYTE lpReserved2;
		HANDLE hStdInput;
		HANDLE hStdOutput;
		HANDLE hStdError;
	  } STARTUPINFOA, *LPSTARTUPINFOA;

	  typedef struct _STARTUPINFOW {
		DWORD cb;
		LPWSTR lpReserved;
		LPWSTR lpDesktop;
		LPWSTR lpTitle;
		DWORD dwX;
		DWORD dwY;
		DWORD dwXSize;
		DWORD dwYSize;
		DWORD dwXCountChars;
		DWORD dwYCountChars;
		DWORD dwFillAttribute;
		DWORD dwFlags;
		WORD wShowWindow;
		WORD cbReserved2;
		LPBYTE lpReserved2;
		HANDLE hStdInput;
		HANDLE hStdOutput;
		HANDLE hStdError;
	  } STARTUPINFOW, *LPSTARTUPINFOW;

	#ifndef VOID
	#define VOID void
	  typedef char CHAR;
	  typedef short SHORT;
	  typedef __LONG32 LONG;
	#if !defined (__WIDL__)
	  typedef int INT;
	#endif
	#endif

	#ifndef __WCHAR_DEFINED
	#define __WCHAR_DEFINED
	  typedef wchar_t WCHAR;
	#endif
	  typedef WCHAR *PWCHAR,*LPWCH,*PWCH;
	  typedef CONST WCHAR *LPCWCH,*PCWCH;
	  typedef WCHAR *NWPSTR,*LPWSTR,*PWSTR;
	  typedef PWSTR *PZPWSTR;
	  typedef CONST PWSTR *PCZPWSTR;
	  typedef WCHAR UNALIGNED *LPUWSTR,*PUWSTR;
	  typedef CONST WCHAR *LPCWSTR,*PCWSTR;
	  typedef PCWSTR *PZPCWSTR;
	  typedef CONST WCHAR UNALIGNED *LPCUWSTR,*PCUWSTR;
	  typedef WCHAR *PZZWSTR;
	  typedef CONST WCHAR *PCZZWSTR;
	  typedef WCHAR UNALIGNED *PUZZWSTR;
	  typedef CONST WCHAR UNALIGNED *PCUZZWSTR;
	  typedef WCHAR *PNZWCH;
	  typedef CONST WCHAR *PCNZWCH;
	  typedef WCHAR UNALIGNED *PUNZWCH;
	  typedef CONST WCHAR UNALIGNED *PCUNZWCH;


	  typedef CHAR *PCHAR,*LPCH,*PCH;
	  typedef CONST CHAR *LPCCH,*PCCH;
	  typedef CHAR *NPSTR,*LPSTR,*PSTR;
	  typedef PSTR *PZPSTR;
	  typedef CONST PSTR *PCZPSTR;
	  typedef CONST CHAR *LPCSTR,*PCSTR;
	  typedef PCSTR *PZPCSTR;
	  typedef CHAR *PZZSTR;
	  typedef CONST CHAR *PCZZSTR;
	  typedef CHAR *PNZCH;
	  typedef CONST CHAR *PCNZCH;
	  
	#ifndef _DEF_WINBOOL_
	#define _DEF_WINBOOL_
	typedef int WINBOOL;
	#pragma push_macro("BOOL")
	#undef BOOL
	#if !defined(__OBJC__) && !defined(__OBJC_BOOL) && !defined(__objc_INCLUDE_GNU) && !defined(_NO_BOOL_TYPEDEF)
	  typedef int BOOL;
	#endif
	#define BOOL WINBOOL
	typedef BOOL *PBOOL;
	typedef BOOL *LPBOOL;
	#pragma pop_macro("BOOL")
	#endif /* _DEF_WINBOOL_ */
	
	#define INVALID_HANDLE_VALUE ((HANDLE) (LONG_PTR)-1)
	

	typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    __C89_NAMELESS union {
      struct {
	DWORD Offset;
	DWORD OffsetHigh;
      } DUMMYSTRUCTNAME;
      PVOID Pointer;
    } DUMMYUNIONNAME;
    HANDLE hEvent;
  } OVERLAPPED, *LPOVERLAPPED;

  typedef struct _OVERLAPPED_ENTRY {
    ULONG_PTR lpCompletionKey;
    LPOVERLAPPED lpOverlapped;
    ULONG_PTR Internal;
    DWORD dwNumberOfBytesTransferred;
  } OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;


	typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;
	typedef PRTL_CRITICAL_SECTION PCRITICAL_SECTION;
	typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;
	typedef RTL_CRITICAL_SECTION_DEBUG CRITICAL_SECTION_DEBUG;
	typedef PRTL_CRITICAL_SECTION_DEBUG PCRITICAL_SECTION_DEBUG;
	typedef PRTL_CRITICAL_SECTION_DEBUG LPCRITICAL_SECTION_DEBUG;

	typedef VOID (WINAPI *LPOVERLAPPED_COMPLETION_ROUTINE) (DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped);

	#define LOCKFILE_FAIL_IMMEDIATELY 0x1
	#define LOCKFILE_EXCLUSIVE_LOCK 0x2
	
	
	typedef DWORD (WINAPI *PTHREAD_START_ROUTINE) (LPVOID lpThreadParameter);
	typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

   typedef struct _MESSAGE_RESOURCE_ENTRY {
      WORD Length;
      WORD Flags;
      BYTE Text[1];
    } MESSAGE_RESOURCE_ENTRY,*PMESSAGE_RESOURCE_ENTRY;

#define SEF_DACL_AUTO_INHERIT 0x01
#define SEF_SACL_AUTO_INHERIT 0x02
#define SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT 0x04
#define SEF_AVOID_PRIVILEGE_CHECK 0x08
#define SEF_AVOID_OWNER_CHECK 0x10
#define SEF_DEFAULT_OWNER_FROM_PARENT 0x20
#define SEF_DEFAULT_GROUP_FROM_PARENT 0x40
#define SEF_MACL_NO_WRITE_UP 0x100
#define SEF_MACL_NO_READ_UP 0x200
#define SEF_MACL_NO_EXECUTE_UP 0x400
#define SEF_AVOID_OWNER_RESTRICTION 0x1000

#define SEF_MACL_VALID_FLAGS (SEF_MACL_NO_WRITE_UP | SEF_MACL_NO_READ_UP | SEF_MACL_NO_EXECUTE_UP)

#define MESSAGE_RESOURCE_UNICODE 0x0001

    typedef struct _MESSAGE_RESOURCE_BLOCK {
      DWORD LowId;
      DWORD HighId;
      DWORD OffsetToEntries;
    } MESSAGE_RESOURCE_BLOCK,*PMESSAGE_RESOURCE_BLOCK;

    typedef struct _MESSAGE_RESOURCE_DATA {
      DWORD NumberOfBlocks;
      MESSAGE_RESOURCE_BLOCK Blocks[1];
    } MESSAGE_RESOURCE_DATA,*PMESSAGE_RESOURCE_DATA;

   
	 typedef struct _CONSOLE_SCREEN_BUFFER_INFO {
    COORD dwSize;
    COORD dwCursorPosition;
    WORD wAttributes;
    SMALL_RECT srWindow;
    COORD dwMaximumWindowSize;
  } CONSOLE_SCREEN_BUFFER_INFO,*PCONSOLE_SCREEN_BUFFER_INFO;


   typedef LRESULT (CALLBACK *WNDPROC)(HWND,UINT,WPARAM,LPARAM);
  
  
	typedef struct tagWNDCLASSEXA {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
    HICON hIconSm;
  } WNDCLASSEXA,*PWNDCLASSEXA,*NPWNDCLASSEXA,*LPWNDCLASSEXA;

  typedef struct tagWNDCLASSEXW {
    UINT cbSize;
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
    HICON hIconSm;
  } WNDCLASSEXW,*PWNDCLASSEXW,*NPWNDCLASSEXW,*LPWNDCLASSEXW;

  __MINGW_TYPEDEF_AW(WNDCLASSEX) __MINGW_TYPEDEF_AW(PWNDCLASSEX) __MINGW_TYPEDEF_AW(NPWNDCLASSEX) __MINGW_TYPEDEF_AW(LPWNDCLASSEX) typedef struct tagWNDCLASSA {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCSTR lpszMenuName;
    LPCSTR lpszClassName;
  } WNDCLASSA,*PWNDCLASSA,*NPWNDCLASSA,*LPWNDCLASSA;

  typedef struct tagWNDCLASSW {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
  } WNDCLASSW,*PWNDCLASSW,*NPWNDCLASSW,*LPWNDCLASSW;
  
  
  
#define WM_CTLCOLORMSGBOX 0x0132
#define WM_CTLCOLOREDIT 0x0133
#define WM_CTLCOLORLISTBOX 0x0134
#define WM_CTLCOLORBTN 0x0135
#define WM_CTLCOLORDLG 0x0136
#define WM_CTLCOLORSCROLLBAR 0x0137
#define WM_CTLCOLORSTATIC 0x0138
#define MN_GETHMENU 0x01E1

#define WM_MOUSEFIRST 0x0200
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_LBUTTONDBLCLK 0x0203
#define WM_RBUTTONDOWN 0x0204
#define WM_RBUTTONUP 0x0205
#define WM_RBUTTONDBLCLK 0x0206
#define WM_MBUTTONDOWN 0x0207
#define WM_MBUTTONUP 0x0208
#define WM_MBUTTONDBLCLK 0x0209
#define WM_MOUSEWHEEL 0x020A
#define WM_XBUTTONDOWN 0x020B
#define WM_XBUTTONUP 0x020C
#define WM_XBUTTONDBLCLK 0x020D
#define WM_MOUSEHWHEEL 0x020e
#define WM_MOUSELAST 0x020d


  typedef struct tagTRACKMOUSEEVENT {
    DWORD cbSize;
    DWORD dwFlags;
    HWND hwndTrack;
    DWORD dwHoverTime;
  } TRACKMOUSEEVENT,*LPTRACKMOUSEEVENT;


	#if defined (_WIN64)
	typedef struct DECLSPEC_ALIGN (16) _SLIST_ENTRY
	{
	struct _SLIST_ENTRY *Next;
	}
	SLIST_ENTRY,*PSLIST_ENTRY;
	typedef union DECLSPEC_ALIGN (16) _SLIST_HEADER
	{
	__C89_NAMELESS struct
	{
	ULONGLONG Alignment;
	ULONGLONG Region;
	}
	DUMMYSTRUCTNAME;
	struct
	{
	ULONGLONG Depth:16;
	ULONGLONG Sequence:9;
	ULONGLONG NextEntry:39;
	ULONGLONG HeaderType:1;
	ULONGLONG Init:1;
	ULONGLONG Reserved:59;
	ULONGLONG Region:3;
	}
	Header8;
	struct
	{
	ULONGLONG Depth:16;
	ULONGLONG Sequence:48;
	ULONGLONG HeaderType:1;
	ULONGLONG Reserved:3;
	ULONGLONG NextEntry:60;
	}
	HeaderX64;
	}
	SLIST_HEADER,*PSLIST_HEADER;
	#else
	typedef struct _SINGLE_LIST_ENTRY SLIST_ENTRY,*PSLIST_ENTRY;
	typedef union _SLIST_HEADER
	{
	ULONGLONG Alignment;
	__C89_NAMELESS struct
	{
	SLIST_ENTRY Next;
	WORD Depth;
	WORD Sequence;
	}
	DUMMYSTRUCTNAME;
	}
	SLIST_HEADER,*PSLIST_HEADER;
	#endif

/////// Version /////
typedef struct _OSVERSIONINFOA
{
DWORD dwOSVersionInfoSize;
DWORD dwMajorVersion;
DWORD dwMinorVersion;
DWORD dwBuildNumber;
DWORD dwPlatformId;
CHAR szCSDVersion[128];
}
OSVERSIONINFOA,*POSVERSIONINFOA,*LPOSVERSIONINFOA;
typedef struct _OSVERSIONINFOW
{
DWORD dwOSVersionInfoSize;
DWORD dwMajorVersion;
DWORD dwMinorVersion;
DWORD dwBuildNumber;
DWORD dwPlatformId;
WCHAR szCSDVersion[128];
}
OSVERSIONINFOW,*POSVERSIONINFOW,*LPOSVERSIONINFOW,RTL_OSVERSIONINFOW,*PRTL_OSVERSIONINFOW;
__MINGW_TYPEDEF_AW(OSVERSIONINFO) __MINGW_TYPEDEF_AW(POSVERSIONINFO) __MINGW_TYPEDEF_AW(LPOSVERSIONINFO) typedef struct _OSVERSIONINFOEXA
{
DWORD dwOSVersionInfoSize;
DWORD dwMajorVersion;
DWORD dwMinorVersion;
DWORD dwBuildNumber;
DWORD dwPlatformId;
CHAR szCSDVersion[128];
WORD wServicePackMajor;
WORD wServicePackMinor;
WORD wSuiteMask;
BYTE wProductType;
BYTE wReserved;
}
OSVERSIONINFOEXA,*POSVERSIONINFOEXA,*LPOSVERSIONINFOEXA;
typedef struct _OSVERSIONINFOEXW
{
DWORD dwOSVersionInfoSize;
DWORD dwMajorVersion;
DWORD dwMinorVersion;
DWORD dwBuildNumber;
DWORD dwPlatformId;
WCHAR szCSDVersion[128];
WORD wServicePackMajor;
WORD wServicePackMinor;
WORD wSuiteMask;
BYTE wProductType;
BYTE wReserved;
}
OSVERSIONINFOEXW,*POSVERSIONINFOEXW,*LPOSVERSIONINFOEXW,RTL_OSVERSIONINFOEXW,*PRTL_OSVERSIONINFOEXW;
__MINGW_TYPEDEF_AW(OSVERSIONINFOEX) __MINGW_TYPEDEF_AW(POSVERSIONINFOEX) __MINGW_TYPEDEF_AW(LPOSVERSIONINFOEX)
#define VER_EQUAL 1
#define VER_GREATER 2
#define VER_GREATER_EQUAL 3
#define VER_LESS 4
#define VER_LESS_EQUAL 5
#define VER_AND 6
#define VER_OR 7
#define VER_CONDITION_MASK 7
#define VER_NUM_BITS_PER_CONDITION_MASK 3
#define VER_MINORVERSION 0x0000001
#define VER_MAJORVERSION 0x0000002
#define VER_BUILDNUMBER 0x0000004
#define VER_PLATFORMID 0x0000008
#define VER_SERVICEPACKMINOR 0x0000010
#define VER_SERVICEPACKMAJOR 0x0000020
#define VER_SUITENAME 0x0000040
#define VER_PRODUCT_TYPE 0x0000080
#define VER_NT_WORKSTATION 0x0000001
#define VER_NT_DOMAIN_CONTROLLER 0x0000002
#define VER_NT_SERVER 0x0000003
#define VER_PLATFORM_WIN32s 0
#define VER_PLATFORM_WIN32_WINDOWS 1
#define VER_PLATFORM_WIN32_NT 2
///////////////////////////////////////////////
typedef IMAGE_BASE_RELOCATION UNALIGNED *PIMAGE_BASE_RELOCATION;
#define IMAGE_SIZEOF_BASE_RELOCATION 8
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_HIGHADJ 4
#define IMAGE_REL_BASED_MIPS_JMPADDR 5
#define IMAGE_REL_BASED_ARM_MOV32 5
#define IMAGE_REL_BASED_THUMB_MOV32 7
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_IA64_IMM64 9
#define IMAGE_REL_BASED_DIR64 10
#define IMAGE_ARCHIVE_START_SIZE 8
#define IMAGE_ARCHIVE_START "!<arch>\n"
#define IMAGE_ARCHIVE_END "`\n"
#define IMAGE_ARCHIVE_PAD "\n"
#define IMAGE_ARCHIVE_LINKER_MEMBER "/               "
#define IMAGE_ARCHIVE_LONGNAMES_MEMBER "//              "

#ifndef _PALETTEENTRY_DEFINED
#define _PALETTEENTRY_DEFINED
typedef struct tagPALETTEENTRY
{
BYTE peRed;
BYTE peGreen;
BYTE peBlue;
BYTE peFlags;
}
PALETTEENTRY,*PPALETTEENTRY,*LPPALETTEENTRY;
#endif
#ifndef _LOGPALETTE_DEFINED
#define _LOGPALETTE_DEFINED
typedef struct tagLOGPALETTE
{
WORD palVersion;
WORD palNumEntries;
PALETTEENTRY palPalEntry[1];
}
LOGPALETTE,*PLOGPALETTE,*NPLOGPALETTE,*LPLOGPALETTE;
#endif
#ifndef LF_FACESIZE
#define LF_FACESIZE 32
#endif




typedef struct _KEY_EVENT_RECORD
{
WINBOOL bKeyDown;
WORD wRepeatCount;
WORD wVirtualKeyCode;
WORD wVirtualScanCode;
union
{
WCHAR UnicodeChar;
CHAR AsciiChar;
}
uChar;
DWORD dwControlKeyState;
}
KEY_EVENT_RECORD,*PKEY_EVENT_RECORD;

typedef struct _MOUSE_EVENT_RECORD
{
COORD dwMousePosition;
DWORD dwButtonState;
DWORD dwControlKeyState;
DWORD dwEventFlags;
}
MOUSE_EVENT_RECORD,*PMOUSE_EVENT_RECORD;

typedef struct _MENU_EVENT_RECORD
{
UINT dwCommandId;
}
MENU_EVENT_RECORD,*PMENU_EVENT_RECORD;

typedef struct _FOCUS_EVENT_RECORD
{
WINBOOL bSetFocus;
}
FOCUS_EVENT_RECORD,*PFOCUS_EVENT_RECORD;
typedef struct _WINDOW_BUFFER_SIZE_RECORD
{
COORD dwSize;
}
WINDOW_BUFFER_SIZE_RECORD,*PWINDOW_BUFFER_SIZE_RECORD;
typedef struct _INPUT_RECORD
{
WORD EventType;
union
{
KEY_EVENT_RECORD KeyEvent;
MOUSE_EVENT_RECORD MouseEvent;
WINDOW_BUFFER_SIZE_RECORD WindowBufferSizeEvent;
MENU_EVENT_RECORD MenuEvent;
FOCUS_EVENT_RECORD FocusEvent;
}
Event;
}
INPUT_RECORD,*PINPUT_RECORD;

typedef struct tagPAINTSTRUCT
{
HDC hdc;
WINBOOL fErase;
RECT rcPaint;
WINBOOL fRestore;
WINBOOL fIncUpdate;
BYTE rgbReserved[32];
}
PAINTSTRUCT,*PPAINTSTRUCT,*NPPAINTSTRUCT,*LPPAINTSTRUCT;

typedef void *HGDIOBJ;

typedef WINBOOL (WINAPI *PHANDLER_ROUTINE)(DWORD CtrlType);


#define FACILITY_WINDOWSUPDATE 36
#define FACILITY_WINDOWS_CE 24
#define FACILITY_WINDOWS 8
#define FACILITY_URT 19
#define FACILITY_UMI 22
#define FACILITY_SXS 23
#define FACILITY_STORAGE 3
#define FACILITY_STATE_MANAGEMENT 34
#define FACILITY_SSPI 9
#define FACILITY_SCARD 16
#define FACILITY_SETUPAPI 15
#define FACILITY_SECURITY 9
#define FACILITY_RPC 1
#define FACILITY_WIN32 7
#define FACILITY_CONTROL 10
#define FACILITY_NULL 0
#define FACILITY_METADIRECTORY 35
#define FACILITY_MSMQ 14
#define FACILITY_MEDIASERVER 13
#define FACILITY_INTERNET 12
#define FACILITY_ITF 4
#define FACILITY_HTTP 25
#define FACILITY_DPLAY 21
#define FACILITY_DISPATCH 2
#define FACILITY_DIRECTORYSERVICE 37
#define FACILITY_CONFIGURATION 33
#define FACILITY_COMPLUS 17
#define FACILITY_CERT 11
#define FACILITY_BACKGROUNDCOPY 32
#define FACILITY_ACS 20
#define FACILITY_AAF 18
#define FACILITY_AUDCLNT 2185
#define ERROR_SUCCESS __MSABI_LONG(0)
#define NO_ERROR __MSABI_LONG(0)
#define SEC_E_OK ((HRESULT)0x00000000)
#define ERROR_INVALID_FUNCTION __MSABI_LONG(1)
#define ERROR_FILE_NOT_FOUND __MSABI_LONG(2)
#define ERROR_PATH_NOT_FOUND __MSABI_LONG(3)
#define ERROR_TOO_MANY_OPEN_FILES __MSABI_LONG(4)
#define ERROR_ACCESS_DENIED __MSABI_LONG(5)
#define ERROR_INVALID_HANDLE __MSABI_LONG(6)
#define ERROR_ARENA_TRASHED __MSABI_LONG(7)
#define ERROR_NOT_ENOUGH_MEMORY __MSABI_LONG(8)
#define ERROR_INVALID_BLOCK __MSABI_LONG(9)
#define ERROR_BAD_ENVIRONMENT __MSABI_LONG(10)
#define ERROR_BAD_FORMAT __MSABI_LONG(11)
#define ERROR_INVALID_ACCESS __MSABI_LONG(12)
#define ERROR_INVALID_DATA __MSABI_LONG(13)
#define ERROR_OUTOFMEMORY __MSABI_LONG(14)
#define ERROR_INVALID_DRIVE __MSABI_LONG(15)
#define ERROR_CURRENT_DIRECTORY __MSABI_LONG(16)
#define ERROR_NOT_SAME_DEVICE __MSABI_LONG(17)
#define ERROR_NO_MORE_FILES __MSABI_LONG(18)
#define ERROR_WRITE_PROTECT __MSABI_LONG(19)
#define ERROR_BAD_UNIT __MSABI_LONG(20)
#define ERROR_NOT_READY __MSABI_LONG(21)
#define ERROR_BAD_COMMAND __MSABI_LONG(22)
#define ERROR_CRC __MSABI_LONG(23)
#define ERROR_BAD_LENGTH __MSABI_LONG(24)
#define ERROR_SEEK __MSABI_LONG(25)
#define ERROR_NOT_DOS_DISK __MSABI_LONG(26)
#define ERROR_SECTOR_NOT_FOUND __MSABI_LONG(27)
#define ERROR_OUT_OF_PAPER __MSABI_LONG(28)
#define ERROR_WRITE_FAULT __MSABI_LONG(29)
#define ERROR_READ_FAULT __MSABI_LONG(30)
#define ERROR_GEN_FAILURE __MSABI_LONG(31)
#define ERROR_SHARING_VIOLATION __MSABI_LONG(32)
#define ERROR_LOCK_VIOLATION __MSABI_LONG(33)
#define ERROR_WRONG_DISK __MSABI_LONG(34)
#define ERROR_SHARING_BUFFER_EXCEEDED __MSABI_LONG(36)
#define ERROR_HANDLE_EOF __MSABI_LONG(38)
#define ERROR_HANDLE_DISK_FULL __MSABI_LONG(39)
#define ERROR_NOT_SUPPORTED __MSABI_LONG(50)
#define ERROR_REM_NOT_LIST __MSABI_LONG(51)
#define ERROR_DUP_NAME __MSABI_LONG(52)
#define ERROR_BAD_NETPATH __MSABI_LONG(53)
#define ERROR_NETWORK_BUSY __MSABI_LONG(54)
#define ERROR_DEV_NOT_EXIST __MSABI_LONG(55)
#define ERROR_TOO_MANY_CMDS __MSABI_LONG(56)
#define ERROR_ADAP_HDW_ERR __MSABI_LONG(57)
#define ERROR_BAD_NET_RESP __MSABI_LONG(58)
#define ERROR_UNEXP_NET_ERR __MSABI_LONG(59)
#define ERROR_BAD_REM_ADAP __MSABI_LONG(60)
#define ERROR_PRINTQ_FULL __MSABI_LONG(61)
#define ERROR_NO_SPOOL_SPACE __MSABI_LONG(62)
#define ERROR_PRINT_CANCELLED __MSABI_LONG(63)
#define ERROR_NETNAME_DELETED __MSABI_LONG(64)
#define ERROR_NETWORK_ACCESS_DENIED __MSABI_LONG(65)
#define ERROR_BAD_DEV_TYPE __MSABI_LONG(66)
#define ERROR_BAD_NET_NAME __MSABI_LONG(67)
#define ERROR_TOO_MANY_NAMES __MSABI_LONG(68)
#define ERROR_TOO_MANY_SESS __MSABI_LONG(69)
#define ERROR_SHARING_PAUSED __MSABI_LONG(70)
#define ERROR_REQ_NOT_ACCEP __MSABI_LONG(71)
#define ERROR_REDIR_PAUSED __MSABI_LONG(72)
#define ERROR_FILE_EXISTS __MSABI_LONG(80)
#define ERROR_CANNOT_MAKE __MSABI_LONG(82)
#define ERROR_FAIL_I24 __MSABI_LONG(83)
#define ERROR_OUT_OF_STRUCTURES __MSABI_LONG(84)
#define ERROR_ALREADY_ASSIGNED __MSABI_LONG(85)
#define ERROR_INVALID_PASSWORD __MSABI_LONG(86)
#define ERROR_INVALID_PARAMETER __MSABI_LONG(87)
#define ERROR_NET_WRITE_FAULT __MSABI_LONG(88)
#define ERROR_NO_PROC_SLOTS __MSABI_LONG(89)
#define ERROR_TOO_MANY_SEMAPHORES __MSABI_LONG(100)
#define ERROR_EXCL_SEM_ALREADY_OWNED __MSABI_LONG(101)
#define ERROR_SEM_IS_SET __MSABI_LONG(102)
#define ERROR_TOO_MANY_SEM_REQUESTS __MSABI_LONG(103)
#define ERROR_INVALID_AT_INTERRUPT_TIME __MSABI_LONG(104)
#define ERROR_SEM_OWNER_DIED __MSABI_LONG(105)
#define ERROR_SEM_USER_LIMIT __MSABI_LONG(106)
#define ERROR_DISK_CHANGE __MSABI_LONG(107)
#define ERROR_DRIVE_LOCKED __MSABI_LONG(108)
#define ERROR_BROKEN_PIPE __MSABI_LONG(109)
#define ERROR_OPEN_FAILED __MSABI_LONG(110)
#define ERROR_BUFFER_OVERFLOW __MSABI_LONG(111)
#define ERROR_DISK_FULL __MSABI_LONG(112)
#define ERROR_NO_MORE_SEARCH_HANDLES __MSABI_LONG(113)
#define ERROR_INVALID_TARGET_HANDLE __MSABI_LONG(114)
#define ERROR_INVALID_CATEGORY __MSABI_LONG(117)
#define ERROR_INVALID_VERIFY_SWITCH __MSABI_LONG(118)
#define ERROR_BAD_DRIVER_LEVEL __MSABI_LONG(119)
#define ERROR_CALL_NOT_IMPLEMENTED __MSABI_LONG(120)
#define ERROR_SEM_TIMEOUT __MSABI_LONG(121)
#define ERROR_INSUFFICIENT_BUFFER __MSABI_LONG(122)
#define ERROR_INVALID_NAME __MSABI_LONG(123)
#define ERROR_INVALID_LEVEL __MSABI_LONG(124)
#define ERROR_NO_VOLUME_LABEL __MSABI_LONG(125)
#define ERROR_MOD_NOT_FOUND __MSABI_LONG(126)
#define ERROR_PROC_NOT_FOUND __MSABI_LONG(127)
#define ERROR_WAIT_NO_CHILDREN __MSABI_LONG(128)
#define ERROR_CHILD_NOT_COMPLETE __MSABI_LONG(129)
#define ERROR_DIRECT_ACCESS_HANDLE __MSABI_LONG(130)
#define ERROR_NEGATIVE_SEEK __MSABI_LONG(131)
#define ERROR_SEEK_ON_DEVICE __MSABI_LONG(132)
#define ERROR_IS_JOIN_TARGET __MSABI_LONG(133)
#define ERROR_IS_JOINED __MSABI_LONG(134)
#define ERROR_IS_SUBSTED __MSABI_LONG(135)
#define ERROR_NOT_JOINED __MSABI_LONG(136)
#define ERROR_NOT_SUBSTED __MSABI_LONG(137)
#define ERROR_JOIN_TO_JOIN __MSABI_LONG(138)
#define ERROR_SUBST_TO_SUBST __MSABI_LONG(139)
#define ERROR_JOIN_TO_SUBST __MSABI_LONG(140)
#define ERROR_SUBST_TO_JOIN __MSABI_LONG(141)
#define ERROR_BUSY_DRIVE __MSABI_LONG(142)
#define ERROR_SAME_DRIVE __MSABI_LONG(143)
#define ERROR_DIR_NOT_ROOT __MSABI_LONG(144)
#define ERROR_DIR_NOT_EMPTY __MSABI_LONG(145)
#define ERROR_IS_SUBST_PATH __MSABI_LONG(146)
#define ERROR_IS_JOIN_PATH __MSABI_LONG(147)
#define ERROR_PATH_BUSY __MSABI_LONG(148)
#define ERROR_IS_SUBST_TARGET __MSABI_LONG(149)
#define ERROR_SYSTEM_TRACE __MSABI_LONG(150)
#define ERROR_INVALID_EVENT_COUNT __MSABI_LONG(151)
#define ERROR_TOO_MANY_MUXWAITERS __MSABI_LONG(152)
#define ERROR_INVALID_LIST_FORMAT __MSABI_LONG(153)
#define ERROR_LABEL_TOO_LONG __MSABI_LONG(154)
#define ERROR_TOO_MANY_TCBS __MSABI_LONG(155)
#define ERROR_SIGNAL_REFUSED __MSABI_LONG(156)
#define ERROR_DISCARDED __MSABI_LONG(157)
#define ERROR_NOT_LOCKED __MSABI_LONG(158)
#define ERROR_BAD_THREADID_ADDR __MSABI_LONG(159)
#define ERROR_BAD_ARGUMENTS __MSABI_LONG(160)
#define ERROR_BAD_PATHNAME __MSABI_LONG(161)
#define ERROR_SIGNAL_PENDING __MSABI_LONG(162)
#define ERROR_MAX_THRDS_REACHED __MSABI_LONG(164)
#define ERROR_LOCK_FAILED __MSABI_LONG(167)
#define ERROR_BUSY __MSABI_LONG(170)
#define ERROR_CANCEL_VIOLATION __MSABI_LONG(173)
#define ERROR_ATOMIC_LOCKS_NOT_SUPPORTED __MSABI_LONG(174)
#define ERROR_INVALID_SEGMENT_NUMBER __MSABI_LONG(180)
#define ERROR_INVALID_ORDINAL __MSABI_LONG(182)
#define ERROR_ALREADY_EXISTS __MSABI_LONG(183)
#define ERROR_INVALID_FLAG_NUMBER __MSABI_LONG(186)
#define ERROR_SEM_NOT_FOUND __MSABI_LONG(187)
#define ERROR_INVALID_STARTING_CODESEG __MSABI_LONG(188)
#define ERROR_INVALID_STACKSEG __MSABI_LONG(189)
#define ERROR_INVALID_MODULETYPE __MSABI_LONG(190)
#define ERROR_INVALID_EXE_SIGNATURE __MSABI_LONG(191)
#define ERROR_EXE_MARKED_INVALID __MSABI_LONG(192)
#define ERROR_BAD_EXE_FORMAT __MSABI_LONG(193)
#define ERROR_ITERATED_DATA_EXCEEDS_64k __MSABI_LONG(194)
#define ERROR_INVALID_MINALLOCSIZE __MSABI_LONG(195)
#define ERROR_DYNLINK_FROM_INVALID_RING __MSABI_LONG(196)
#define ERROR_IOPL_NOT_ENABLED __MSABI_LONG(197)
#define ERROR_INVALID_SEGDPL __MSABI_LONG(198)
#define ERROR_AUTODATASEG_EXCEEDS_64k __MSABI_LONG(199)
#define ERROR_RING2SEG_MUST_BE_MOVABLE __MSABI_LONG(200)
#define ERROR_RELOC_CHAIN_XEEDS_SEGLIM __MSABI_LONG(201)
#define ERROR_INFLOOP_IN_RELOC_CHAIN __MSABI_LONG(202)
#define ERROR_ENVVAR_NOT_FOUND __MSABI_LONG(203)
#define ERROR_NO_SIGNAL_SENT __MSABI_LONG(205)
#define ERROR_FILENAME_EXCED_RANGE __MSABI_LONG(206)
#define ERROR_RING2_STACK_IN_USE __MSABI_LONG(207)
#define ERROR_META_EXPANSION_TOO_LONG __MSABI_LONG(208)
#define ERROR_INVALID_SIGNAL_NUMBER __MSABI_LONG(209)
#define ERROR_THREAD_1_INACTIVE __MSABI_LONG(210)
#define ERROR_LOCKED __MSABI_LONG(212)
#define ERROR_TOO_MANY_MODULES __MSABI_LONG(214)
#define ERROR_NESTING_NOT_ALLOWED __MSABI_LONG(215)
#define ERROR_EXE_MACHINE_TYPE_MISMATCH __MSABI_LONG(216)
#define ERROR_EXE_CANNOT_MODIFY_SIGNED_BINARY __MSABI_LONG(217)
#define ERROR_EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY __MSABI_LONG(218)
#define ERROR_FILE_CHECKED_OUT __MSABI_LONG(220)
#define ERROR_CHECKOUT_REQUIRED __MSABI_LONG(221)
#define ERROR_BAD_FILE_TYPE __MSABI_LONG(222)
#define ERROR_FILE_TOO_LARGE __MSABI_LONG(223)
#define ERROR_FORMS_AUTH_REQUIRED __MSABI_LONG(224)
#define ERROR_PIPE_LOCAL __MSABI_LONG(229)
#define ERROR_BAD_PIPE __MSABI_LONG(230)
#define ERROR_PIPE_BUSY __MSABI_LONG(231)
#define ERROR_NO_DATA __MSABI_LONG(232)
#define ERROR_PIPE_NOT_CONNECTED __MSABI_LONG(233)
#define ERROR_MORE_DATA __MSABI_LONG(234)
#define ERROR_VC_DISCONNECTED __MSABI_LONG(240)
#define ERROR_INVALID_EA_NAME __MSABI_LONG(254)
#define ERROR_EA_LIST_INCONSISTENT __MSABI_LONG(255)
#define WAIT_TIMEOUT __MSABI_LONG(258)
#define ERROR_NO_MORE_ITEMS __MSABI_LONG(259)
#define ERROR_CANNOT_COPY __MSABI_LONG(266)
#define ERROR_DIRECTORY __MSABI_LONG(267)
#define ERROR_EAS_DIDNT_FIT __MSABI_LONG(275)
#define ERROR_EA_FILE_CORRUPT __MSABI_LONG(276)
#define ERROR_EA_TABLE_FULL __MSABI_LONG(277)
#define ERROR_INVALID_EA_HANDLE __MSABI_LONG(278)
#define ERROR_EAS_NOT_SUPPORTED __MSABI_LONG(282)
#define ERROR_NOT_OWNER __MSABI_LONG(288)
#define ERROR_TOO_MANY_POSTS __MSABI_LONG(298)
#define ERROR_PARTIAL_COPY __MSABI_LONG(299)
#define ERROR_OPLOCK_NOT_GRANTED __MSABI_LONG(300)
#define ERROR_INVALID_OPLOCK_PROTOCOL __MSABI_LONG(301)
#define ERROR_DISK_TOO_FRAGMENTED __MSABI_LONG(302)
#define ERROR_DELETE_PENDING __MSABI_LONG(303)
#define ERROR_MR_MID_NOT_FOUND __MSABI_LONG(317)
#define ERROR_SCOPE_NOT_FOUND __MSABI_LONG(318)
#define ERROR_INVALID_ADDRESS __MSABI_LONG(487)
#define ERROR_ARITHMETIC_OVERFLOW __MSABI_LONG(534)
#define ERROR_PIPE_CONNECTED __MSABI_LONG(535)
#define ERROR_PIPE_LISTENING __MSABI_LONG(536)
#define ERROR_WAKE_SYSTEM __MSABI_LONG(730)
#define ERROR_WAIT_1 __MSABI_LONG(731)
#define ERROR_WAIT_2 __MSABI_LONG(732)
#define ERROR_WAIT_3 __MSABI_LONG(733)
#define ERROR_WAIT_63 __MSABI_LONG(734)
#define ERROR_ABANDONED_WAIT_0 __MSABI_LONG(735)
#define ERROR_ABANDONED_WAIT_63 __MSABI_LONG(736)
#define ERROR_USER_APC __MSABI_LONG(737)
#define ERROR_KERNEL_APC __MSABI_LONG(738)
#define ERROR_ALERTED __MSABI_LONG(739)
#define ERROR_EA_ACCESS_DENIED __MSABI_LONG(994)
#define ERROR_OPERATION_ABORTED __MSABI_LONG(995)
#define ERROR_IO_INCOMPLETE __MSABI_LONG(996)
#define ERROR_IO_PENDING __MSABI_LONG(997)
#define ERROR_NOACCESS __MSABI_LONG(998)
#define ERROR_SWAPERROR __MSABI_LONG(999)
#define ERROR_STACK_OVERFLOW __MSABI_LONG(1001)
#define ERROR_INVALID_MESSAGE __MSABI_LONG(1002)
#define ERROR_CAN_NOT_COMPLETE __MSABI_LONG(1003)
#define ERROR_INVALID_FLAGS __MSABI_LONG(1004)
#define ERROR_UNRECOGNIZED_VOLUME __MSABI_LONG(1005)
#define ERROR_FILE_INVALID __MSABI_LONG(1006)
#define ERROR_FULLSCREEN_MODE __MSABI_LONG(1007)
#define ERROR_NO_TOKEN __MSABI_LONG(1008)
#define ERROR_BADDB __MSABI_LONG(1009)
#define ERROR_BADKEY __MSABI_LONG(1010)
#define ERROR_CANTOPEN __MSABI_LONG(1011)
#define ERROR_CANTREAD __MSABI_LONG(1012)
#define ERROR_CANTWRITE __MSABI_LONG(1013)
#define ERROR_REGISTRY_RECOVERED __MSABI_LONG(1014)
#define ERROR_REGISTRY_CORRUPT __MSABI_LONG(1015)
#define ERROR_REGISTRY_IO_FAILED __MSABI_LONG(1016)
#define ERROR_NOT_REGISTRY_FILE __MSABI_LONG(1017)
#define ERROR_KEY_DELETED __MSABI_LONG(1018)
#define ERROR_NO_LOG_SPACE __MSABI_LONG(1019)
#define ERROR_KEY_HAS_CHILDREN __MSABI_LONG(1020)
#define ERROR_CHILD_MUST_BE_VOLATILE __MSABI_LONG(1021)
#define ERROR_NOTIFY_ENUM_DIR __MSABI_LONG(1022)
#define ERROR_DEPENDENT_SERVICES_RUNNING __MSABI_LONG(1051)
#define ERROR_INVALID_SERVICE_CONTROL __MSABI_LONG(1052)
#define ERROR_SERVICE_REQUEST_TIMEOUT __MSABI_LONG(1053)
#define ERROR_SERVICE_NO_THREAD __MSABI_LONG(1054)
#define ERROR_SERVICE_DATABASE_LOCKED __MSABI_LONG(1055)
#define ERROR_SERVICE_ALREADY_RUNNING __MSABI_LONG(1056)
#define ERROR_INVALID_SERVICE_ACCOUNT __MSABI_LONG(1057)
#define ERROR_SERVICE_DISABLED __MSABI_LONG(1058)
#define ERROR_CIRCULAR_DEPENDENCY __MSABI_LONG(1059)
#define ERROR_SERVICE_DOES_NOT_EXIST __MSABI_LONG(1060)
#define ERROR_SERVICE_CANNOT_ACCEPT_CTRL __MSABI_LONG(1061)
#define ERROR_SERVICE_NOT_ACTIVE __MSABI_LONG(1062)
#define ERROR_FAILED_SERVICE_CONTROLLER_CONNECT __MSABI_LONG(1063)
#define ERROR_EXCEPTION_IN_SERVICE __MSABI_LONG(1064)
#define ERROR_DATABASE_DOES_NOT_EXIST __MSABI_LONG(1065)
#define ERROR_SERVICE_SPECIFIC_ERROR __MSABI_LONG(1066)
#define ERROR_PROCESS_ABORTED __MSABI_LONG(1067)
#define ERROR_SERVICE_DEPENDENCY_FAIL __MSABI_LONG(1068)
#define ERROR_SERVICE_LOGON_FAILED __MSABI_LONG(1069)
#define ERROR_SERVICE_START_HANG __MSABI_LONG(1070)
#define ERROR_INVALID_SERVICE_LOCK __MSABI_LONG(1071)
#define ERROR_SERVICE_MARKED_FOR_DELETE __MSABI_LONG(1072)
#define ERROR_SERVICE_EXISTS __MSABI_LONG(1073)
#define ERROR_ALREADY_RUNNING_LKG __MSABI_LONG(1074)
#define ERROR_SERVICE_DEPENDENCY_DELETED __MSABI_LONG(1075)
#define ERROR_BOOT_ALREADY_ACCEPTED __MSABI_LONG(1076)
#define ERROR_SERVICE_NEVER_STARTED __MSABI_LONG(1077)
#define ERROR_DUPLICATE_SERVICE_NAME __MSABI_LONG(1078)
#define ERROR_DIFFERENT_SERVICE_ACCOUNT __MSABI_LONG(1079)
#define ERROR_CANNOT_DETECT_DRIVER_FAILURE __MSABI_LONG(1080)
#define ERROR_CANNOT_DETECT_PROCESS_ABORT __MSABI_LONG(1081)
#define ERROR_NO_RECOVERY_PROGRAM __MSABI_LONG(1082)
#define ERROR_SERVICE_NOT_IN_EXE __MSABI_LONG(1083)
#define ERROR_NOT_SAFEBOOT_SERVICE __MSABI_LONG(1084)
#define ERROR_END_OF_MEDIA __MSABI_LONG(1100)
#define ERROR_FILEMARK_DETECTED __MSABI_LONG(1101)
#define ERROR_BEGINNING_OF_MEDIA __MSABI_LONG(1102)
#define ERROR_SETMARK_DETECTED __MSABI_LONG(1103)
#define ERROR_NO_DATA_DETECTED __MSABI_LONG(1104)
#define ERROR_PARTITION_FAILURE __MSABI_LONG(1105)
#define ERROR_INVALID_BLOCK_LENGTH __MSABI_LONG(1106)
#define ERROR_DEVICE_NOT_PARTITIONED __MSABI_LONG(1107)
#define ERROR_UNABLE_TO_LOCK_MEDIA __MSABI_LONG(1108)
#define ERROR_UNABLE_TO_UNLOAD_MEDIA __MSABI_LONG(1109)
#define ERROR_MEDIA_CHANGED __MSABI_LONG(1110)
#define ERROR_BUS_RESET __MSABI_LONG(1111)
#define ERROR_NO_MEDIA_IN_DRIVE __MSABI_LONG(1112)
#define ERROR_NO_UNICODE_TRANSLATION __MSABI_LONG(1113)
#define ERROR_DLL_INIT_FAILED __MSABI_LONG(1114)
#define ERROR_SHUTDOWN_IN_PROGRESS __MSABI_LONG(1115)
#define ERROR_NO_SHUTDOWN_IN_PROGRESS __MSABI_LONG(1116)
#define ERROR_IO_DEVICE __MSABI_LONG(1117)
#define ERROR_SERIAL_NO_DEVICE __MSABI_LONG(1118)
#define ERROR_IRQ_BUSY __MSABI_LONG(1119)
#define ERROR_MORE_WRITES __MSABI_LONG(1120)
#define ERROR_COUNTER_TIMEOUT __MSABI_LONG(1121)
#define ERROR_FLOPPY_ID_MARK_NOT_FOUND __MSABI_LONG(1122)
#define ERROR_FLOPPY_WRONG_CYLINDER __MSABI_LONG(1123)
#define ERROR_FLOPPY_UNKNOWN_ERROR __MSABI_LONG(1124)
#define ERROR_FLOPPY_BAD_REGISTERS __MSABI_LONG(1125)
#define ERROR_DISK_RECALIBRATE_FAILED __MSABI_LONG(1126)
#define ERROR_DISK_OPERATION_FAILED __MSABI_LONG(1127)
#define ERROR_DISK_RESET_FAILED __MSABI_LONG(1128)
#define ERROR_EOM_OVERFLOW __MSABI_LONG(1129)
#define ERROR_NOT_ENOUGH_SERVER_MEMORY __MSABI_LONG(1130)
#define ERROR_POSSIBLE_DEADLOCK __MSABI_LONG(1131)
#define ERROR_MAPPED_ALIGNMENT __MSABI_LONG(1132)
#define ERROR_SET_POWER_STATE_VETOED __MSABI_LONG(1140)
#define ERROR_SET_POWER_STATE_FAILED __MSABI_LONG(1141)
#define ERROR_TOO_MANY_LINKS __MSABI_LONG(1142)
#define ERROR_OLD_WIN_VERSION __MSABI_LONG(1150)
#define ERROR_APP_WRONG_OS __MSABI_LONG(1151)
#define ERROR_SINGLE_INSTANCE_APP __MSABI_LONG(1152)
#define ERROR_RMODE_APP __MSABI_LONG(1153)
#define ERROR_INVALID_DLL __MSABI_LONG(1154)
#define ERROR_NO_ASSOCIATION __MSABI_LONG(1155)
#define ERROR_DDE_FAIL __MSABI_LONG(1156)
#define ERROR_DLL_NOT_FOUND __MSABI_LONG(1157)
#define ERROR_NO_MORE_USER_HANDLES __MSABI_LONG(1158)
#define ERROR_MESSAGE_SYNC_ONLY __MSABI_LONG(1159)
#define ERROR_SOURCE_ELEMENT_EMPTY __MSABI_LONG(1160)
#define ERROR_DESTINATION_ELEMENT_FULL __MSABI_LONG(1161)
#define ERROR_ILLEGAL_ELEMENT_ADDRESS __MSABI_LONG(1162)
#define ERROR_MAGAZINE_NOT_PRESENT __MSABI_LONG(1163)
#define ERROR_DEVICE_REINITIALIZATION_NEEDED __MSABI_LONG(1164)
#define ERROR_DEVICE_REQUIRES_CLEANING __MSABI_LONG(1165)
#define ERROR_DEVICE_DOOR_OPEN __MSABI_LONG(1166)
#define ERROR_DEVICE_NOT_CONNECTED __MSABI_LONG(1167)
#define ERROR_NOT_FOUND __MSABI_LONG(1168)
#define ERROR_NO_MATCH __MSABI_LONG(1169)
#define ERROR_SET_NOT_FOUND __MSABI_LONG(1170)
#define ERROR_POINT_NOT_FOUND __MSABI_LONG(1171)
#define ERROR_NO_TRACKING_SERVICE __MSABI_LONG(1172)
#define ERROR_NO_VOLUME_ID __MSABI_LONG(1173)
#define ERROR_UNABLE_TO_REMOVE_REPLACED __MSABI_LONG(1175)
#define ERROR_UNABLE_TO_MOVE_REPLACEMENT __MSABI_LONG(1176)
#define ERROR_UNABLE_TO_MOVE_REPLACEMENT_2 __MSABI_LONG(1177)
#define ERROR_JOURNAL_DELETE_IN_PROGRESS __MSABI_LONG(1178)
#define ERROR_JOURNAL_NOT_ACTIVE __MSABI_LONG(1179)
#define ERROR_POTENTIAL_FILE_FOUND __MSABI_LONG(1180)
#define ERROR_JOURNAL_ENTRY_DELETED __MSABI_LONG(1181)
#define ERROR_BAD_DEVICE __MSABI_LONG(1200)
#define ERROR_CONNECTION_UNAVAIL __MSABI_LONG(1201)
#define ERROR_DEVICE_ALREADY_REMEMBERED __MSABI_LONG(1202)
#define ERROR_NO_NET_OR_BAD_PATH __MSABI_LONG(1203)
#define ERROR_BAD_PROVIDER __MSABI_LONG(1204)
#define ERROR_CANNOT_OPEN_PROFILE __MSABI_LONG(1205)
#define ERROR_BAD_PROFILE __MSABI_LONG(1206)
#define ERROR_NOT_CONTAINER __MSABI_LONG(1207)
#define ERROR_EXTENDED_ERROR __MSABI_LONG(1208)
#define ERROR_INVALID_GROUPNAME __MSABI_LONG(1209)
#define ERROR_INVALID_COMPUTERNAME __MSABI_LONG(1210)
#define ERROR_INVALID_EVENTNAME __MSABI_LONG(1211)
#define ERROR_INVALID_DOMAINNAME __MSABI_LONG(1212)
#define ERROR_INVALID_SERVICENAME __MSABI_LONG(1213)
#define ERROR_INVALID_NETNAME __MSABI_LONG(1214)
#define ERROR_INVALID_SHARENAME __MSABI_LONG(1215)
#define ERROR_INVALID_PASSWORDNAME __MSABI_LONG(1216)
#define ERROR_INVALID_MESSAGENAME __MSABI_LONG(1217)
#define ERROR_INVALID_MESSAGEDEST __MSABI_LONG(1218)
#define ERROR_SESSION_CREDENTIAL_CONFLICT __MSABI_LONG(1219)
#define ERROR_REMOTE_SESSION_LIMIT_EXCEEDED __MSABI_LONG(1220)
#define ERROR_DUP_DOMAINNAME __MSABI_LONG(1221)
#define ERROR_NO_NETWORK __MSABI_LONG(1222)
#define ERROR_CANCELLED __MSABI_LONG(1223)
#define ERROR_USER_MAPPED_FILE __MSABI_LONG(1224)
#define ERROR_CONNECTION_REFUSED __MSABI_LONG(1225)
#define ERROR_GRACEFUL_DISCONNECT __MSABI_LONG(1226)
#define ERROR_ADDRESS_ALREADY_ASSOCIATED __MSABI_LONG(1227)
#define ERROR_ADDRESS_NOT_ASSOCIATED __MSABI_LONG(1228)
#define ERROR_CONNECTION_INVALID __MSABI_LONG(1229)
#define ERROR_CONNECTION_ACTIVE __MSABI_LONG(1230)
#define ERROR_NETWORK_UNREACHABLE __MSABI_LONG(1231)
#define ERROR_HOST_UNREACHABLE __MSABI_LONG(1232)
#define ERROR_PROTOCOL_UNREACHABLE __MSABI_LONG(1233)
#define ERROR_PORT_UNREACHABLE __MSABI_LONG(1234)
#define ERROR_REQUEST_ABORTED __MSABI_LONG(1235)
#define ERROR_CONNECTION_ABORTED __MSABI_LONG(1236)
#define ERROR_RETRY __MSABI_LONG(1237)
#define ERROR_CONNECTION_COUNT_LIMIT __MSABI_LONG(1238)
#define ERROR_LOGIN_TIME_RESTRICTION __MSABI_LONG(1239)
#define ERROR_LOGIN_WKSTA_RESTRICTION __MSABI_LONG(1240)
#define ERROR_INCORRECT_ADDRESS __MSABI_LONG(1241)
#define ERROR_ALREADY_REGISTERED __MSABI_LONG(1242)
#define ERROR_SERVICE_NOT_FOUND __MSABI_LONG(1243)
#define ERROR_NOT_AUTHENTICATED __MSABI_LONG(1244)
#define ERROR_NOT_LOGGED_ON __MSABI_LONG(1245)
#define ERROR_CONTINUE __MSABI_LONG(1246)
#define ERROR_ALREADY_INITIALIZED __MSABI_LONG(1247)
#define ERROR_NO_MORE_DEVICES __MSABI_LONG(1248)
#define ERROR_NO_SUCH_SITE __MSABI_LONG(1249)
#define ERROR_DOMAIN_CONTROLLER_EXISTS __MSABI_LONG(1250)
#define ERROR_ONLY_IF_CONNECTED __MSABI_LONG(1251)
#define ERROR_OVERRIDE_NOCHANGES __MSABI_LONG(1252)
#define ERROR_BAD_USER_PROFILE __MSABI_LONG(1253)
#define ERROR_NOT_SUPPORTED_ON_SBS __MSABI_LONG(1254)
#define ERROR_SERVER_SHUTDOWN_IN_PROGRESS __MSABI_LONG(1255)
#define ERROR_HOST_DOWN __MSABI_LONG(1256)
#define ERROR_NON_ACCOUNT_SID __MSABI_LONG(1257)
#define ERROR_NON_DOMAIN_SID __MSABI_LONG(1258)
#define ERROR_APPHELP_BLOCK __MSABI_LONG(1259)
#define ERROR_ACCESS_DISABLED_BY_POLICY __MSABI_LONG(1260)
#define ERROR_REG_NAT_CONSUMPTION __MSABI_LONG(1261)
#define ERROR_CSCSHARE_OFFLINE __MSABI_LONG(1262)
#define ERROR_PKINIT_FAILURE __MSABI_LONG(1263)
#define ERROR_SMARTCARD_SUBSYSTEM_FAILURE __MSABI_LONG(1264)
#define ERROR_DOWNGRADE_DETECTED __MSABI_LONG(1265)
#define ERROR_MACHINE_LOCKED __MSABI_LONG(1271)
#define ERROR_CALLBACK_SUPPLIED_INVALID_DATA __MSABI_LONG(1273)
#define ERROR_SYNC_FOREGROUND_REFRESH_REQUIRED __MSABI_LONG(1274)
#define ERROR_DRIVER_BLOCKED __MSABI_LONG(1275)
#define ERROR_INVALID_IMPORT_OF_NON_DLL __MSABI_LONG(1276)
#define ERROR_ACCESS_DISABLED_WEBBLADE __MSABI_LONG(1277)
#define ERROR_ACCESS_DISABLED_WEBBLADE_TAMPER __MSABI_LONG(1278)
#define ERROR_RECOVERY_FAILURE __MSABI_LONG(1279)
#define ERROR_ALREADY_FIBER __MSABI_LONG(1280)
#define ERROR_ALREADY_THREAD __MSABI_LONG(1281)
#define ERROR_STACK_BUFFER_OVERRUN __MSABI_LONG(1282)
#define ERROR_PARAMETER_QUOTA_EXCEEDED __MSABI_LONG(1283)
#define ERROR_DEBUGGER_INACTIVE __MSABI_LONG(1284)
#define ERROR_DELAY_LOAD_FAILED __MSABI_LONG(1285)
#define ERROR_VDM_DISALLOWED __MSABI_LONG(1286)
#define ERROR_UNIDENTIFIED_ERROR __MSABI_LONG(1287)
#define ERROR_NOT_ALL_ASSIGNED __MSABI_LONG(1300)
#define ERROR_SOME_NOT_MAPPED __MSABI_LONG(1301)
#define ERROR_NO_QUOTAS_FOR_ACCOUNT __MSABI_LONG(1302)
#define ERROR_LOCAL_USER_SESSION_KEY __MSABI_LONG(1303)
#define ERROR_NULL_LM_PASSWORD __MSABI_LONG(1304)
#define ERROR_UNKNOWN_REVISION __MSABI_LONG(1305)
#define ERROR_REVISION_MISMATCH __MSABI_LONG(1306)
#define ERROR_INVALID_OWNER __MSABI_LONG(1307)
#define ERROR_INVALID_PRIMARY_GROUP __MSABI_LONG(1308)
#define ERROR_NO_IMPERSONATION_TOKEN __MSABI_LONG(1309)
#define ERROR_CANT_DISABLE_MANDATORY __MSABI_LONG(1310)
#define ERROR_NO_LOGON_SERVERS __MSABI_LONG(1311)
#define ERROR_NO_SUCH_LOGON_SESSION __MSABI_LONG(1312)
#define ERROR_NO_SUCH_PRIVILEGE __MSABI_LONG(1313)
#define ERROR_PRIVILEGE_NOT_HELD __MSABI_LONG(1314)
#define ERROR_INVALID_ACCOUNT_NAME __MSABI_LONG(1315)
#define ERROR_USER_EXISTS __MSABI_LONG(1316)
#define ERROR_NO_SUCH_USER __MSABI_LONG(1317)
#define ERROR_GROUP_EXISTS __MSABI_LONG(1318)
#define ERROR_NO_SUCH_GROUP __MSABI_LONG(1319)
#define ERROR_MEMBER_IN_GROUP __MSABI_LONG(1320)
#define ERROR_MEMBER_NOT_IN_GROUP __MSABI_LONG(1321)
#define ERROR_LAST_ADMIN __MSABI_LONG(1322)
#define ERROR_WRONG_PASSWORD __MSABI_LONG(1323)
#define ERROR_ILL_FORMED_PASSWORD __MSABI_LONG(1324)
#define ERROR_PASSWORD_RESTRICTION __MSABI_LONG(1325)
#define ERROR_LOGON_FAILURE __MSABI_LONG(1326)
#define ERROR_ACCOUNT_RESTRICTION __MSABI_LONG(1327)
#define ERROR_INVALID_LOGON_HOURS __MSABI_LONG(1328)
#define ERROR_INVALID_WORKSTATION __MSABI_LONG(1329)
#define ERROR_PASSWORD_EXPIRED __MSABI_LONG(1330)
#define ERROR_ACCOUNT_DISABLED __MSABI_LONG(1331)
#define ERROR_NONE_MAPPED __MSABI_LONG(1332)
#define ERROR_TOO_MANY_LUIDS_REQUESTED __MSABI_LONG(1333)
#define ERROR_LUIDS_EXHAUSTED __MSABI_LONG(1334)
#define ERROR_INVALID_SUB_AUTHORITY __MSABI_LONG(1335)
#define ERROR_INVALID_ACL __MSABI_LONG(1336)
#define ERROR_INVALID_SID __MSABI_LONG(1337)
#define ERROR_INVALID_SECURITY_DESCR __MSABI_LONG(1338)
#define ERROR_BAD_INHERITANCE_ACL __MSABI_LONG(1340)
#define ERROR_SERVER_DISABLED __MSABI_LONG(1341)
#define ERROR_SERVER_NOT_DISABLED __MSABI_LONG(1342)
#define ERROR_INVALID_ID_AUTHORITY __MSABI_LONG(1343)
#define ERROR_ALLOTTED_SPACE_EXCEEDED __MSABI_LONG(1344)
#define ERROR_INVALID_GROUP_ATTRIBUTES __MSABI_LONG(1345)
#define ERROR_BAD_IMPERSONATION_LEVEL __MSABI_LONG(1346)
#define ERROR_CANT_OPEN_ANONYMOUS __MSABI_LONG(1347)
#define ERROR_BAD_VALIDATION_CLASS __MSABI_LONG(1348)
#define ERROR_BAD_TOKEN_TYPE __MSABI_LONG(1349)
#define ERROR_NO_SECURITY_ON_OBJECT __MSABI_LONG(1350)
#define ERROR_CANT_ACCESS_DOMAIN_INFO __MSABI_LONG(1351)
#define ERROR_INVALID_SERVER_STATE __MSABI_LONG(1352)
#define ERROR_INVALID_DOMAIN_STATE __MSABI_LONG(1353)
#define ERROR_INVALID_DOMAIN_ROLE __MSABI_LONG(1354)
#define ERROR_NO_SUCH_DOMAIN __MSABI_LONG(1355)
#define ERROR_DOMAIN_EXISTS __MSABI_LONG(1356)
#define ERROR_DOMAIN_LIMIT_EXCEEDED __MSABI_LONG(1357)
#define ERROR_INTERNAL_DB_CORRUPTION __MSABI_LONG(1358)
#define ERROR_INTERNAL_ERROR __MSABI_LONG(1359)
#define ERROR_GENERIC_NOT_MAPPED __MSABI_LONG(1360)
#define ERROR_BAD_DESCRIPTOR_FORMAT __MSABI_LONG(1361)
#define ERROR_NOT_LOGON_PROCESS __MSABI_LONG(1362)
#define ERROR_LOGON_SESSION_EXISTS __MSABI_LONG(1363)
#define ERROR_NO_SUCH_PACKAGE __MSABI_LONG(1364)
#define ERROR_BAD_LOGON_SESSION_STATE __MSABI_LONG(1365)
#define ERROR_LOGON_SESSION_COLLISION __MSABI_LONG(1366)
#define ERROR_INVALID_LOGON_TYPE __MSABI_LONG(1367)
#define ERROR_CANNOT_IMPERSONATE __MSABI_LONG(1368)
#define ERROR_RXACT_INVALID_STATE __MSABI_LONG(1369)
#define ERROR_RXACT_COMMIT_FAILURE __MSABI_LONG(1370)
#define ERROR_SPECIAL_ACCOUNT __MSABI_LONG(1371)
#define ERROR_SPECIAL_GROUP __MSABI_LONG(1372)
#define ERROR_SPECIAL_USER __MSABI_LONG(1373)
#define ERROR_MEMBERS_PRIMARY_GROUP __MSABI_LONG(1374)
#define ERROR_TOKEN_ALREADY_IN_USE __MSABI_LONG(1375)
#define ERROR_NO_SUCH_ALIAS __MSABI_LONG(1376)
#define ERROR_MEMBER_NOT_IN_ALIAS __MSABI_LONG(1377)
#define ERROR_MEMBER_IN_ALIAS __MSABI_LONG(1378)
#define ERROR_ALIAS_EXISTS __MSABI_LONG(1379)
#define ERROR_LOGON_NOT_GRANTED __MSABI_LONG(1380)
#define ERROR_TOO_MANY_SECRETS __MSABI_LONG(1381)
#define ERROR_SECRET_TOO_LONG __MSABI_LONG(1382)
#define ERROR_INTERNAL_DB_ERROR __MSABI_LONG(1383)
#define ERROR_TOO_MANY_CONTEXT_IDS __MSABI_LONG(1384)
#define ERROR_LOGON_TYPE_NOT_GRANTED __MSABI_LONG(1385)
#define ERROR_NT_CROSS_ENCRYPTION_REQUIRED __MSABI_LONG(1386)
#define ERROR_NO_SUCH_MEMBER __MSABI_LONG(1387)
#define ERROR_INVALID_MEMBER __MSABI_LONG(1388)
#define ERROR_TOO_MANY_SIDS __MSABI_LONG(1389)
#define ERROR_LM_CROSS_ENCRYPTION_REQUIRED __MSABI_LONG(1390)
#define ERROR_NO_INHERITANCE __MSABI_LONG(1391)
#define ERROR_FILE_CORRUPT __MSABI_LONG(1392)
#define ERROR_DISK_CORRUPT __MSABI_LONG(1393)
#define ERROR_NO_USER_SESSION_KEY __MSABI_LONG(1394)
#define ERROR_LICENSE_QUOTA_EXCEEDED __MSABI_LONG(1395)
#define ERROR_WRONG_TARGET_NAME __MSABI_LONG(1396)
#define ERROR_MUTUAL_AUTH_FAILED __MSABI_LONG(1397)
#define ERROR_TIME_SKEW __MSABI_LONG(1398)
#define ERROR_CURRENT_DOMAIN_NOT_ALLOWED __MSABI_LONG(1399)
#define ERROR_INVALID_WINDOW_HANDLE __MSABI_LONG(1400)
#define ERROR_INVALID_MENU_HANDLE __MSABI_LONG(1401)
#define ERROR_INVALID_CURSOR_HANDLE __MSABI_LONG(1402)
#define ERROR_INVALID_ACCEL_HANDLE __MSABI_LONG(1403)
#define ERROR_INVALID_HOOK_HANDLE __MSABI_LONG(1404)
#define ERROR_INVALID_DWP_HANDLE __MSABI_LONG(1405)
#define ERROR_TLW_WITH_WSCHILD __MSABI_LONG(1406)
#define ERROR_CANNOT_FIND_WND_CLASS __MSABI_LONG(1407)
#define ERROR_WINDOW_OF_OTHER_THREAD __MSABI_LONG(1408)
#define ERROR_HOTKEY_ALREADY_REGISTERED __MSABI_LONG(1409)
#define ERROR_CLASS_ALREADY_EXISTS __MSABI_LONG(1410)
#define ERROR_CLASS_DOES_NOT_EXIST __MSABI_LONG(1411)
#define ERROR_CLASS_HAS_WINDOWS __MSABI_LONG(1412)
#define ERROR_INVALID_INDEX __MSABI_LONG(1413)
#define ERROR_INVALID_ICON_HANDLE __MSABI_LONG(1414)
#define ERROR_PRIVATE_DIALOG_INDEX __MSABI_LONG(1415)
#define ERROR_LISTBOX_ID_NOT_FOUND __MSABI_LONG(1416)
#define ERROR_NO_WILDCARD_CHARACTERS __MSABI_LONG(1417)
#define ERROR_CLIPBOARD_NOT_OPEN __MSABI_LONG(1418)
#define ERROR_HOTKEY_NOT_REGISTERED __MSABI_LONG(1419)
#define ERROR_WINDOW_NOT_DIALOG __MSABI_LONG(1420)
#define ERROR_CONTROL_ID_NOT_FOUND __MSABI_LONG(1421)
#define ERROR_INVALID_COMBOBOX_MESSAGE __MSABI_LONG(1422)
#define ERROR_WINDOW_NOT_COMBOBOX __MSABI_LONG(1423)
#define ERROR_INVALID_EDIT_HEIGHT __MSABI_LONG(1424)
#define ERROR_DC_NOT_FOUND __MSABI_LONG(1425)
#define ERROR_INVALID_HOOK_FILTER __MSABI_LONG(1426)
#define ERROR_INVALID_FILTER_PROC __MSABI_LONG(1427)
#define ERROR_HOOK_NEEDS_HMOD __MSABI_LONG(1428)
#define ERROR_GLOBAL_ONLY_HOOK __MSABI_LONG(1429)
#define ERROR_JOURNAL_HOOK_SET __MSABI_LONG(1430)
#define ERROR_HOOK_NOT_INSTALLED __MSABI_LONG(1431)
#define ERROR_INVALID_LB_MESSAGE __MSABI_LONG(1432)
#define ERROR_SETCOUNT_ON_BAD_LB __MSABI_LONG(1433)
#define ERROR_LB_WITHOUT_TABSTOPS __MSABI_LONG(1434)
#define ERROR_DESTROY_OBJECT_OF_OTHER_THREAD __MSABI_LONG(1435)
#define ERROR_CHILD_WINDOW_MENU __MSABI_LONG(1436)
#define ERROR_NO_SYSTEM_MENU __MSABI_LONG(1437)
#define ERROR_INVALID_MSGBOX_STYLE __MSABI_LONG(1438)
#define ERROR_INVALID_SPI_VALUE __MSABI_LONG(1439)
#define ERROR_SCREEN_ALREADY_LOCKED __MSABI_LONG(1440)
#define ERROR_HWNDS_HAVE_DIFF_PARENT __MSABI_LONG(1441)
#define ERROR_NOT_CHILD_WINDOW __MSABI_LONG(1442)
#define ERROR_INVALID_GW_COMMAND __MSABI_LONG(1443)
#define ERROR_INVALID_THREAD_ID __MSABI_LONG(1444)
#define ERROR_NON_MDICHILD_WINDOW __MSABI_LONG(1445)
#define ERROR_POPUP_ALREADY_ACTIVE __MSABI_LONG(1446)
#define ERROR_NO_SCROLLBARS __MSABI_LONG(1447)
#define ERROR_INVALID_SCROLLBAR_RANGE __MSABI_LONG(1448)
#define ERROR_INVALID_SHOWWIN_COMMAND __MSABI_LONG(1449)
#define ERROR_NO_SYSTEM_RESOURCES __MSABI_LONG(1450)
#define ERROR_NONPAGED_SYSTEM_RESOURCES __MSABI_LONG(1451)
#define ERROR_PAGED_SYSTEM_RESOURCES __MSABI_LONG(1452)
#define ERROR_WORKING_SET_QUOTA __MSABI_LONG(1453)
#define ERROR_PAGEFILE_QUOTA __MSABI_LONG(1454)
#define ERROR_COMMITMENT_LIMIT __MSABI_LONG(1455)
#define ERROR_MENU_ITEM_NOT_FOUND __MSABI_LONG(1456)
#define ERROR_INVALID_KEYBOARD_HANDLE __MSABI_LONG(1457)
#define ERROR_HOOK_TYPE_NOT_ALLOWED __MSABI_LONG(1458)
#define ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION __MSABI_LONG(1459)
#define ERROR_TIMEOUT __MSABI_LONG(1460)
#define ERROR_INVALID_MONITOR_HANDLE __MSABI_LONG(1461)
#define ERROR_INCORRECT_SIZE __MSABI_LONG(1462)
#define ERROR_EVENTLOG_FILE_CORRUPT __MSABI_LONG(1500)
#define ERROR_EVENTLOG_CANT_START __MSABI_LONG(1501)
#define ERROR_LOG_FILE_FULL __MSABI_LONG(1502)
#define ERROR_EVENTLOG_FILE_CHANGED __MSABI_LONG(1503)
#define ERROR_INSTALL_SERVICE_FAILURE __MSABI_LONG(1601)
#define ERROR_INSTALL_USEREXIT __MSABI_LONG(1602)
#define ERROR_INSTALL_FAILURE __MSABI_LONG(1603)
#define ERROR_INSTALL_SUSPEND __MSABI_LONG(1604)
#define ERROR_UNKNOWN_PRODUCT __MSABI_LONG(1605)
#define ERROR_UNKNOWN_FEATURE __MSABI_LONG(1606)
#define ERROR_UNKNOWN_COMPONENT __MSABI_LONG(1607)
#define ERROR_UNKNOWN_PROPERTY __MSABI_LONG(1608)
#define ERROR_INVALID_HANDLE_STATE __MSABI_LONG(1609)
#define ERROR_BAD_CONFIGURATION __MSABI_LONG(1610)
#define ERROR_INDEX_ABSENT __MSABI_LONG(1611)
#define ERROR_INSTALL_SOURCE_ABSENT __MSABI_LONG(1612)
#define ERROR_INSTALL_PACKAGE_VERSION __MSABI_LONG(1613)
#define ERROR_PRODUCT_UNINSTALLED __MSABI_LONG(1614)
#define ERROR_BAD_QUERY_SYNTAX __MSABI_LONG(1615)
#define ERROR_INVALID_FIELD __MSABI_LONG(1616)
#define ERROR_DEVICE_REMOVED __MSABI_LONG(1617)
#define ERROR_INSTALL_ALREADY_RUNNING __MSABI_LONG(1618)
#define ERROR_INSTALL_PACKAGE_OPEN_FAILED __MSABI_LONG(1619)
#define ERROR_INSTALL_PACKAGE_INVALID __MSABI_LONG(1620)
#define ERROR_INSTALL_UI_FAILURE __MSABI_LONG(1621)
#define ERROR_INSTALL_LOG_FAILURE __MSABI_LONG(1622)
#define ERROR_INSTALL_LANGUAGE_UNSUPPORTED __MSABI_LONG(1623)
#define ERROR_INSTALL_TRANSFORM_FAILURE __MSABI_LONG(1624)
#define ERROR_INSTALL_PACKAGE_REJECTED __MSABI_LONG(1625)
#define ERROR_FUNCTION_NOT_CALLED __MSABI_LONG(1626)
#define ERROR_FUNCTION_FAILED __MSABI_LONG(1627)
#define ERROR_INVALID_TABLE __MSABI_LONG(1628)
#define ERROR_DATATYPE_MISMATCH __MSABI_LONG(1629)
#define ERROR_UNSUPPORTED_TYPE __MSABI_LONG(1630)
#define ERROR_CREATE_FAILED __MSABI_LONG(1631)
#define ERROR_INSTALL_TEMP_UNWRITABLE __MSABI_LONG(1632)
#define ERROR_INSTALL_PLATFORM_UNSUPPORTED __MSABI_LONG(1633)
#define ERROR_INSTALL_NOTUSED __MSABI_LONG(1634)
#define ERROR_PATCH_PACKAGE_OPEN_FAILED __MSABI_LONG(1635)
#define ERROR_PATCH_PACKAGE_INVALID __MSABI_LONG(1636)
#define ERROR_PATCH_PACKAGE_UNSUPPORTED __MSABI_LONG(1637)
#define ERROR_PRODUCT_VERSION __MSABI_LONG(1638)
#define ERROR_INVALID_COMMAND_LINE __MSABI_LONG(1639)
#define ERROR_INSTALL_REMOTE_DISALLOWED __MSABI_LONG(1640)
#define ERROR_SUCCESS_REBOOT_INITIATED __MSABI_LONG(1641)
#define ERROR_PATCH_TARGET_NOT_FOUND __MSABI_LONG(1642)
#define ERROR_PATCH_PACKAGE_REJECTED __MSABI_LONG(1643)
#define ERROR_INSTALL_TRANSFORM_REJECTED __MSABI_LONG(1644)
#define ERROR_INSTALL_REMOTE_PROHIBITED __MSABI_LONG(1645)
#define RPC_S_INVALID_STRING_BINDING __MSABI_LONG(1700)
#define RPC_S_WRONG_KIND_OF_BINDING __MSABI_LONG(1701)
#define RPC_S_INVALID_BINDING __MSABI_LONG(1702)
#define RPC_S_PROTSEQ_NOT_SUPPORTED __MSABI_LONG(1703)
#define RPC_S_INVALID_RPC_PROTSEQ __MSABI_LONG(1704)
#define RPC_S_INVALID_STRING_UUID __MSABI_LONG(1705)
#define RPC_S_INVALID_ENDPOINT_FORMAT __MSABI_LONG(1706)
#define RPC_S_INVALID_NET_ADDR __MSABI_LONG(1707)
#define RPC_S_NO_ENDPOINT_FOUND __MSABI_LONG(1708)
#define RPC_S_INVALID_TIMEOUT __MSABI_LONG(1709)
#define RPC_S_OBJECT_NOT_FOUND __MSABI_LONG(1710)
#define RPC_S_ALREADY_REGISTERED __MSABI_LONG(1711)
#define RPC_S_TYPE_ALREADY_REGISTERED __MSABI_LONG(1712)
#define RPC_S_ALREADY_LISTENING __MSABI_LONG(1713)
#define RPC_S_NO_PROTSEQS_REGISTERED __MSABI_LONG(1714)
#define RPC_S_NOT_LISTENING __MSABI_LONG(1715)
#define RPC_S_UNKNOWN_MGR_TYPE __MSABI_LONG(1716)
#define RPC_S_UNKNOWN_IF __MSABI_LONG(1717)
#define RPC_S_NO_BINDINGS __MSABI_LONG(1718)
#define RPC_S_NO_PROTSEQS __MSABI_LONG(1719)
#define RPC_S_CANT_CREATE_ENDPOINT __MSABI_LONG(1720)
#define RPC_S_OUT_OF_RESOURCES __MSABI_LONG(1721)
#define RPC_S_SERVER_UNAVAILABLE __MSABI_LONG(1722)
#define RPC_S_SERVER_TOO_BUSY __MSABI_LONG(1723)
#define RPC_S_INVALID_NETWORK_OPTIONS __MSABI_LONG(1724)
#define RPC_S_NO_CALL_ACTIVE __MSABI_LONG(1725)
#define RPC_S_CALL_FAILED __MSABI_LONG(1726)
#define RPC_S_CALL_FAILED_DNE __MSABI_LONG(1727)
#define RPC_S_PROTOCOL_ERROR __MSABI_LONG(1728)
#define RPC_S_UNSUPPORTED_TRANS_SYN __MSABI_LONG(1730)
#define RPC_S_UNSUPPORTED_TYPE __MSABI_LONG(1732)
#define RPC_S_INVALID_TAG __MSABI_LONG(1733)
#define RPC_S_INVALID_BOUND __MSABI_LONG(1734)
#define RPC_S_NO_ENTRY_NAME __MSABI_LONG(1735)
#define RPC_S_INVALID_NAME_SYNTAX __MSABI_LONG(1736)
#define RPC_S_UNSUPPORTED_NAME_SYNTAX __MSABI_LONG(1737)
#define RPC_S_UUID_NO_ADDRESS __MSABI_LONG(1739)
#define RPC_S_DUPLICATE_ENDPOINT __MSABI_LONG(1740)
#define RPC_S_UNKNOWN_AUTHN_TYPE __MSABI_LONG(1741)
#define RPC_S_MAX_CALLS_TOO_SMALL __MSABI_LONG(1742)
#define RPC_S_STRING_TOO_LONG __MSABI_LONG(1743)
#define RPC_S_PROTSEQ_NOT_FOUND __MSABI_LONG(1744)
#define RPC_S_PROCNUM_OUT_OF_RANGE __MSABI_LONG(1745)
#define RPC_S_BINDING_HAS_NO_AUTH __MSABI_LONG(1746)
#define RPC_S_UNKNOWN_AUTHN_SERVICE __MSABI_LONG(1747)
#define RPC_S_UNKNOWN_AUTHN_LEVEL __MSABI_LONG(1748)
#define RPC_S_INVALID_AUTH_IDENTITY __MSABI_LONG(1749)
#define RPC_S_UNKNOWN_AUTHZ_SERVICE __MSABI_LONG(1750)
#define EPT_S_INVALID_ENTRY __MSABI_LONG(1751)
#define EPT_S_CANT_PERFORM_OP __MSABI_LONG(1752)
#define EPT_S_NOT_REGISTERED __MSABI_LONG(1753)
#define RPC_S_NOTHING_TO_EXPORT __MSABI_LONG(1754)
#define RPC_S_INCOMPLETE_NAME __MSABI_LONG(1755)
#define RPC_S_INVALID_VERS_OPTION __MSABI_LONG(1756)
#define RPC_S_NO_MORE_MEMBERS __MSABI_LONG(1757)
#define RPC_S_NOT_ALL_OBJS_UNEXPORTED __MSABI_LONG(1758)
#define RPC_S_INTERFACE_NOT_FOUND __MSABI_LONG(1759)
#define RPC_S_ENTRY_ALREADY_EXISTS __MSABI_LONG(1760)
#define RPC_S_ENTRY_NOT_FOUND __MSABI_LONG(1761)
#define RPC_S_NAME_SERVICE_UNAVAILABLE __MSABI_LONG(1762)
#define RPC_S_INVALID_NAF_ID __MSABI_LONG(1763)
#define RPC_S_CANNOT_SUPPORT __MSABI_LONG(1764)
#define RPC_S_NO_CONTEXT_AVAILABLE __MSABI_LONG(1765)
#define RPC_S_INTERNAL_ERROR __MSABI_LONG(1766)
#define RPC_S_ZERO_DIVIDE __MSABI_LONG(1767)
#define RPC_S_ADDRESS_ERROR __MSABI_LONG(1768)
#define RPC_S_FP_DIV_ZERO __MSABI_LONG(1769)
#define RPC_S_FP_UNDERFLOW __MSABI_LONG(1770)
#define RPC_S_FP_OVERFLOW __MSABI_LONG(1771)
#define RPC_X_NO_MORE_ENTRIES __MSABI_LONG(1772)
#define RPC_X_SS_CHAR_TRANS_OPEN_FAIL __MSABI_LONG(1773)
#define RPC_X_SS_CHAR_TRANS_SHORT_FILE __MSABI_LONG(1774)
#define RPC_X_SS_IN_NULL_CONTEXT __MSABI_LONG(1775)
#define RPC_X_SS_CONTEXT_DAMAGED __MSABI_LONG(1777)
#define RPC_X_SS_HANDLES_MISMATCH __MSABI_LONG(1778)
#define RPC_X_SS_CANNOT_GET_CALL_HANDLE __MSABI_LONG(1779)
#define RPC_X_NULL_REF_POINTER __MSABI_LONG(1780)
#define RPC_X_ENUM_VALUE_OUT_OF_RANGE __MSABI_LONG(1781)
#define RPC_X_BYTE_COUNT_TOO_SMALL __MSABI_LONG(1782)
#define RPC_X_BAD_STUB_DATA __MSABI_LONG(1783)
#define ERROR_INVALID_USER_BUFFER __MSABI_LONG(1784)
#define ERROR_UNRECOGNIZED_MEDIA __MSABI_LONG(1785)
#define ERROR_NO_TRUST_LSA_SECRET __MSABI_LONG(1786)
#define ERROR_NO_TRUST_SAM_ACCOUNT __MSABI_LONG(1787)
#define ERROR_TRUSTED_DOMAIN_FAILURE __MSABI_LONG(1788)
#define ERROR_TRUSTED_RELATIONSHIP_FAILURE __MSABI_LONG(1789)
#define ERROR_TRUST_FAILURE __MSABI_LONG(1790)
#define RPC_S_CALL_IN_PROGRESS __MSABI_LONG(1791)
#define ERROR_NETLOGON_NOT_STARTED __MSABI_LONG(1792)
#define ERROR_ACCOUNT_EXPIRED __MSABI_LONG(1793)
#define ERROR_REDIRECTOR_HAS_OPEN_HANDLES __MSABI_LONG(1794)
#define ERROR_PRINTER_DRIVER_ALREADY_INSTALLED __MSABI_LONG(1795)
#define ERROR_UNKNOWN_PORT __MSABI_LONG(1796)
#define ERROR_UNKNOWN_PRINTER_DRIVER __MSABI_LONG(1797)
#define ERROR_UNKNOWN_PRINTPROCESSOR __MSABI_LONG(1798)
#define ERROR_INVALID_SEPARATOR_FILE __MSABI_LONG(1799)
#define ERROR_INVALID_PRIORITY __MSABI_LONG(1800)
#define ERROR_INVALID_PRINTER_NAME __MSABI_LONG(1801)
#define ERROR_PRINTER_ALREADY_EXISTS __MSABI_LONG(1802)
#define ERROR_INVALID_PRINTER_COMMAND __MSABI_LONG(1803)
#define ERROR_INVALID_DATATYPE __MSABI_LONG(1804)
#define ERROR_INVALID_ENVIRONMENT __MSABI_LONG(1805)
#define RPC_S_NO_MORE_BINDINGS __MSABI_LONG(1806)
#define ERROR_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT __MSABI_LONG(1807)
#define ERROR_NOLOGON_WORKSTATION_TRUST_ACCOUNT __MSABI_LONG(1808)
#define ERROR_NOLOGON_SERVER_TRUST_ACCOUNT __MSABI_LONG(1809)
#define ERROR_DOMAIN_TRUST_INCONSISTENT __MSABI_LONG(1810)
#define ERROR_SERVER_HAS_OPEN_HANDLES __MSABI_LONG(1811)
#define ERROR_RESOURCE_DATA_NOT_FOUND __MSABI_LONG(1812)
#define ERROR_RESOURCE_TYPE_NOT_FOUND __MSABI_LONG(1813)
#define ERROR_RESOURCE_NAME_NOT_FOUND __MSABI_LONG(1814)
#define ERROR_RESOURCE_LANG_NOT_FOUND __MSABI_LONG(1815)
#define ERROR_NOT_ENOUGH_QUOTA __MSABI_LONG(1816)
#define RPC_S_NO_INTERFACES __MSABI_LONG(1817)
#define RPC_S_CALL_CANCELLED __MSABI_LONG(1818)
#define RPC_S_BINDING_INCOMPLETE __MSABI_LONG(1819)
#define RPC_S_COMM_FAILURE __MSABI_LONG(1820)
#define RPC_S_UNSUPPORTED_AUTHN_LEVEL __MSABI_LONG(1821)
#define RPC_S_NO_PRINC_NAME __MSABI_LONG(1822)
#define RPC_S_NOT_RPC_ERROR __MSABI_LONG(1823)
#define RPC_S_UUID_LOCAL_ONLY __MSABI_LONG(1824)
#define RPC_S_SEC_PKG_ERROR __MSABI_LONG(1825)
#define RPC_S_NOT_CANCELLED __MSABI_LONG(1826)
#define RPC_X_INVALID_ES_ACTION __MSABI_LONG(1827)
#define RPC_X_WRONG_ES_VERSION __MSABI_LONG(1828)
#define RPC_X_WRONG_STUB_VERSION __MSABI_LONG(1829)
#define RPC_X_INVALID_PIPE_OBJECT __MSABI_LONG(1830)
#define RPC_X_WRONG_PIPE_ORDER __MSABI_LONG(1831)
#define RPC_X_WRONG_PIPE_VERSION __MSABI_LONG(1832)
#define RPC_S_GROUP_MEMBER_NOT_FOUND __MSABI_LONG(1898)
#define EPT_S_CANT_CREATE __MSABI_LONG(1899)
#define RPC_S_INVALID_OBJECT __MSABI_LONG(1900)
#define ERROR_INVALID_TIME __MSABI_LONG(1901)
#define ERROR_INVALID_FORM_NAME __MSABI_LONG(1902)
#define ERROR_INVALID_FORM_SIZE __MSABI_LONG(1903)
#define ERROR_ALREADY_WAITING __MSABI_LONG(1904)
#define ERROR_PRINTER_DELETED __MSABI_LONG(1905)
#define ERROR_INVALID_PRINTER_STATE __MSABI_LONG(1906)
#define ERROR_PASSWORD_MUST_CHANGE __MSABI_LONG(1907)
#define ERROR_DOMAIN_CONTROLLER_NOT_FOUND __MSABI_LONG(1908)
#define ERROR_ACCOUNT_LOCKED_OUT __MSABI_LONG(1909)
#define OR_INVALID_OXID __MSABI_LONG(1910)
#define OR_INVALID_OID __MSABI_LONG(1911)
#define OR_INVALID_SET __MSABI_LONG(1912)
#define RPC_S_SEND_INCOMPLETE __MSABI_LONG(1913)
#define RPC_S_INVALID_ASYNC_HANDLE __MSABI_LONG(1914)
#define RPC_S_INVALID_ASYNC_CALL __MSABI_LONG(1915)
#define RPC_X_PIPE_CLOSED __MSABI_LONG(1916)
#define RPC_X_PIPE_DISCIPLINE_ERROR __MSABI_LONG(1917)
#define RPC_X_PIPE_EMPTY __MSABI_LONG(1918)
#define ERROR_NO_SITENAME __MSABI_LONG(1919)
#define ERROR_CANT_ACCESS_FILE __MSABI_LONG(1920)
#define ERROR_CANT_RESOLVE_FILENAME __MSABI_LONG(1921)
#define RPC_S_ENTRY_TYPE_MISMATCH __MSABI_LONG(1922)
#define RPC_S_NOT_ALL_OBJS_EXPORTED __MSABI_LONG(1923)
#define RPC_S_INTERFACE_NOT_EXPORTED __MSABI_LONG(1924)
#define RPC_S_PROFILE_NOT_ADDED __MSABI_LONG(1925)
#define RPC_S_PRF_ELT_NOT_ADDED __MSABI_LONG(1926)
#define RPC_S_PRF_ELT_NOT_REMOVED __MSABI_LONG(1927)
#define RPC_S_GRP_ELT_NOT_ADDED __MSABI_LONG(1928)
#define RPC_S_GRP_ELT_NOT_REMOVED __MSABI_LONG(1929)
#define ERROR_KM_DRIVER_BLOCKED __MSABI_LONG(1930)
#define ERROR_CONTEXT_EXPIRED __MSABI_LONG(1931)
#define ERROR_PER_USER_TRUST_QUOTA_EXCEEDED __MSABI_LONG(1932)
#define ERROR_ALL_USER_TRUST_QUOTA_EXCEEDED __MSABI_LONG(1933)
#define ERROR_USER_DELETE_TRUST_QUOTA_EXCEEDED __MSABI_LONG(1934)
#define ERROR_AUTHENTICATION_FIREWALL_FAILED __MSABI_LONG(1935)
#define ERROR_REMOTE_PRINT_CONNECTIONS_BLOCKED __MSABI_LONG(1936)
#define ERROR_INVALID_PIXEL_FORMAT __MSABI_LONG(2000)
#define ERROR_BAD_DRIVER __MSABI_LONG(2001)
#define ERROR_INVALID_WINDOW_STYLE __MSABI_LONG(2002)
#define ERROR_METAFILE_NOT_SUPPORTED __MSABI_LONG(2003)
#define ERROR_TRANSFORM_NOT_SUPPORTED __MSABI_LONG(2004)
#define ERROR_CLIPPING_NOT_SUPPORTED __MSABI_LONG(2005)
#define ERROR_INVALID_CMM __MSABI_LONG(2010)
#define ERROR_INVALID_PROFILE __MSABI_LONG(2011)
#define ERROR_TAG_NOT_FOUND __MSABI_LONG(2012)
#define ERROR_TAG_NOT_PRESENT __MSABI_LONG(2013)
#define ERROR_DUPLICATE_TAG __MSABI_LONG(2014)
#define ERROR_PROFILE_NOT_ASSOCIATED_WITH_DEVICE __MSABI_LONG(2015)
#define ERROR_PROFILE_NOT_FOUND __MSABI_LONG(2016)
#define ERROR_INVALID_COLORSPACE __MSABI_LONG(2017)
#define ERROR_ICM_NOT_ENABLED __MSABI_LONG(2018)
#define ERROR_DELETING_ICM_XFORM __MSABI_LONG(2019)
#define ERROR_INVALID_TRANSFORM __MSABI_LONG(2020)
#define ERROR_COLORSPACE_MISMATCH __MSABI_LONG(2021)
#define ERROR_INVALID_COLORINDEX __MSABI_LONG(2022)
#define ERROR_CONNECTED_OTHER_PASSWORD __MSABI_LONG(2108)
#define ERROR_CONNECTED_OTHER_PASSWORD_DEFAULT __MSABI_LONG(2109)
#define ERROR_BAD_USERNAME __MSABI_LONG(2202)
#define ERROR_NOT_CONNECTED __MSABI_LONG(2250)
#define ERROR_OPEN_FILES __MSABI_LONG(2401)
#define ERROR_ACTIVE_CONNECTIONS __MSABI_LONG(2402)
#define ERROR_DEVICE_IN_USE __MSABI_LONG(2404)
#define ERROR_UNKNOWN_PRINT_MONITOR __MSABI_LONG(3000)
#define ERROR_PRINTER_DRIVER_IN_USE __MSABI_LONG(3001)
#define ERROR_SPOOL_FILE_NOT_FOUND __MSABI_LONG(3002)
#define ERROR_SPL_NO_STARTDOC __MSABI_LONG(3003)
#define ERROR_SPL_NO_ADDJOB __MSABI_LONG(3004)
#define ERROR_PRINT_PROCESSOR_ALREADY_INSTALLED __MSABI_LONG(3005)
#define ERROR_PRINT_MONITOR_ALREADY_INSTALLED __MSABI_LONG(3006)
#define ERROR_INVALID_PRINT_MONITOR __MSABI_LONG(3007)
#define ERROR_PRINT_MONITOR_IN_USE __MSABI_LONG(3008)
#define ERROR_PRINTER_HAS_JOBS_QUEUED __MSABI_LONG(3009)
#define ERROR_SUCCESS_REBOOT_REQUIRED __MSABI_LONG(3010)
#define ERROR_SUCCESS_RESTART_REQUIRED __MSABI_LONG(3011)
#define ERROR_PRINTER_NOT_FOUND __MSABI_LONG(3012)
#define ERROR_PRINTER_DRIVER_WARNED __MSABI_LONG(3013)
#define ERROR_PRINTER_DRIVER_BLOCKED __MSABI_LONG(3014)
#define ERROR_WINS_INTERNAL __MSABI_LONG(4000)
#define ERROR_CAN_NOT_DEL_LOCAL_WINS __MSABI_LONG(4001)
#define ERROR_STATIC_INIT __MSABI_LONG(4002)
#define ERROR_INC_BACKUP __MSABI_LONG(4003)
#define ERROR_FULL_BACKUP __MSABI_LONG(4004)
#define ERROR_REC_NON_EXISTENT __MSABI_LONG(4005)
#define ERROR_RPL_NOT_ALLOWED __MSABI_LONG(4006)
#define ERROR_DHCP_ADDRESS_CONFLICT __MSABI_LONG(4100)
#define ERROR_WMI_GUID_NOT_FOUND __MSABI_LONG(4200)
#define ERROR_WMI_INSTANCE_NOT_FOUND __MSABI_LONG(4201)
#define ERROR_WMI_ITEMID_NOT_FOUND __MSABI_LONG(4202)
#define ERROR_WMI_TRY_AGAIN __MSABI_LONG(4203)
#define ERROR_WMI_DP_NOT_FOUND __MSABI_LONG(4204)
#define ERROR_WMI_UNRESOLVED_INSTANCE_REF __MSABI_LONG(4205)
#define ERROR_WMI_ALREADY_ENABLED __MSABI_LONG(4206)
#define ERROR_WMI_GUID_DISCONNECTED __MSABI_LONG(4207)
#define ERROR_WMI_SERVER_UNAVAILABLE __MSABI_LONG(4208)
#define ERROR_WMI_DP_FAILED __MSABI_LONG(4209)
#define ERROR_WMI_INVALID_MOF __MSABI_LONG(4210)
#define ERROR_WMI_INVALID_REGINFO __MSABI_LONG(4211)
#define ERROR_WMI_ALREADY_DISABLED __MSABI_LONG(4212)
#define ERROR_WMI_READ_ONLY __MSABI_LONG(4213)
#define ERROR_WMI_SET_FAILURE __MSABI_LONG(4214)
#define ERROR_INVALID_MEDIA __MSABI_LONG(4300)
#define ERROR_INVALID_LIBRARY __MSABI_LONG(4301)
#define ERROR_INVALID_MEDIA_POOL __MSABI_LONG(4302)
#define ERROR_DRIVE_MEDIA_MISMATCH __MSABI_LONG(4303)
#define ERROR_MEDIA_OFFLINE __MSABI_LONG(4304)
#define ERROR_LIBRARY_OFFLINE __MSABI_LONG(4305)
#define ERROR_EMPTY __MSABI_LONG(4306)
#define ERROR_NOT_EMPTY __MSABI_LONG(4307)
#define ERROR_MEDIA_UNAVAILABLE __MSABI_LONG(4308)
#define ERROR_RESOURCE_DISABLED __MSABI_LONG(4309)
#define ERROR_INVALID_CLEANER __MSABI_LONG(4310)
#define ERROR_UNABLE_TO_CLEAN __MSABI_LONG(4311)
#define ERROR_OBJECT_NOT_FOUND __MSABI_LONG(4312)
#define ERROR_DATABASE_FAILURE __MSABI_LONG(4313)
#define ERROR_DATABASE_FULL __MSABI_LONG(4314)
#define ERROR_MEDIA_INCOMPATIBLE __MSABI_LONG(4315)
#define ERROR_RESOURCE_NOT_PRESENT __MSABI_LONG(4316)
#define ERROR_INVALID_OPERATION __MSABI_LONG(4317)
#define ERROR_MEDIA_NOT_AVAILABLE __MSABI_LONG(4318)
#define ERROR_DEVICE_NOT_AVAILABLE __MSABI_LONG(4319)
#define ERROR_REQUEST_REFUSED __MSABI_LONG(4320)
#define ERROR_INVALID_DRIVE_OBJECT __MSABI_LONG(4321)
#define ERROR_LIBRARY_FULL __MSABI_LONG(4322)
#define ERROR_MEDIUM_NOT_ACCESSIBLE __MSABI_LONG(4323)
#define ERROR_UNABLE_TO_LOAD_MEDIUM __MSABI_LONG(4324)
#define ERROR_UNABLE_TO_INVENTORY_DRIVE __MSABI_LONG(4325)
#define ERROR_UNABLE_TO_INVENTORY_SLOT __MSABI_LONG(4326)
#define ERROR_UNABLE_TO_INVENTORY_TRANSPORT __MSABI_LONG(4327)
#define ERROR_TRANSPORT_FULL __MSABI_LONG(4328)
#define ERROR_CONTROLLING_IEPORT __MSABI_LONG(4329)
#define ERROR_UNABLE_TO_EJECT_MOUNTED_MEDIA __MSABI_LONG(4330)
#define ERROR_CLEANER_SLOT_SET __MSABI_LONG(4331)
#define ERROR_CLEANER_SLOT_NOT_SET __MSABI_LONG(4332)
#define ERROR_CLEANER_CARTRIDGE_SPENT __MSABI_LONG(4333)
#define ERROR_UNEXPECTED_OMID __MSABI_LONG(4334)
#define ERROR_CANT_DELETE_LAST_ITEM __MSABI_LONG(4335)
#define ERROR_MESSAGE_EXCEEDS_MAX_SIZE __MSABI_LONG(4336)
#define ERROR_VOLUME_CONTAINS_SYS_FILES __MSABI_LONG(4337)
#define ERROR_INDIGENOUS_TYPE __MSABI_LONG(4338)
#define ERROR_NO_SUPPORTING_DRIVES __MSABI_LONG(4339)
#define ERROR_CLEANER_CARTRIDGE_INSTALLED __MSABI_LONG(4340)
#define ERROR_IEPORT_FULL __MSABI_LONG(4341)
#define ERROR_FILE_OFFLINE __MSABI_LONG(4350)
#define ERROR_REMOTE_STORAGE_NOT_ACTIVE __MSABI_LONG(4351)
#define ERROR_REMOTE_STORAGE_MEDIA_ERROR __MSABI_LONG(4352)
#define ERROR_NOT_A_REPARSE_POINT __MSABI_LONG(4390)
#define ERROR_REPARSE_ATTRIBUTE_CONFLICT __MSABI_LONG(4391)
#define ERROR_INVALID_REPARSE_DATA __MSABI_LONG(4392)
#define ERROR_REPARSE_TAG_INVALID __MSABI_LONG(4393)
#define ERROR_REPARSE_TAG_MISMATCH __MSABI_LONG(4394)
#define ERROR_VOLUME_NOT_SIS_ENABLED __MSABI_LONG(4500)
#define ERROR_DEPENDENT_RESOURCE_EXISTS __MSABI_LONG(5001)
#define ERROR_DEPENDENCY_NOT_FOUND __MSABI_LONG(5002)
#define ERROR_DEPENDENCY_ALREADY_EXISTS __MSABI_LONG(5003)
#define ERROR_RESOURCE_NOT_ONLINE __MSABI_LONG(5004)
#define ERROR_HOST_NODE_NOT_AVAILABLE __MSABI_LONG(5005)
#define ERROR_RESOURCE_NOT_AVAILABLE __MSABI_LONG(5006)
#define ERROR_RESOURCE_NOT_FOUND __MSABI_LONG(5007)
#define ERROR_SHUTDOWN_CLUSTER __MSABI_LONG(5008)
#define ERROR_CANT_EVICT_ACTIVE_NODE __MSABI_LONG(5009)
#define ERROR_OBJECT_ALREADY_EXISTS __MSABI_LONG(5010)
#define ERROR_OBJECT_IN_LIST __MSABI_LONG(5011)
#define ERROR_GROUP_NOT_AVAILABLE __MSABI_LONG(5012)
#define ERROR_GROUP_NOT_FOUND __MSABI_LONG(5013)
#define ERROR_GROUP_NOT_ONLINE __MSABI_LONG(5014)
#define ERROR_HOST_NODE_NOT_RESOURCE_OWNER __MSABI_LONG(5015)
#define ERROR_HOST_NODE_NOT_GROUP_OWNER __MSABI_LONG(5016)
#define ERROR_RESMON_CREATE_FAILED __MSABI_LONG(5017)
#define ERROR_RESMON_ONLINE_FAILED __MSABI_LONG(5018)
#define ERROR_RESOURCE_ONLINE __MSABI_LONG(5019)
#define ERROR_QUORUM_RESOURCE __MSABI_LONG(5020)
#define ERROR_NOT_QUORUM_CAPABLE __MSABI_LONG(5021)
#define ERROR_CLUSTER_SHUTTING_DOWN __MSABI_LONG(5022)
#define ERROR_INVALID_STATE __MSABI_LONG(5023)
#define ERROR_RESOURCE_PROPERTIES_STORED __MSABI_LONG(5024)
#define ERROR_NOT_QUORUM_CLASS __MSABI_LONG(5025)
#define ERROR_CORE_RESOURCE __MSABI_LONG(5026)
#define ERROR_QUORUM_RESOURCE_ONLINE_FAILED __MSABI_LONG(5027)
#define ERROR_QUORUMLOG_OPEN_FAILED __MSABI_LONG(5028)
#define ERROR_CLUSTERLOG_CORRUPT __MSABI_LONG(5029)
#define ERROR_CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE __MSABI_LONG(5030)
#define ERROR_CLUSTERLOG_EXCEEDS_MAXSIZE __MSABI_LONG(5031)
#define ERROR_CLUSTERLOG_CHKPOINT_NOT_FOUND __MSABI_LONG(5032)
#define ERROR_CLUSTERLOG_NOT_ENOUGH_SPACE __MSABI_LONG(5033)
#define ERROR_QUORUM_OWNER_ALIVE __MSABI_LONG(5034)
#define ERROR_NETWORK_NOT_AVAILABLE __MSABI_LONG(5035)
#define ERROR_NODE_NOT_AVAILABLE __MSABI_LONG(5036)
#define ERROR_ALL_NODES_NOT_AVAILABLE __MSABI_LONG(5037)
#define ERROR_RESOURCE_FAILED __MSABI_LONG(5038)
#define ERROR_CLUSTER_INVALID_NODE __MSABI_LONG(5039)
#define ERROR_CLUSTER_NODE_EXISTS __MSABI_LONG(5040)
#define ERROR_CLUSTER_JOIN_IN_PROGRESS __MSABI_LONG(5041)
#define ERROR_CLUSTER_NODE_NOT_FOUND __MSABI_LONG(5042)
#define ERROR_CLUSTER_LOCAL_NODE_NOT_FOUND __MSABI_LONG(5043)
#define ERROR_CLUSTER_NETWORK_EXISTS __MSABI_LONG(5044)
#define ERROR_CLUSTER_NETWORK_NOT_FOUND __MSABI_LONG(5045)
#define ERROR_CLUSTER_NETINTERFACE_EXISTS __MSABI_LONG(5046)
#define ERROR_CLUSTER_NETINTERFACE_NOT_FOUND __MSABI_LONG(5047)
#define ERROR_CLUSTER_INVALID_REQUEST __MSABI_LONG(5048)
#define ERROR_CLUSTER_INVALID_NETWORK_PROVIDER __MSABI_LONG(5049)
#define ERROR_CLUSTER_NODE_DOWN __MSABI_LONG(5050)
#define ERROR_CLUSTER_NODE_UNREACHABLE __MSABI_LONG(5051)
#define ERROR_CLUSTER_NODE_NOT_MEMBER __MSABI_LONG(5052)
#define ERROR_CLUSTER_JOIN_NOT_IN_PROGRESS __MSABI_LONG(5053)
#define ERROR_CLUSTER_INVALID_NETWORK __MSABI_LONG(5054)
#define ERROR_CLUSTER_NODE_UP __MSABI_LONG(5056)
#define ERROR_CLUSTER_IPADDR_IN_USE __MSABI_LONG(5057)
#define ERROR_CLUSTER_NODE_NOT_PAUSED __MSABI_LONG(5058)
#define ERROR_CLUSTER_NO_SECURITY_CONTEXT __MSABI_LONG(5059)
#define ERROR_CLUSTER_NETWORK_NOT_INTERNAL __MSABI_LONG(5060)
#define ERROR_CLUSTER_NODE_ALREADY_UP __MSABI_LONG(5061)
#define ERROR_CLUSTER_NODE_ALREADY_DOWN __MSABI_LONG(5062)
#define ERROR_CLUSTER_NETWORK_ALREADY_ONLINE __MSABI_LONG(5063)
#define ERROR_CLUSTER_NETWORK_ALREADY_OFFLINE __MSABI_LONG(5064)
#define ERROR_CLUSTER_NODE_ALREADY_MEMBER __MSABI_LONG(5065)
#define ERROR_CLUSTER_LAST_INTERNAL_NETWORK __MSABI_LONG(5066)
#define ERROR_CLUSTER_NETWORK_HAS_DEPENDENTS __MSABI_LONG(5067)
#define ERROR_INVALID_OPERATION_ON_QUORUM __MSABI_LONG(5068)
#define ERROR_DEPENDENCY_NOT_ALLOWED __MSABI_LONG(5069)
#define ERROR_CLUSTER_NODE_PAUSED __MSABI_LONG(5070)
#define ERROR_NODE_CANT_HOST_RESOURCE __MSABI_LONG(5071)
#define ERROR_CLUSTER_NODE_NOT_READY __MSABI_LONG(5072)
#define ERROR_CLUSTER_NODE_SHUTTING_DOWN __MSABI_LONG(5073)
#define ERROR_CLUSTER_JOIN_ABORTED __MSABI_LONG(5074)
#define ERROR_CLUSTER_INCOMPATIBLE_VERSIONS __MSABI_LONG(5075)
#define ERROR_CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED __MSABI_LONG(5076)
#define ERROR_CLUSTER_SYSTEM_CONFIG_CHANGED __MSABI_LONG(5077)
#define ERROR_CLUSTER_RESOURCE_TYPE_NOT_FOUND __MSABI_LONG(5078)
#define ERROR_CLUSTER_RESTYPE_NOT_SUPPORTED __MSABI_LONG(5079)
#define ERROR_CLUSTER_RESNAME_NOT_FOUND __MSABI_LONG(5080)
#define ERROR_CLUSTER_NO_RPC_PACKAGES_REGISTERED __MSABI_LONG(5081)
#define ERROR_CLUSTER_OWNER_NOT_IN_PREFLIST __MSABI_LONG(5082)
#define ERROR_CLUSTER_DATABASE_SEQMISMATCH __MSABI_LONG(5083)
#define ERROR_RESMON_INVALID_STATE __MSABI_LONG(5084)
#define ERROR_CLUSTER_GUM_NOT_LOCKER __MSABI_LONG(5085)
#define ERROR_QUORUM_DISK_NOT_FOUND __MSABI_LONG(5086)
#define ERROR_DATABASE_BACKUP_CORRUPT __MSABI_LONG(5087)
#define ERROR_CLUSTER_NODE_ALREADY_HAS_DFS_ROOT __MSABI_LONG(5088)
#define ERROR_RESOURCE_PROPERTY_UNCHANGEABLE __MSABI_LONG(5089)
#define ERROR_CLUSTER_MEMBERSHIP_INVALID_STATE __MSABI_LONG(5890)
#define ERROR_CLUSTER_QUORUMLOG_NOT_FOUND __MSABI_LONG(5891)
#define ERROR_CLUSTER_MEMBERSHIP_HALT __MSABI_LONG(5892)
#define ERROR_CLUSTER_INSTANCE_ID_MISMATCH __MSABI_LONG(5893)
#define ERROR_CLUSTER_NETWORK_NOT_FOUND_FOR_IP __MSABI_LONG(5894)
#define ERROR_CLUSTER_PROPERTY_DATA_TYPE_MISMATCH __MSABI_LONG(5895)
#define ERROR_CLUSTER_EVICT_WITHOUT_CLEANUP __MSABI_LONG(5896)
#define ERROR_CLUSTER_PARAMETER_MISMATCH __MSABI_LONG(5897)
#define ERROR_NODE_CANNOT_BE_CLUSTERED __MSABI_LONG(5898)
#define ERROR_CLUSTER_WRONG_OS_VERSION __MSABI_LONG(5899)
#define ERROR_CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME __MSABI_LONG(5900)
#define ERROR_CLUSCFG_ALREADY_COMMITTED __MSABI_LONG(5901)
#define ERROR_CLUSCFG_ROLLBACK_FAILED __MSABI_LONG(5902)
#define ERROR_CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT __MSABI_LONG(5903)
#define ERROR_CLUSTER_OLD_VERSION __MSABI_LONG(5904)
#define ERROR_CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME __MSABI_LONG(5905)
#define ERROR_ENCRYPTION_FAILED __MSABI_LONG(6000)
#define ERROR_DECRYPTION_FAILED __MSABI_LONG(6001)
#define ERROR_FILE_ENCRYPTED __MSABI_LONG(6002)
#define ERROR_NO_RECOVERY_POLICY __MSABI_LONG(6003)
#define ERROR_NO_EFS __MSABI_LONG(6004)
#define ERROR_WRONG_EFS __MSABI_LONG(6005)
#define ERROR_NO_USER_KEYS __MSABI_LONG(6006)
#define ERROR_FILE_NOT_ENCRYPTED __MSABI_LONG(6007)
#define ERROR_NOT_EXPORT_FORMAT __MSABI_LONG(6008)
#define ERROR_FILE_READ_ONLY __MSABI_LONG(6009)
#define ERROR_DIR_EFS_DISALLOWED __MSABI_LONG(6010)
#define ERROR_EFS_SERVER_NOT_TRUSTED __MSABI_LONG(6011)
#define ERROR_BAD_RECOVERY_POLICY __MSABI_LONG(6012)
#define ERROR_EFS_ALG_BLOB_TOO_BIG __MSABI_LONG(6013)
#define ERROR_VOLUME_NOT_SUPPORT_EFS __MSABI_LONG(6014)
#define ERROR_EFS_DISABLED __MSABI_LONG(6015)
#define ERROR_EFS_VERSION_NOT_SUPPORT __MSABI_LONG(6016)
#define ERROR_NO_BROWSER_SERVERS_FOUND __MSABI_LONG(6118)
#define SCHED_E_SERVICE_NOT_LOCALSYSTEM __MSABI_LONG(6200)
#define ERROR_CTX_WINSTATION_NAME_INVALID __MSABI_LONG(7001)
#define ERROR_CTX_INVALID_PD __MSABI_LONG(7002)
#define ERROR_CTX_PD_NOT_FOUND __MSABI_LONG(7003)
#define ERROR_CTX_WD_NOT_FOUND __MSABI_LONG(7004)
#define ERROR_CTX_CANNOT_MAKE_EVENTLOG_ENTRY __MSABI_LONG(7005)
#define ERROR_CTX_SERVICE_NAME_COLLISION __MSABI_LONG(7006)
#define ERROR_CTX_CLOSE_PENDING __MSABI_LONG(7007)
#define ERROR_CTX_NO_OUTBUF __MSABI_LONG(7008)
#define ERROR_CTX_MODEM_INF_NOT_FOUND __MSABI_LONG(7009)
#define ERROR_CTX_INVALID_MODEMNAME __MSABI_LONG(7010)
#define ERROR_CTX_MODEM_RESPONSE_ERROR __MSABI_LONG(7011)
#define ERROR_CTX_MODEM_RESPONSE_TIMEOUT __MSABI_LONG(7012)
#define ERROR_CTX_MODEM_RESPONSE_NO_CARRIER __MSABI_LONG(7013)
#define ERROR_CTX_MODEM_RESPONSE_NO_DIALTONE __MSABI_LONG(7014)
#define ERROR_CTX_MODEM_RESPONSE_BUSY __MSABI_LONG(7015)
#define ERROR_CTX_MODEM_RESPONSE_VOICE __MSABI_LONG(7016)
#define ERROR_CTX_TD_ERROR __MSABI_LONG(7017)
#define ERROR_CTX_WINSTATION_NOT_FOUND __MSABI_LONG(7022)
#define ERROR_CTX_WINSTATION_ALREADY_EXISTS __MSABI_LONG(7023)
#define ERROR_CTX_WINSTATION_BUSY __MSABI_LONG(7024)
#define ERROR_CTX_BAD_VIDEO_MODE __MSABI_LONG(7025)
#define ERROR_CTX_GRAPHICS_INVALID __MSABI_LONG(7035)
#define ERROR_CTX_LOGON_DISABLED __MSABI_LONG(7037)
#define ERROR_CTX_NOT_CONSOLE __MSABI_LONG(7038)
#define ERROR_CTX_CLIENT_QUERY_TIMEOUT __MSABI_LONG(7040)
#define ERROR_CTX_CONSOLE_DISCONNECT __MSABI_LONG(7041)
#define ERROR_CTX_CONSOLE_CONNECT __MSABI_LONG(7042)
#define ERROR_CTX_SHADOW_DENIED __MSABI_LONG(7044)
#define ERROR_CTX_WINSTATION_ACCESS_DENIED __MSABI_LONG(7045)
#define ERROR_CTX_INVALID_WD __MSABI_LONG(7049)
#define ERROR_CTX_SHADOW_INVALID __MSABI_LONG(7050)
#define ERROR_CTX_SHADOW_DISABLED __MSABI_LONG(7051)
#define ERROR_CTX_CLIENT_LICENSE_IN_USE __MSABI_LONG(7052)
#define ERROR_CTX_CLIENT_LICENSE_NOT_SET __MSABI_LONG(7053)
#define ERROR_CTX_LICENSE_NOT_AVAILABLE __MSABI_LONG(7054)
#define ERROR_CTX_LICENSE_CLIENT_INVALID __MSABI_LONG(7055)
#define ERROR_CTX_LICENSE_EXPIRED __MSABI_LONG(7056)
#define ERROR_CTX_SHADOW_NOT_RUNNING __MSABI_LONG(7057)
#define ERROR_CTX_SHADOW_ENDED_BY_MODE_CHANGE __MSABI_LONG(7058)
#define ERROR_ACTIVATION_COUNT_EXCEEDED __MSABI_LONG(7059)
#define FRS_ERR_INVALID_API_SEQUENCE __MSABI_LONG(8001)
#define FRS_ERR_STARTING_SERVICE __MSABI_LONG(8002)
#define FRS_ERR_STOPPING_SERVICE __MSABI_LONG(8003)
#define FRS_ERR_INTERNAL_API __MSABI_LONG(8004)
#define FRS_ERR_INTERNAL __MSABI_LONG(8005)
#define FRS_ERR_SERVICE_COMM __MSABI_LONG(8006)
#define FRS_ERR_INSUFFICIENT_PRIV __MSABI_LONG(8007)
#define FRS_ERR_AUTHENTICATION __MSABI_LONG(8008)
#define FRS_ERR_PARENT_INSUFFICIENT_PRIV __MSABI_LONG(8009)
#define FRS_ERR_PARENT_AUTHENTICATION __MSABI_LONG(8010)
#define FRS_ERR_CHILD_TO_PARENT_COMM __MSABI_LONG(8011)
#define FRS_ERR_PARENT_TO_CHILD_COMM __MSABI_LONG(8012)
#define FRS_ERR_SYSVOL_POPULATE __MSABI_LONG(8013)
#define FRS_ERR_SYSVOL_POPULATE_TIMEOUT __MSABI_LONG(8014)
#define FRS_ERR_SYSVOL_IS_BUSY __MSABI_LONG(8015)
#define FRS_ERR_SYSVOL_DEMOTE __MSABI_LONG(8016)
#define FRS_ERR_INVALID_SERVICE_PARAMETER __MSABI_LONG(8017)
#define DS_S_SUCCESS NO_ERROR
#define ERROR_DS_NOT_INSTALLED __MSABI_LONG(8200)
#define ERROR_DS_MEMBERSHIP_EVALUATED_LOCALLY __MSABI_LONG(8201)
#define ERROR_DS_NO_ATTRIBUTE_OR_VALUE __MSABI_LONG(8202)
#define ERROR_DS_INVALID_ATTRIBUTE_SYNTAX __MSABI_LONG(8203)
#define ERROR_DS_ATTRIBUTE_TYPE_UNDEFINED __MSABI_LONG(8204)
#define ERROR_DS_ATTRIBUTE_OR_VALUE_EXISTS __MSABI_LONG(8205)
#define ERROR_DS_BUSY __MSABI_LONG(8206)
#define ERROR_DS_UNAVAILABLE __MSABI_LONG(8207)
#define ERROR_DS_NO_RIDS_ALLOCATED __MSABI_LONG(8208)
#define ERROR_DS_NO_MORE_RIDS __MSABI_LONG(8209)
#define ERROR_DS_INCORRECT_ROLE_OWNER __MSABI_LONG(8210)
#define ERROR_DS_RIDMGR_INIT_ERROR __MSABI_LONG(8211)
#define ERROR_DS_OBJ_CLASS_VIOLATION __MSABI_LONG(8212)
#define ERROR_DS_CANT_ON_NON_LEAF __MSABI_LONG(8213)
#define ERROR_DS_CANT_ON_RDN __MSABI_LONG(8214)
#define ERROR_DS_CANT_MOD_OBJ_CLASS __MSABI_LONG(8215)
#define ERROR_DS_CROSS_DOM_MOVE_ERROR __MSABI_LONG(8216)
#define ERROR_DS_GC_NOT_AVAILABLE __MSABI_LONG(8217)
#define ERROR_SHARED_POLICY __MSABI_LONG(8218)
#define ERROR_POLICY_OBJECT_NOT_FOUND __MSABI_LONG(8219)
#define ERROR_POLICY_ONLY_IN_DS __MSABI_LONG(8220)
#define ERROR_PROMOTION_ACTIVE __MSABI_LONG(8221)
#define ERROR_NO_PROMOTION_ACTIVE __MSABI_LONG(8222)
#define ERROR_DS_OPERATIONS_ERROR __MSABI_LONG(8224)
#define ERROR_DS_PROTOCOL_ERROR __MSABI_LONG(8225)
#define ERROR_DS_TIMELIMIT_EXCEEDED __MSABI_LONG(8226)
#define ERROR_DS_SIZELIMIT_EXCEEDED __MSABI_LONG(8227)
#define ERROR_DS_ADMIN_LIMIT_EXCEEDED __MSABI_LONG(8228)
#define ERROR_DS_COMPARE_FALSE __MSABI_LONG(8229)
#define ERROR_DS_COMPARE_TRUE __MSABI_LONG(8230)
#define ERROR_DS_AUTH_METHOD_NOT_SUPPORTED __MSABI_LONG(8231)
#define ERROR_DS_STRONG_AUTH_REQUIRED __MSABI_LONG(8232)
#define ERROR_DS_INAPPROPRIATE_AUTH __MSABI_LONG(8233)
#define ERROR_DS_AUTH_UNKNOWN __MSABI_LONG(8234)
#define ERROR_DS_REFERRAL __MSABI_LONG(8235)
#define ERROR_DS_UNAVAILABLE_CRIT_EXTENSION __MSABI_LONG(8236)
#define ERROR_DS_CONFIDENTIALITY_REQUIRED __MSABI_LONG(8237)
#define ERROR_DS_INAPPROPRIATE_MATCHING __MSABI_LONG(8238)
#define ERROR_DS_CONSTRAINT_VIOLATION __MSABI_LONG(8239)
#define ERROR_DS_NO_SUCH_OBJECT __MSABI_LONG(8240)
#define ERROR_DS_ALIAS_PROBLEM __MSABI_LONG(8241)
#define ERROR_DS_INVALID_DN_SYNTAX __MSABI_LONG(8242)
#define ERROR_DS_IS_LEAF __MSABI_LONG(8243)
#define ERROR_DS_ALIAS_DEREF_PROBLEM __MSABI_LONG(8244)
#define ERROR_DS_UNWILLING_TO_PERFORM __MSABI_LONG(8245)
#define ERROR_DS_LOOP_DETECT __MSABI_LONG(8246)
#define ERROR_DS_NAMING_VIOLATION __MSABI_LONG(8247)
#define ERROR_DS_OBJECT_RESULTS_TOO_LARGE __MSABI_LONG(8248)
#define ERROR_DS_AFFECTS_MULTIPLE_DSAS __MSABI_LONG(8249)
#define ERROR_DS_SERVER_DOWN __MSABI_LONG(8250)
#define ERROR_DS_LOCAL_ERROR __MSABI_LONG(8251)
#define ERROR_DS_ENCODING_ERROR __MSABI_LONG(8252)
#define ERROR_DS_DECODING_ERROR __MSABI_LONG(8253)
#define ERROR_DS_FILTER_UNKNOWN __MSABI_LONG(8254)
#define ERROR_DS_PARAM_ERROR __MSABI_LONG(8255)
#define ERROR_DS_NOT_SUPPORTED __MSABI_LONG(8256)
#define ERROR_DS_NO_RESULTS_RETURNED __MSABI_LONG(8257)
#define ERROR_DS_CONTROL_NOT_FOUND __MSABI_LONG(8258)
#define ERROR_DS_CLIENT_LOOP __MSABI_LONG(8259)
#define ERROR_DS_REFERRAL_LIMIT_EXCEEDED __MSABI_LONG(8260)
#define ERROR_DS_SORT_CONTROL_MISSING __MSABI_LONG(8261)
#define ERROR_DS_OFFSET_RANGE_ERROR __MSABI_LONG(8262)
#define ERROR_DS_ROOT_MUST_BE_NC __MSABI_LONG(8301)
#define ERROR_DS_ADD_REPLICA_INHIBITED __MSABI_LONG(8302)
#define ERROR_DS_ATT_NOT_DEF_IN_SCHEMA __MSABI_LONG(8303)
#define ERROR_DS_MAX_OBJ_SIZE_EXCEEDED __MSABI_LONG(8304)
#define ERROR_DS_OBJ_STRING_NAME_EXISTS __MSABI_LONG(8305)
#define ERROR_DS_NO_RDN_DEFINED_IN_SCHEMA __MSABI_LONG(8306)
#define ERROR_DS_RDN_DOESNT_MATCH_SCHEMA __MSABI_LONG(8307)
#define ERROR_DS_NO_REQUESTED_ATTS_FOUND __MSABI_LONG(8308)
#define ERROR_DS_USER_BUFFER_TO_SMALL __MSABI_LONG(8309)
#define ERROR_DS_ATT_IS_NOT_ON_OBJ __MSABI_LONG(8310)
#define ERROR_DS_ILLEGAL_MOD_OPERATION __MSABI_LONG(8311)
#define ERROR_DS_OBJ_TOO_LARGE __MSABI_LONG(8312)
#define ERROR_DS_BAD_INSTANCE_TYPE __MSABI_LONG(8313)
#define ERROR_DS_MASTERDSA_REQUIRED __MSABI_LONG(8314)
#define ERROR_DS_OBJECT_CLASS_REQUIRED __MSABI_LONG(8315)
#define ERROR_DS_MISSING_REQUIRED_ATT __MSABI_LONG(8316)
#define ERROR_DS_ATT_NOT_DEF_FOR_CLASS __MSABI_LONG(8317)
#define ERROR_DS_ATT_ALREADY_EXISTS __MSABI_LONG(8318)
#define ERROR_DS_CANT_ADD_ATT_VALUES __MSABI_LONG(8320)
#define ERROR_DS_SINGLE_VALUE_CONSTRAINT __MSABI_LONG(8321)
#define ERROR_DS_RANGE_CONSTRAINT __MSABI_LONG(8322)
#define ERROR_DS_ATT_VAL_ALREADY_EXISTS __MSABI_LONG(8323)
#define ERROR_DS_CANT_REM_MISSING_ATT __MSABI_LONG(8324)
#define ERROR_DS_CANT_REM_MISSING_ATT_VAL __MSABI_LONG(8325)
#define ERROR_DS_ROOT_CANT_BE_SUBREF __MSABI_LONG(8326)
#define ERROR_DS_NO_CHAINING __MSABI_LONG(8327)
#define ERROR_DS_NO_CHAINED_EVAL __MSABI_LONG(8328)
#define ERROR_DS_NO_PARENT_OBJECT __MSABI_LONG(8329)
#define ERROR_DS_PARENT_IS_AN_ALIAS __MSABI_LONG(8330)
#define ERROR_DS_CANT_MIX_MASTER_AND_REPS __MSABI_LONG(8331)
#define ERROR_DS_CHILDREN_EXIST __MSABI_LONG(8332)
#define ERROR_DS_OBJ_NOT_FOUND __MSABI_LONG(8333)
#define ERROR_DS_ALIASED_OBJ_MISSING __MSABI_LONG(8334)
#define ERROR_DS_BAD_NAME_SYNTAX __MSABI_LONG(8335)
#define ERROR_DS_ALIAS_POINTS_TO_ALIAS __MSABI_LONG(8336)
#define ERROR_DS_CANT_DEREF_ALIAS __MSABI_LONG(8337)
#define ERROR_DS_OUT_OF_SCOPE __MSABI_LONG(8338)
#define ERROR_DS_OBJECT_BEING_REMOVED __MSABI_LONG(8339)
#define ERROR_DS_CANT_DELETE_DSA_OBJ __MSABI_LONG(8340)
#define ERROR_DS_GENERIC_ERROR __MSABI_LONG(8341)
#define ERROR_DS_DSA_MUST_BE_INT_MASTER __MSABI_LONG(8342)
#define ERROR_DS_CLASS_NOT_DSA __MSABI_LONG(8343)
#define ERROR_DS_INSUFF_ACCESS_RIGHTS __MSABI_LONG(8344)
#define ERROR_DS_ILLEGAL_SUPERIOR __MSABI_LONG(8345)
#define ERROR_DS_ATTRIBUTE_OWNED_BY_SAM __MSABI_LONG(8346)
#define ERROR_DS_NAME_TOO_MANY_PARTS __MSABI_LONG(8347)
#define ERROR_DS_NAME_TOO_LONG __MSABI_LONG(8348)
#define ERROR_DS_NAME_VALUE_TOO_LONG __MSABI_LONG(8349)
#define ERROR_DS_NAME_UNPARSEABLE __MSABI_LONG(8350)
#define ERROR_DS_NAME_TYPE_UNKNOWN __MSABI_LONG(8351)
#define ERROR_DS_NOT_AN_OBJECT __MSABI_LONG(8352)
#define ERROR_DS_SEC_DESC_TOO_SHORT __MSABI_LONG(8353)
#define ERROR_DS_SEC_DESC_INVALID __MSABI_LONG(8354)
#define ERROR_DS_NO_DELETED_NAME __MSABI_LONG(8355)
#define ERROR_DS_SUBREF_MUST_HAVE_PARENT __MSABI_LONG(8356)
#define ERROR_DS_NCNAME_MUST_BE_NC __MSABI_LONG(8357)
#define ERROR_DS_CANT_ADD_SYSTEM_ONLY __MSABI_LONG(8358)
#define ERROR_DS_CLASS_MUST_BE_CONCRETE __MSABI_LONG(8359)
#define ERROR_DS_INVALID_DMD __MSABI_LONG(8360)
#define ERROR_DS_OBJ_GUID_EXISTS __MSABI_LONG(8361)
#define ERROR_DS_NOT_ON_BACKLINK __MSABI_LONG(8362)
#define ERROR_DS_NO_CROSSREF_FOR_NC __MSABI_LONG(8363)
#define ERROR_DS_SHUTTING_DOWN __MSABI_LONG(8364)
#define ERROR_DS_UNKNOWN_OPERATION __MSABI_LONG(8365)
#define ERROR_DS_INVALID_ROLE_OWNER __MSABI_LONG(8366)
#define ERROR_DS_COULDNT_CONTACT_FSMO __MSABI_LONG(8367)
#define ERROR_DS_CROSS_NC_DN_RENAME __MSABI_LONG(8368)
#define ERROR_DS_CANT_MOD_SYSTEM_ONLY __MSABI_LONG(8369)
#define ERROR_DS_REPLICATOR_ONLY __MSABI_LONG(8370)
#define ERROR_DS_OBJ_CLASS_NOT_DEFINED __MSABI_LONG(8371)
#define ERROR_DS_OBJ_CLASS_NOT_SUBCLASS __MSABI_LONG(8372)
#define ERROR_DS_NAME_REFERENCE_INVALID __MSABI_LONG(8373)
#define ERROR_DS_CROSS_REF_EXISTS __MSABI_LONG(8374)
#define ERROR_DS_CANT_DEL_MASTER_CROSSREF __MSABI_LONG(8375)
#define ERROR_DS_SUBTREE_NOTIFY_NOT_NC_HEAD __MSABI_LONG(8376)
#define ERROR_DS_NOTIFY_FILTER_TOO_COMPLEX __MSABI_LONG(8377)
#define ERROR_DS_DUP_RDN __MSABI_LONG(8378)
#define ERROR_DS_DUP_OID __MSABI_LONG(8379)
#define ERROR_DS_DUP_MAPI_ID __MSABI_LONG(8380)
#define ERROR_DS_DUP_SCHEMA_ID_GUID __MSABI_LONG(8381)
#define ERROR_DS_DUP_LDAP_DISPLAY_NAME __MSABI_LONG(8382)
#define ERROR_DS_SEMANTIC_ATT_TEST __MSABI_LONG(8383)
#define ERROR_DS_SYNTAX_MISMATCH __MSABI_LONG(8384)
#define ERROR_DS_EXISTS_IN_MUST_HAVE __MSABI_LONG(8385)
#define ERROR_DS_EXISTS_IN_MAY_HAVE __MSABI_LONG(8386)
#define ERROR_DS_NONEXISTENT_MAY_HAVE __MSABI_LONG(8387)
#define ERROR_DS_NONEXISTENT_MUST_HAVE __MSABI_LONG(8388)
#define ERROR_DS_AUX_CLS_TEST_FAIL __MSABI_LONG(8389)
#define ERROR_DS_NONEXISTENT_POSS_SUP __MSABI_LONG(8390)
#define ERROR_DS_SUB_CLS_TEST_FAIL __MSABI_LONG(8391)
#define ERROR_DS_BAD_RDN_ATT_ID_SYNTAX __MSABI_LONG(8392)
#define ERROR_DS_EXISTS_IN_AUX_CLS __MSABI_LONG(8393)
#define ERROR_DS_EXISTS_IN_SUB_CLS __MSABI_LONG(8394)
#define ERROR_DS_EXISTS_IN_POSS_SUP __MSABI_LONG(8395)
#define ERROR_DS_RECALCSCHEMA_FAILED __MSABI_LONG(8396)
#define ERROR_DS_TREE_DELETE_NOT_FINISHED __MSABI_LONG(8397)
#define ERROR_DS_CANT_DELETE __MSABI_LONG(8398)
#define ERROR_DS_ATT_SCHEMA_REQ_ID __MSABI_LONG(8399)
#define ERROR_DS_BAD_ATT_SCHEMA_SYNTAX __MSABI_LONG(8400)
#define ERROR_DS_CANT_CACHE_ATT __MSABI_LONG(8401)
#define ERROR_DS_CANT_CACHE_CLASS __MSABI_LONG(8402)
#define ERROR_DS_CANT_REMOVE_ATT_CACHE __MSABI_LONG(8403)
#define ERROR_DS_CANT_REMOVE_CLASS_CACHE __MSABI_LONG(8404)
#define ERROR_DS_CANT_RETRIEVE_DN __MSABI_LONG(8405)
#define ERROR_DS_MISSING_SUPREF __MSABI_LONG(8406)
#define ERROR_DS_CANT_RETRIEVE_INSTANCE __MSABI_LONG(8407)
#define ERROR_DS_CODE_INCONSISTENCY __MSABI_LONG(8408)
#define ERROR_DS_DATABASE_ERROR __MSABI_LONG(8409)
#define ERROR_DS_GOVERNSID_MISSING __MSABI_LONG(8410)
#define ERROR_DS_MISSING_EXPECTED_ATT __MSABI_LONG(8411)
#define ERROR_DS_NCNAME_MISSING_CR_REF __MSABI_LONG(8412)
#define ERROR_DS_SECURITY_CHECKING_ERROR __MSABI_LONG(8413)
#define ERROR_DS_SCHEMA_NOT_LOADED __MSABI_LONG(8414)
#define ERROR_DS_SCHEMA_ALLOC_FAILED __MSABI_LONG(8415)
#define ERROR_DS_ATT_SCHEMA_REQ_SYNTAX __MSABI_LONG(8416)
#define ERROR_DS_GCVERIFY_ERROR __MSABI_LONG(8417)
#define ERROR_DS_DRA_SCHEMA_MISMATCH __MSABI_LONG(8418)
#define ERROR_DS_CANT_FIND_DSA_OBJ __MSABI_LONG(8419)
#define ERROR_DS_CANT_FIND_EXPECTED_NC __MSABI_LONG(8420)
#define ERROR_DS_CANT_FIND_NC_IN_CACHE __MSABI_LONG(8421)
#define ERROR_DS_CANT_RETRIEVE_CHILD __MSABI_LONG(8422)
#define ERROR_DS_SECURITY_ILLEGAL_MODIFY __MSABI_LONG(8423)
#define ERROR_DS_CANT_REPLACE_HIDDEN_REC __MSABI_LONG(8424)
#define ERROR_DS_BAD_HIERARCHY_FILE __MSABI_LONG(8425)
#define ERROR_DS_BUILD_HIERARCHY_TABLE_FAILED __MSABI_LONG(8426)
#define ERROR_DS_CONFIG_PARAM_MISSING __MSABI_LONG(8427)
#define ERROR_DS_COUNTING_AB_INDICES_FAILED __MSABI_LONG(8428)
#define ERROR_DS_HIERARCHY_TABLE_MALLOC_FAILED __MSABI_LONG(8429)
#define ERROR_DS_INTERNAL_FAILURE __MSABI_LONG(8430)
#define ERROR_DS_UNKNOWN_ERROR __MSABI_LONG(8431)
#define ERROR_DS_ROOT_REQUIRES_CLASS_TOP __MSABI_LONG(8432)
#define ERROR_DS_REFUSING_FSMO_ROLES __MSABI_LONG(8433)
#define ERROR_DS_MISSING_FSMO_SETTINGS __MSABI_LONG(8434)
#define ERROR_DS_UNABLE_TO_SURRENDER_ROLES __MSABI_LONG(8435)
#define ERROR_DS_DRA_GENERIC __MSABI_LONG(8436)
#define ERROR_DS_DRA_INVALID_PARAMETER __MSABI_LONG(8437)
#define ERROR_DS_DRA_BUSY __MSABI_LONG(8438)
#define ERROR_DS_DRA_BAD_DN __MSABI_LONG(8439)
#define ERROR_DS_DRA_BAD_NC __MSABI_LONG(8440)
#define ERROR_DS_DRA_DN_EXISTS __MSABI_LONG(8441)
#define ERROR_DS_DRA_INTERNAL_ERROR __MSABI_LONG(8442)
#define ERROR_DS_DRA_INCONSISTENT_DIT __MSABI_LONG(8443)
#define ERROR_DS_DRA_CONNECTION_FAILED __MSABI_LONG(8444)
#define ERROR_DS_DRA_BAD_INSTANCE_TYPE __MSABI_LONG(8445)
#define ERROR_DS_DRA_OUT_OF_MEM __MSABI_LONG(8446)
#define ERROR_DS_DRA_MAIL_PROBLEM __MSABI_LONG(8447)
#define ERROR_DS_DRA_REF_ALREADY_EXISTS __MSABI_LONG(8448)
#define ERROR_DS_DRA_REF_NOT_FOUND __MSABI_LONG(8449)
#define ERROR_DS_DRA_OBJ_IS_REP_SOURCE __MSABI_LONG(8450)
#define ERROR_DS_DRA_DB_ERROR __MSABI_LONG(8451)
#define ERROR_DS_DRA_NO_REPLICA __MSABI_LONG(8452)
#define ERROR_DS_DRA_ACCESS_DENIED __MSABI_LONG(8453)
#define ERROR_DS_DRA_NOT_SUPPORTED __MSABI_LONG(8454)
#define ERROR_DS_DRA_RPC_CANCELLED __MSABI_LONG(8455)
#define ERROR_DS_DRA_SOURCE_DISABLED __MSABI_LONG(8456)
#define ERROR_DS_DRA_SINK_DISABLED __MSABI_LONG(8457)
#define ERROR_DS_DRA_NAME_COLLISION __MSABI_LONG(8458)
#define ERROR_DS_DRA_SOURCE_REINSTALLED __MSABI_LONG(8459)
#define ERROR_DS_DRA_MISSING_PARENT __MSABI_LONG(8460)
#define ERROR_DS_DRA_PREEMPTED __MSABI_LONG(8461)
#define ERROR_DS_DRA_ABANDON_SYNC __MSABI_LONG(8462)
#define ERROR_DS_DRA_SHUTDOWN __MSABI_LONG(8463)
#define ERROR_DS_DRA_INCOMPATIBLE_PARTIAL_SET __MSABI_LONG(8464)
#define ERROR_DS_DRA_SOURCE_IS_PARTIAL_REPLICA __MSABI_LONG(8465)
#define ERROR_DS_DRA_EXTN_CONNECTION_FAILED __MSABI_LONG(8466)
#define ERROR_DS_INSTALL_SCHEMA_MISMATCH __MSABI_LONG(8467)
#define ERROR_DS_DUP_LINK_ID __MSABI_LONG(8468)
#define ERROR_DS_NAME_ERROR_RESOLVING __MSABI_LONG(8469)
#define ERROR_DS_NAME_ERROR_NOT_FOUND __MSABI_LONG(8470)
#define ERROR_DS_NAME_ERROR_NOT_UNIQUE __MSABI_LONG(8471)
#define ERROR_DS_NAME_ERROR_NO_MAPPING __MSABI_LONG(8472)
#define ERROR_DS_NAME_ERROR_DOMAIN_ONLY __MSABI_LONG(8473)
#define ERROR_DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING __MSABI_LONG(8474)
#define ERROR_DS_CONSTRUCTED_ATT_MOD __MSABI_LONG(8475)
#define ERROR_DS_WRONG_OM_OBJ_CLASS __MSABI_LONG(8476)
#define ERROR_DS_DRA_REPL_PENDING __MSABI_LONG(8477)
#define ERROR_DS_DS_REQUIRED __MSABI_LONG(8478)
#define ERROR_DS_INVALID_LDAP_DISPLAY_NAME __MSABI_LONG(8479)
#define ERROR_DS_NON_BASE_SEARCH __MSABI_LONG(8480)
#define ERROR_DS_CANT_RETRIEVE_ATTS __MSABI_LONG(8481)
#define ERROR_DS_BACKLINK_WITHOUT_LINK __MSABI_LONG(8482)
#define ERROR_DS_EPOCH_MISMATCH __MSABI_LONG(8483)
#define ERROR_DS_SRC_NAME_MISMATCH __MSABI_LONG(8484)
#define ERROR_DS_SRC_AND_DST_NC_IDENTICAL __MSABI_LONG(8485)
#define ERROR_DS_DST_NC_MISMATCH __MSABI_LONG(8486)
#define ERROR_DS_NOT_AUTHORITIVE_FOR_DST_NC __MSABI_LONG(8487)
#define ERROR_DS_SRC_GUID_MISMATCH __MSABI_LONG(8488)
#define ERROR_DS_CANT_MOVE_DELETED_OBJECT __MSABI_LONG(8489)
#define ERROR_DS_PDC_OPERATION_IN_PROGRESS __MSABI_LONG(8490)
#define ERROR_DS_CROSS_DOMAIN_CLEANUP_REQD __MSABI_LONG(8491)
#define ERROR_DS_ILLEGAL_XDOM_MOVE_OPERATION __MSABI_LONG(8492)
#define ERROR_DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS __MSABI_LONG(8493)
#define ERROR_DS_NC_MUST_HAVE_NC_PARENT __MSABI_LONG(8494)
#define ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE __MSABI_LONG(8495)
#define ERROR_DS_DST_DOMAIN_NOT_NATIVE __MSABI_LONG(8496)
#define ERROR_DS_MISSING_INFRASTRUCTURE_CONTAINER __MSABI_LONG(8497)
#define ERROR_DS_CANT_MOVE_ACCOUNT_GROUP __MSABI_LONG(8498)
#define ERROR_DS_CANT_MOVE_RESOURCE_GROUP __MSABI_LONG(8499)
#define ERROR_DS_INVALID_SEARCH_FLAG __MSABI_LONG(8500)
#define ERROR_DS_NO_TREE_DELETE_ABOVE_NC __MSABI_LONG(8501)
#define ERROR_DS_COULDNT_LOCK_TREE_FOR_DELETE __MSABI_LONG(8502)
#define ERROR_DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE __MSABI_LONG(8503)
#define ERROR_DS_SAM_INIT_FAILURE __MSABI_LONG(8504)
#define ERROR_DS_SENSITIVE_GROUP_VIOLATION __MSABI_LONG(8505)
#define ERROR_DS_CANT_MOD_PRIMARYGROUPID __MSABI_LONG(8506)
#define ERROR_DS_ILLEGAL_BASE_SCHEMA_MOD __MSABI_LONG(8507)
#define ERROR_DS_NONSAFE_SCHEMA_CHANGE __MSABI_LONG(8508)
#define ERROR_DS_SCHEMA_UPDATE_DISALLOWED __MSABI_LONG(8509)
#define ERROR_DS_CANT_CREATE_UNDER_SCHEMA __MSABI_LONG(8510)
#define ERROR_DS_INSTALL_NO_SRC_SCH_VERSION __MSABI_LONG(8511)
#define ERROR_DS_INSTALL_NO_SCH_VERSION_IN_INIFILE __MSABI_LONG(8512)
#define ERROR_DS_INVALID_GROUP_TYPE __MSABI_LONG(8513)
#define ERROR_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN __MSABI_LONG(8514)
#define ERROR_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN __MSABI_LONG(8515)
#define ERROR_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER __MSABI_LONG(8516)
#define ERROR_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER __MSABI_LONG(8517)
#define ERROR_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER __MSABI_LONG(8518)
#define ERROR_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER __MSABI_LONG(8519)
#define ERROR_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER __MSABI_LONG(8520)
#define ERROR_DS_HAVE_PRIMARY_MEMBERS __MSABI_LONG(8521)
#define ERROR_DS_STRING_SD_CONVERSION_FAILED __MSABI_LONG(8522)
#define ERROR_DS_NAMING_MASTER_GC __MSABI_LONG(8523)
#define ERROR_DS_DNS_LOOKUP_FAILURE __MSABI_LONG(8524)
#define ERROR_DS_COULDNT_UPDATE_SPNS __MSABI_LONG(8525)
#define ERROR_DS_CANT_RETRIEVE_SD __MSABI_LONG(8526)
#define ERROR_DS_KEY_NOT_UNIQUE __MSABI_LONG(8527)
#define ERROR_DS_WRONG_LINKED_ATT_SYNTAX __MSABI_LONG(8528)
#define ERROR_DS_SAM_NEED_BOOTKEY_PASSWORD __MSABI_LONG(8529)
#define ERROR_DS_SAM_NEED_BOOTKEY_FLOPPY __MSABI_LONG(8530)
#define ERROR_DS_CANT_START __MSABI_LONG(8531)
#define ERROR_DS_INIT_FAILURE __MSABI_LONG(8532)
#define ERROR_DS_NO_PKT_PRIVACY_ON_CONNECTION __MSABI_LONG(8533)
#define ERROR_DS_SOURCE_DOMAIN_IN_FOREST __MSABI_LONG(8534)
#define ERROR_DS_DESTINATION_DOMAIN_NOT_IN_FOREST __MSABI_LONG(8535)
#define ERROR_DS_DESTINATION_AUDITING_NOT_ENABLED __MSABI_LONG(8536)
#define ERROR_DS_CANT_FIND_DC_FOR_SRC_DOMAIN __MSABI_LONG(8537)
#define ERROR_DS_SRC_OBJ_NOT_GROUP_OR_USER __MSABI_LONG(8538)
#define ERROR_DS_SRC_SID_EXISTS_IN_FOREST __MSABI_LONG(8539)
#define ERROR_DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH __MSABI_LONG(8540)
#define ERROR_SAM_INIT_FAILURE __MSABI_LONG(8541)
#define ERROR_DS_DRA_SCHEMA_INFO_SHIP __MSABI_LONG(8542)
#define ERROR_DS_DRA_SCHEMA_CONFLICT __MSABI_LONG(8543)
#define ERROR_DS_DRA_EARLIER_SCHEMA_CONFLICT __MSABI_LONG(8544)
#define ERROR_DS_DRA_OBJ_NC_MISMATCH __MSABI_LONG(8545)
#define ERROR_DS_NC_STILL_HAS_DSAS __MSABI_LONG(8546)
#define ERROR_DS_GC_REQUIRED __MSABI_LONG(8547)
#define ERROR_DS_LOCAL_MEMBER_OF_LOCAL_ONLY __MSABI_LONG(8548)
#define ERROR_DS_NO_FPO_IN_UNIVERSAL_GROUPS __MSABI_LONG(8549)
#define ERROR_DS_CANT_ADD_TO_GC __MSABI_LONG(8550)
#define ERROR_DS_NO_CHECKPOINT_WITH_PDC __MSABI_LONG(8551)
#define ERROR_DS_SOURCE_AUDITING_NOT_ENABLED __MSABI_LONG(8552)
#define ERROR_DS_CANT_CREATE_IN_NONDOMAIN_NC __MSABI_LONG(8553)
#define ERROR_DS_INVALID_NAME_FOR_SPN __MSABI_LONG(8554)
#define ERROR_DS_FILTER_USES_CONTRUCTED_ATTRS __MSABI_LONG(8555)
#define ERROR_DS_UNICODEPWD_NOT_IN_QUOTES __MSABI_LONG(8556)
#define ERROR_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED __MSABI_LONG(8557)
#define ERROR_DS_MUST_BE_RUN_ON_DST_DC __MSABI_LONG(8558)
#define ERROR_DS_SRC_DC_MUST_BE_SP4_OR_GREATER __MSABI_LONG(8559)
#define ERROR_DS_CANT_TREE_DELETE_CRITICAL_OBJ __MSABI_LONG(8560)
#define ERROR_DS_INIT_FAILURE_CONSOLE __MSABI_LONG(8561)
#define ERROR_DS_SAM_INIT_FAILURE_CONSOLE __MSABI_LONG(8562)
#define ERROR_DS_FOREST_VERSION_TOO_HIGH __MSABI_LONG(8563)
#define ERROR_DS_DOMAIN_VERSION_TOO_HIGH __MSABI_LONG(8564)
#define ERROR_DS_FOREST_VERSION_TOO_LOW __MSABI_LONG(8565)
#define ERROR_DS_DOMAIN_VERSION_TOO_LOW __MSABI_LONG(8566)
#define ERROR_DS_INCOMPATIBLE_VERSION __MSABI_LONG(8567)
#define ERROR_DS_LOW_DSA_VERSION __MSABI_LONG(8568)
#define ERROR_DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN __MSABI_LONG(8569)
#define ERROR_DS_NOT_SUPPORTED_SORT_ORDER __MSABI_LONG(8570)
#define ERROR_DS_NAME_NOT_UNIQUE __MSABI_LONG(8571)
#define ERROR_DS_MACHINE_ACCOUNT_CREATED_PRENT4 __MSABI_LONG(8572)
#define ERROR_DS_OUT_OF_VERSION_STORE __MSABI_LONG(8573)
#define ERROR_DS_INCOMPATIBLE_CONTROLS_USED __MSABI_LONG(8574)
#define ERROR_DS_NO_REF_DOMAIN __MSABI_LONG(8575)
#define ERROR_DS_RESERVED_LINK_ID __MSABI_LONG(8576)
#define ERROR_DS_LINK_ID_NOT_AVAILABLE __MSABI_LONG(8577)
#define ERROR_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER __MSABI_LONG(8578)
#define ERROR_DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE __MSABI_LONG(8579)
#define ERROR_DS_NO_OBJECT_MOVE_IN_SCHEMA_NC __MSABI_LONG(8580)
#define ERROR_DS_MODIFYDN_DISALLOWED_BY_FLAG __MSABI_LONG(8581)
#define ERROR_DS_MODIFYDN_WRONG_GRANDPARENT __MSABI_LONG(8582)
#define ERROR_DS_NAME_ERROR_TRUST_REFERRAL __MSABI_LONG(8583)
#define ERROR_NOT_SUPPORTED_ON_STANDARD_SERVER __MSABI_LONG(8584)
#define ERROR_DS_CANT_ACCESS_REMOTE_PART_OF_AD __MSABI_LONG(8585)
#define ERROR_DS_CR_IMPOSSIBLE_TO_VALIDATE_V2 __MSABI_LONG(8586)
#define ERROR_DS_THREAD_LIMIT_EXCEEDED __MSABI_LONG(8587)
#define ERROR_DS_NOT_CLOSEST __MSABI_LONG(8588)
#define ERROR_DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF __MSABI_LONG(8589)
#define ERROR_DS_SINGLE_USER_MODE_FAILED __MSABI_LONG(8590)
#define ERROR_DS_NTDSCRIPT_SYNTAX_ERROR __MSABI_LONG(8591)
#define ERROR_DS_NTDSCRIPT_PROCESS_ERROR __MSABI_LONG(8592)
#define ERROR_DS_DIFFERENT_REPL_EPOCHS __MSABI_LONG(8593)
#define ERROR_DS_DRS_EXTENSIONS_CHANGED __MSABI_LONG(8594)
#define ERROR_DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR __MSABI_LONG(8595)
#define ERROR_DS_NO_MSDS_INTID __MSABI_LONG(8596)
#define ERROR_DS_DUP_MSDS_INTID __MSABI_LONG(8597)
#define ERROR_DS_EXISTS_IN_RDNATTID __MSABI_LONG(8598)
#define ERROR_DS_AUTHORIZATION_FAILED __MSABI_LONG(8599)
#define ERROR_DS_INVALID_SCRIPT __MSABI_LONG(8600)
#define ERROR_DS_REMOTE_CROSSREF_OP_FAILED __MSABI_LONG(8601)
#define ERROR_DS_CROSS_REF_BUSY __MSABI_LONG(8602)
#define ERROR_DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN __MSABI_LONG(8603)
#define ERROR_DS_CANT_DEMOTE_WITH_WRITEABLE_NC __MSABI_LONG(8604)
#define ERROR_DS_DUPLICATE_ID_FOUND __MSABI_LONG(8605)
#define ERROR_DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT __MSABI_LONG(8606)
#define ERROR_DS_GROUP_CONVERSION_ERROR __MSABI_LONG(8607)
#define ERROR_DS_CANT_MOVE_APP_BASIC_GROUP __MSABI_LONG(8608)
#define ERROR_DS_CANT_MOVE_APP_QUERY_GROUP __MSABI_LONG(8609)
#define ERROR_DS_ROLE_NOT_VERIFIED __MSABI_LONG(8610)
#define ERROR_DS_WKO_CONTAINER_CANNOT_BE_SPECIAL __MSABI_LONG(8611)
#define ERROR_DS_DOMAIN_RENAME_IN_PROGRESS __MSABI_LONG(8612)
#define ERROR_DS_EXISTING_AD_CHILD_NC __MSABI_LONG(8613)
#define ERROR_DS_REPL_LIFETIME_EXCEEDED __MSABI_LONG(8614)
#define ERROR_DS_DISALLOWED_IN_SYSTEM_CONTAINER __MSABI_LONG(8615)
#define ERROR_DS_LDAP_SEND_QUEUE_FULL __MSABI_LONG(8616)
#define ERROR_DS_DRA_OUT_SCHEDULE_WINDOW __MSABI_LONG(8617)
#define DNS_ERROR_RESPONSE_CODES_BASE 9000
#define DNS_ERROR_RCODE_NO_ERROR NO_ERROR
#define DNS_ERROR_MASK 0x00002328
#define DNS_ERROR_RCODE_FORMAT_ERROR __MSABI_LONG(9001)
#define DNS_ERROR_RCODE_SERVER_FAILURE __MSABI_LONG(9002)
#define DNS_ERROR_RCODE_NAME_ERROR __MSABI_LONG(9003)
#define DNS_ERROR_RCODE_NOT_IMPLEMENTED __MSABI_LONG(9004)
#define DNS_ERROR_RCODE_REFUSED __MSABI_LONG(9005)
#define DNS_ERROR_RCODE_YXDOMAIN __MSABI_LONG(9006)
#define DNS_ERROR_RCODE_YXRRSET __MSABI_LONG(9007)
#define DNS_ERROR_RCODE_NXRRSET __MSABI_LONG(9008)
#define DNS_ERROR_RCODE_NOTAUTH __MSABI_LONG(9009)
#define DNS_ERROR_RCODE_NOTZONE __MSABI_LONG(9010)
#define DNS_ERROR_RCODE_BADSIG __MSABI_LONG(9016)
#define DNS_ERROR_RCODE_BADKEY __MSABI_LONG(9017)
#define DNS_ERROR_RCODE_BADTIME __MSABI_LONG(9018)
#define DNS_ERROR_RCODE_LAST DNS_ERROR_RCODE_BADTIME
#define DNS_ERROR_PACKET_FMT_BASE 9500
#define DNS_INFO_NO_RECORDS __MSABI_LONG(9501)
#define DNS_ERROR_BAD_PACKET __MSABI_LONG(9502)
#define DNS_ERROR_NO_PACKET __MSABI_LONG(9503)
#define DNS_ERROR_RCODE __MSABI_LONG(9504)
#define DNS_ERROR_UNSECURE_PACKET __MSABI_LONG(9505)
#define DNS_STATUS_PACKET_UNSECURE DNS_ERROR_UNSECURE_PACKET
#define DNS_ERROR_NO_MEMORY ERROR_OUTOFMEMORY
#define DNS_ERROR_INVALID_NAME ERROR_INVALID_NAME
#define DNS_ERROR_INVALID_DATA ERROR_INVALID_DATA
#define DNS_ERROR_GENERAL_API_BASE 9550
#define DNS_ERROR_INVALID_TYPE __MSABI_LONG(9551)
#define DNS_ERROR_INVALID_IP_ADDRESS __MSABI_LONG(9552)
#define DNS_ERROR_INVALID_PROPERTY __MSABI_LONG(9553)
#define DNS_ERROR_TRY_AGAIN_LATER __MSABI_LONG(9554)
#define DNS_ERROR_NOT_UNIQUE __MSABI_LONG(9555)
#define DNS_ERROR_NON_RFC_NAME __MSABI_LONG(9556)
#define DNS_STATUS_FQDN __MSABI_LONG(9557)
#define DNS_STATUS_DOTTED_NAME __MSABI_LONG(9558)
#define DNS_STATUS_SINGLE_PART_NAME __MSABI_LONG(9559)
#define DNS_ERROR_INVALID_NAME_CHAR __MSABI_LONG(9560)
#define DNS_ERROR_NUMERIC_NAME __MSABI_LONG(9561)
#define DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER __MSABI_LONG(9562)
#define DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION __MSABI_LONG(9563)
#define DNS_ERROR_CANNOT_FIND_ROOT_HINTS __MSABI_LONG(9564)
#define DNS_ERROR_INCONSISTENT_ROOT_HINTS __MSABI_LONG(9565)
#define DNS_ERROR_ZONE_BASE 9600
#define DNS_ERROR_ZONE_DOES_NOT_EXIST __MSABI_LONG(9601)
#define DNS_ERROR_NO_ZONE_INFO __MSABI_LONG(9602)
#define DNS_ERROR_INVALID_ZONE_OPERATION __MSABI_LONG(9603)
#define DNS_ERROR_ZONE_CONFIGURATION_ERROR __MSABI_LONG(9604)
#define DNS_ERROR_ZONE_HAS_NO_SOA_RECORD __MSABI_LONG(9605)
#define DNS_ERROR_ZONE_HAS_NO_NS_RECORDS __MSABI_LONG(9606)
#define DNS_ERROR_ZONE_LOCKED __MSABI_LONG(9607)
#define DNS_ERROR_ZONE_CREATION_FAILED __MSABI_LONG(9608)
#define DNS_ERROR_ZONE_ALREADY_EXISTS __MSABI_LONG(9609)
#define DNS_ERROR_AUTOZONE_ALREADY_EXISTS __MSABI_LONG(9610)
#define DNS_ERROR_INVALID_ZONE_TYPE __MSABI_LONG(9611)
#define DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP __MSABI_LONG(9612)
#define DNS_ERROR_ZONE_NOT_SECONDARY __MSABI_LONG(9613)
#define DNS_ERROR_NEED_SECONDARY_ADDRESSES __MSABI_LONG(9614)
#define DNS_ERROR_WINS_INIT_FAILED __MSABI_LONG(9615)
#define DNS_ERROR_NEED_WINS_SERVERS __MSABI_LONG(9616)
#define DNS_ERROR_NBSTAT_INIT_FAILED __MSABI_LONG(9617)
#define DNS_ERROR_SOA_DELETE_INVALID __MSABI_LONG(9618)
#define DNS_ERROR_FORWARDER_ALREADY_EXISTS __MSABI_LONG(9619)
#define DNS_ERROR_ZONE_REQUIRES_MASTER_IP __MSABI_LONG(9620)
#define DNS_ERROR_ZONE_IS_SHUTDOWN __MSABI_LONG(9621)
#define DNS_ERROR_DATAFILE_BASE 9650
#define DNS_ERROR_PRIMARY_REQUIRES_DATAFILE __MSABI_LONG(9651)
#define DNS_ERROR_INVALID_DATAFILE_NAME __MSABI_LONG(9652)
#define DNS_ERROR_DATAFILE_OPEN_FAILURE __MSABI_LONG(9653)
#define DNS_ERROR_FILE_WRITEBACK_FAILED __MSABI_LONG(9654)
#define DNS_ERROR_DATAFILE_PARSING __MSABI_LONG(9655)
#define DNS_ERROR_DATABASE_BASE 9700
#define DNS_ERROR_RECORD_DOES_NOT_EXIST __MSABI_LONG(9701)
#define DNS_ERROR_RECORD_FORMAT __MSABI_LONG(9702)
#define DNS_ERROR_NODE_CREATION_FAILED __MSABI_LONG(9703)
#define DNS_ERROR_UNKNOWN_RECORD_TYPE __MSABI_LONG(9704)
#define DNS_ERROR_RECORD_TIMED_OUT __MSABI_LONG(9705)
#define DNS_ERROR_NAME_NOT_IN_ZONE __MSABI_LONG(9706)
#define DNS_ERROR_CNAME_LOOP __MSABI_LONG(9707)
#define DNS_ERROR_NODE_IS_CNAME __MSABI_LONG(9708)
#define DNS_ERROR_CNAME_COLLISION __MSABI_LONG(9709)
#define DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT __MSABI_LONG(9710)
#define DNS_ERROR_RECORD_ALREADY_EXISTS __MSABI_LONG(9711)
#define DNS_ERROR_SECONDARY_DATA __MSABI_LONG(9712)
#define DNS_ERROR_NO_CREATE_CACHE_DATA __MSABI_LONG(9713)
#define DNS_ERROR_NAME_DOES_NOT_EXIST __MSABI_LONG(9714)
#define DNS_WARNING_PTR_CREATE_FAILED __MSABI_LONG(9715)
#define DNS_WARNING_DOMAIN_UNDELETED __MSABI_LONG(9716)
#define DNS_ERROR_DS_UNAVAILABLE __MSABI_LONG(9717)
#define DNS_ERROR_DS_ZONE_ALREADY_EXISTS __MSABI_LONG(9718)
#define DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE __MSABI_LONG(9719)
#define DNS_ERROR_OPERATION_BASE 9750
#define DNS_INFO_AXFR_COMPLETE __MSABI_LONG(9751)
#define DNS_ERROR_AXFR __MSABI_LONG(9752)
#define DNS_INFO_ADDED_LOCAL_WINS __MSABI_LONG(9753)
#define DNS_ERROR_SECURE_BASE 9800
#define DNS_STATUS_CONTINUE_NEEDED __MSABI_LONG(9801)
#define DNS_ERROR_SETUP_BASE 9850
#define DNS_ERROR_NO_TCPIP __MSABI_LONG(9851)
#define DNS_ERROR_NO_DNS_SERVERS __MSABI_LONG(9852)
#define DNS_ERROR_DP_BASE 9900
#define DNS_ERROR_DP_DOES_NOT_EXIST __MSABI_LONG(9901)
#define DNS_ERROR_DP_ALREADY_EXISTS __MSABI_LONG(9902)
#define DNS_ERROR_DP_NOT_ENLISTED __MSABI_LONG(9903)
#define DNS_ERROR_DP_ALREADY_ENLISTED __MSABI_LONG(9904)
#define DNS_ERROR_DP_NOT_AVAILABLE __MSABI_LONG(9905)
#define DNS_ERROR_DP_FSMO_ERROR __MSABI_LONG(9906)

#define WSABASEERR 10000
#define WSAEINTR (WSABASEERR + 4)
#define WSAEBADF (WSABASEERR + 9)
#define WSAEACCES (WSABASEERR + 13)
#define WSAEFAULT (WSABASEERR + 14)
#define WSAEINVAL (WSABASEERR + 22)
#define WSAEMFILE (WSABASEERR + 24)
#define WSAEWOULDBLOCK (WSABASEERR + 35)
#define WSAEINPROGRESS (WSABASEERR + 36)
#define WSAEALREADY (WSABASEERR + 37)
#define WSAENOTSOCK (WSABASEERR + 38)
#define WSAEDESTADDRREQ (WSABASEERR + 39)
#define WSAEMSGSIZE (WSABASEERR + 40)
#define WSAEPROTOTYPE (WSABASEERR + 41)
#define WSAENOPROTOOPT (WSABASEERR + 42)
#define WSAEPROTONOSUPPORT (WSABASEERR + 43)
#define WSAESOCKTNOSUPPORT (WSABASEERR + 44)
#define WSAEOPNOTSUPP (WSABASEERR + 45)
#define WSAEPFNOSUPPORT (WSABASEERR + 46)
#define WSAEAFNOSUPPORT (WSABASEERR + 47)
#define WSAEADDRINUSE (WSABASEERR + 48)
#define WSAEADDRNOTAVAIL (WSABASEERR + 49)
#define WSAENETDOWN (WSABASEERR + 50)
#define WSAENETUNREACH (WSABASEERR + 51)
#define WSAENETRESET (WSABASEERR + 52)
#define WSAECONNABORTED (WSABASEERR + 53)
#define WSAECONNRESET (WSABASEERR + 54)
#define WSAENOBUFS (WSABASEERR + 55)
#define WSAEISCONN (WSABASEERR + 56)
#define WSAENOTCONN (WSABASEERR + 57)
#define WSAESHUTDOWN (WSABASEERR + 58)
#define WSAETOOMANYREFS (WSABASEERR + 59)
#define WSAETIMEDOUT (WSABASEERR + 60)
#define WSAECONNREFUSED (WSABASEERR + 61)
#define WSAELOOP (WSABASEERR + 62)
#define WSAENAMETOOLONG (WSABASEERR + 63)
#define WSAEHOSTDOWN (WSABASEERR + 64)
#define WSAEHOSTUNREACH (WSABASEERR + 65)
#define WSAENOTEMPTY (WSABASEERR + 66)
#define WSAEPROCLIM (WSABASEERR + 67)
#define WSAEUSERS (WSABASEERR + 68)
#define WSAEDQUOT (WSABASEERR + 69)
#define WSAESTALE (WSABASEERR + 70)
#define WSAEREMOTE (WSABASEERR + 71)
#define WSASYSNOTREADY (WSABASEERR + 91)
#define WSAVERNOTSUPPORTED (WSABASEERR + 92)
#define WSANOTINITIALISED (WSABASEERR + 93)
#define WSAEDISCON (WSABASEERR + 101)
#define WSAENOMORE (WSABASEERR + 102)
#define WSAECANCELLED (WSABASEERR + 103)
#define WSAEINVALIDPROCTABLE (WSABASEERR + 104)
#define WSAEINVALIDPROVIDER (WSABASEERR + 105)
#define WSAEPROVIDERFAILEDINIT (WSABASEERR + 106)
#define WSASYSCALLFAILURE (WSABASEERR + 107)
#define WSASERVICE_NOT_FOUND (WSABASEERR + 108)
#define WSATYPE_NOT_FOUND (WSABASEERR + 109)
#define WSA_E_NO_MORE (WSABASEERR + 110)
#define WSA_E_CANCELLED (WSABASEERR + 111)
#define WSAEREFUSED (WSABASEERR + 112)
#ifndef WSAHOST_NOT_FOUND
#define WSAHOST_NOT_FOUND (WSABASEERR + 1001)
#endif
#ifndef WSATRY_AGAIN
#define WSATRY_AGAIN (WSABASEERR + 1002)
#endif
#ifndef WSANO_RECOVERY
#define WSANO_RECOVERY (WSABASEERR + 1003)
#endif
#ifndef WSANO_DATA
#define WSANO_DATA (WSABASEERR + 1004)
#endif
#ifndef WSA_QOS_RECEIVERS
#define WSA_QOS_RECEIVERS (WSABASEERR + 1005)
#endif
#ifndef WSA_QOS_SENDERS
#define WSA_QOS_SENDERS (WSABASEERR + 1006)
#endif
#ifndef WSA_QOS_NO_SENDERS
#define WSA_QOS_NO_SENDERS (WSABASEERR + 1007)
#endif
#ifndef WSA_QOS_NO_RECEIVERS
#define WSA_QOS_NO_RECEIVERS (WSABASEERR + 1008)
#endif
#ifndef WSA_QOS_REQUEST_CONFIRMED
#define WSA_QOS_REQUEST_CONFIRMED (WSABASEERR + 1009)
#endif
#ifndef WSA_QOS_ADMISSION_FAILURE
#define WSA_QOS_ADMISSION_FAILURE (WSABASEERR + 1010)
#endif
#ifndef WSA_QOS_POLICY_FAILURE
#define WSA_QOS_POLICY_FAILURE (WSABASEERR + 1011)
#endif
#ifndef WSA_QOS_BAD_STYLE
#define WSA_QOS_BAD_STYLE (WSABASEERR + 1012)
#endif
#ifndef WSA_QOS_BAD_OBJECT
#define WSA_QOS_BAD_OBJECT (WSABASEERR + 1013)
#endif
#ifndef WSA_QOS_TRAFFIC_CTRL_ERROR
#define WSA_QOS_TRAFFIC_CTRL_ERROR (WSABASEERR + 1014)
#endif
#ifndef WSA_QOS_GENERIC_ERROR
#define WSA_QOS_GENERIC_ERROR (WSABASEERR + 1015)
#endif
#ifndef WSA_QOS_ESERVICETYPE
#define WSA_QOS_ESERVICETYPE (WSABASEERR + 1016)
#endif
#ifndef WSA_QOS_EFLOWSPEC
#define WSA_QOS_EFLOWSPEC (WSABASEERR + 1017)
#endif
#ifndef WSA_QOS_EPROVSPECBUF
#define WSA_QOS_EPROVSPECBUF (WSABASEERR + 1018)
#endif
#ifndef WSA_QOS_EFILTERSTYLE
#define WSA_QOS_EFILTERSTYLE (WSABASEERR + 1019)
#endif
#ifndef WSA_QOS_EFILTERTYPE
#define WSA_QOS_EFILTERTYPE (WSABASEERR + 1020)
#endif
#ifndef WSA_QOS_EFILTERCOUNT
#define WSA_QOS_EFILTERCOUNT (WSABASEERR + 1021)
#endif
#ifndef WSA_QOS_EOBJLENGTH
#define WSA_QOS_EOBJLENGTH (WSABASEERR + 1022)
#endif
#ifndef WSA_QOS_EFLOWCOUNT
#define WSA_QOS_EFLOWCOUNT (WSABASEERR + 1023)
#endif
#ifndef WSA_QOS_EUNKNOWNPSOBJ
#define WSA_QOS_EUNKNOWNPSOBJ (WSABASEERR + 1024)
#endif
#ifndef WSA_QOS_EUNKOWNPSOBJ
#define WSA_QOS_EUNKOWNPSOBJ WSA_QOS_EUNKNOWNPSOBJ
#endif
#ifndef WSA_QOS_EPOLICYOBJ
#define WSA_QOS_EPOLICYOBJ (WSABASEERR + 1025)
#endif
#ifndef WSA_QOS_EFLOWDESC
#define WSA_QOS_EFLOWDESC (WSABASEERR + 1026)
#endif
#ifndef WSA_QOS_EPSFLOWSPEC
#define WSA_QOS_EPSFLOWSPEC (WSABASEERR + 1027)
#endif
#ifndef WSA_QOS_EPSFILTERSPEC
#define WSA_QOS_EPSFILTERSPEC (WSABASEERR + 1028)
#endif
#ifndef WSA_QOS_ESDMODEOBJ
#define WSA_QOS_ESDMODEOBJ (WSABASEERR + 1029)
#endif
#ifndef WSA_QOS_ESHAPERATEOBJ
#define WSA_QOS_ESHAPERATEOBJ (WSABASEERR + 1030)
#endif
#ifndef WSA_QOS_RESERVED_PETYPE
#define WSA_QOS_RESERVED_PETYPE (WSABASEERR + 1031)
#endif

#define ERROR_SXS_SECTION_NOT_FOUND __MSABI_LONG(14000)
#define ERROR_SXS_CANT_GEN_ACTCTX __MSABI_LONG(14001)
#define ERROR_SXS_INVALID_ACTCTXDATA_FORMAT __MSABI_LONG(14002)
#define ERROR_SXS_ASSEMBLY_NOT_FOUND __MSABI_LONG(14003)
#define ERROR_SXS_MANIFEST_FORMAT_ERROR __MSABI_LONG(14004)
#define ERROR_SXS_MANIFEST_PARSE_ERROR __MSABI_LONG(14005)
#define ERROR_SXS_ACTIVATION_CONTEXT_DISABLED __MSABI_LONG(14006)
#define ERROR_SXS_KEY_NOT_FOUND __MSABI_LONG(14007)
#define ERROR_SXS_VERSION_CONFLICT __MSABI_LONG(14008)
#define ERROR_SXS_WRONG_SECTION_TYPE __MSABI_LONG(14009)
#define ERROR_SXS_THREAD_QUERIES_DISABLED __MSABI_LONG(14010)
#define ERROR_SXS_PROCESS_DEFAULT_ALREADY_SET __MSABI_LONG(14011)
#define ERROR_SXS_UNKNOWN_ENCODING_GROUP __MSABI_LONG(14012)
#define ERROR_SXS_UNKNOWN_ENCODING __MSABI_LONG(14013)
#define ERROR_SXS_INVALID_XML_NAMESPACE_URI __MSABI_LONG(14014)
#define ERROR_SXS_ROOT_MANIFEST_DEPENDENCY_NOT_INSTALLED __MSABI_LONG(14015)
#define ERROR_SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED __MSABI_LONG(14016)
#define ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE __MSABI_LONG(14017)
#define ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE __MSABI_LONG(14018)
#define ERROR_SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE __MSABI_LONG(14019)
#define ERROR_SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT __MSABI_LONG(14020)
#define ERROR_SXS_DUPLICATE_DLL_NAME __MSABI_LONG(14021)
#define ERROR_SXS_DUPLICATE_WINDOWCLASS_NAME __MSABI_LONG(14022)
#define ERROR_SXS_DUPLICATE_CLSID __MSABI_LONG(14023)
#define ERROR_SXS_DUPLICATE_IID __MSABI_LONG(14024)
#define ERROR_SXS_DUPLICATE_TLBID __MSABI_LONG(14025)
#define ERROR_SXS_DUPLICATE_PROGID __MSABI_LONG(14026)
#define ERROR_SXS_DUPLICATE_ASSEMBLY_NAME __MSABI_LONG(14027)
#define ERROR_SXS_FILE_HASH_MISMATCH __MSABI_LONG(14028)
#define ERROR_SXS_POLICY_PARSE_ERROR __MSABI_LONG(14029)
#define ERROR_SXS_XML_E_MISSINGQUOTE __MSABI_LONG(14030)
#define ERROR_SXS_XML_E_COMMENTSYNTAX __MSABI_LONG(14031)
#define ERROR_SXS_XML_E_BADSTARTNAMECHAR __MSABI_LONG(14032)
#define ERROR_SXS_XML_E_BADNAMECHAR __MSABI_LONG(14033)
#define ERROR_SXS_XML_E_BADCHARINSTRING __MSABI_LONG(14034)
#define ERROR_SXS_XML_E_XMLDECLSYNTAX __MSABI_LONG(14035)
#define ERROR_SXS_XML_E_BADCHARDATA __MSABI_LONG(14036)
#define ERROR_SXS_XML_E_MISSINGWHITESPACE __MSABI_LONG(14037)
#define ERROR_SXS_XML_E_EXPECTINGTAGEND __MSABI_LONG(14038)
#define ERROR_SXS_XML_E_MISSINGSEMICOLON __MSABI_LONG(14039)
#define ERROR_SXS_XML_E_UNBALANCEDPAREN __MSABI_LONG(14040)
#define ERROR_SXS_XML_E_INTERNALERROR __MSABI_LONG(14041)
#define ERROR_SXS_XML_E_UNEXPECTED_WHITESPACE __MSABI_LONG(14042)
#define ERROR_SXS_XML_E_INCOMPLETE_ENCODING __MSABI_LONG(14043)
#define ERROR_SXS_XML_E_MISSING_PAREN __MSABI_LONG(14044)
#define ERROR_SXS_XML_E_EXPECTINGCLOSEQUOTE __MSABI_LONG(14045)
#define ERROR_SXS_XML_E_MULTIPLE_COLONS __MSABI_LONG(14046)
#define ERROR_SXS_XML_E_INVALID_DECIMAL __MSABI_LONG(14047)
#define ERROR_SXS_XML_E_INVALID_HEXIDECIMAL __MSABI_LONG(14048)
#define ERROR_SXS_XML_E_INVALID_UNICODE __MSABI_LONG(14049)
#define ERROR_SXS_XML_E_WHITESPACEORQUESTIONMARK __MSABI_LONG(14050)
#define ERROR_SXS_XML_E_UNEXPECTEDENDTAG __MSABI_LONG(14051)
#define ERROR_SXS_XML_E_UNCLOSEDTAG __MSABI_LONG(14052)
#define ERROR_SXS_XML_E_DUPLICATEATTRIBUTE __MSABI_LONG(14053)
#define ERROR_SXS_XML_E_MULTIPLEROOTS __MSABI_LONG(14054)
#define ERROR_SXS_XML_E_INVALIDATROOTLEVEL __MSABI_LONG(14055)
#define ERROR_SXS_XML_E_BADXMLDECL __MSABI_LONG(14056)
#define ERROR_SXS_XML_E_MISSINGROOT __MSABI_LONG(14057)
#define ERROR_SXS_XML_E_UNEXPECTEDEOF __MSABI_LONG(14058)
#define ERROR_SXS_XML_E_BADPEREFINSUBSET __MSABI_LONG(14059)
#define ERROR_SXS_XML_E_UNCLOSEDSTARTTAG __MSABI_LONG(14060)
#define ERROR_SXS_XML_E_UNCLOSEDENDTAG __MSABI_LONG(14061)
#define ERROR_SXS_XML_E_UNCLOSEDSTRING __MSABI_LONG(14062)
#define ERROR_SXS_XML_E_UNCLOSEDCOMMENT __MSABI_LONG(14063)
#define ERROR_SXS_XML_E_UNCLOSEDDECL __MSABI_LONG(14064)
#define ERROR_SXS_XML_E_UNCLOSEDCDATA __MSABI_LONG(14065)
#define ERROR_SXS_XML_E_RESERVEDNAMESPACE __MSABI_LONG(14066)
#define ERROR_SXS_XML_E_INVALIDENCODING __MSABI_LONG(14067)
#define ERROR_SXS_XML_E_INVALIDSWITCH __MSABI_LONG(14068)
#define ERROR_SXS_XML_E_BADXMLCASE __MSABI_LONG(14069)
#define ERROR_SXS_XML_E_INVALID_STANDALONE __MSABI_LONG(14070)
#define ERROR_SXS_XML_E_UNEXPECTED_STANDALONE __MSABI_LONG(14071)
#define ERROR_SXS_XML_E_INVALID_VERSION __MSABI_LONG(14072)
#define ERROR_SXS_XML_E_MISSINGEQUALS __MSABI_LONG(14073)
#define ERROR_SXS_PROTECTION_RECOVERY_FAILED __MSABI_LONG(14074)
#define ERROR_SXS_PROTECTION_PUBLIC_KEY_TOO_SHORT __MSABI_LONG(14075)
#define ERROR_SXS_PROTECTION_CATALOG_NOT_VALID __MSABI_LONG(14076)
#define ERROR_SXS_UNTRANSLATABLE_HRESULT __MSABI_LONG(14077)
#define ERROR_SXS_PROTECTION_CATALOG_FILE_MISSING __MSABI_LONG(14078)
#define ERROR_SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE __MSABI_LONG(14079)
#define ERROR_SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME __MSABI_LONG(14080)
#define ERROR_SXS_ASSEMBLY_MISSING __MSABI_LONG(14081)
#define ERROR_SXS_CORRUPT_ACTIVATION_STACK __MSABI_LONG(14082)
#define ERROR_SXS_CORRUPTION __MSABI_LONG(14083)
#define ERROR_SXS_EARLY_DEACTIVATION __MSABI_LONG(14084)
#define ERROR_SXS_INVALID_DEACTIVATION __MSABI_LONG(14085)
#define ERROR_SXS_MULTIPLE_DEACTIVATION __MSABI_LONG(14086)
#define ERROR_SXS_PROCESS_TERMINATION_REQUESTED __MSABI_LONG(14087)
#define ERROR_SXS_RELEASE_ACTIVATION_CONTEXT __MSABI_LONG(14088)
#define ERROR_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY __MSABI_LONG(14089)
#define ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE __MSABI_LONG(14090)
#define ERROR_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME __MSABI_LONG(14091)
#define ERROR_SXS_IDENTITY_DUPLICATE_ATTRIBUTE __MSABI_LONG(14092)
#define ERROR_SXS_IDENTITY_PARSE_ERROR __MSABI_LONG(14093)
#define ERROR_MALFORMED_SUBSTITUTION_STRING __MSABI_LONG(14094)
#define ERROR_SXS_INCORRECT_PUBLIC_KEY_TOKEN __MSABI_LONG(14095)
#define ERROR_UNMAPPED_SUBSTITUTION_STRING __MSABI_LONG(14096)
#define ERROR_SXS_ASSEMBLY_NOT_LOCKED __MSABI_LONG(14097)
#define ERROR_SXS_COMPONENT_STORE_CORRUPT __MSABI_LONG(14098)
#define ERROR_ADVANCED_INSTALLER_FAILED __MSABI_LONG(14099)
#define ERROR_XML_ENCODING_MISMATCH __MSABI_LONG(14100)
#define ERROR_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT __MSABI_LONG(14101)
#define ERROR_SXS_IDENTITIES_DIFFERENT __MSABI_LONG(14102)
#define ERROR_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT __MSABI_LONG(14103)
#define ERROR_SXS_FILE_NOT_PART_OF_ASSEMBLY __MSABI_LONG(14104)
#define ERROR_SXS_MANIFEST_TOO_BIG __MSABI_LONG(14105)
#define ERROR_SXS_SETTING_NOT_REGISTERED __MSABI_LONG(14106)
#define ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE __MSABI_LONG(14107)
#define ERROR_SMI_PRIMITIVE_INSTALLER_FAILED __MSABI_LONG(14108)
#define ERROR_GENERIC_COMMAND_FAILED __MSABI_LONG(14109)
#define ERROR_SXS_FILE_HASH_MISSING __MSABI_LONG(14110)
#define ERROR_IPSEC_QM_POLICY_EXISTS __MSABI_LONG(13000)
#define ERROR_IPSEC_QM_POLICY_NOT_FOUND __MSABI_LONG(13001)
#define ERROR_IPSEC_QM_POLICY_IN_USE __MSABI_LONG(13002)
#define ERROR_IPSEC_MM_POLICY_EXISTS __MSABI_LONG(13003)
#define ERROR_IPSEC_MM_POLICY_NOT_FOUND __MSABI_LONG(13004)
#define ERROR_IPSEC_MM_POLICY_IN_USE __MSABI_LONG(13005)
#define ERROR_IPSEC_MM_FILTER_EXISTS __MSABI_LONG(13006)
#define ERROR_IPSEC_MM_FILTER_NOT_FOUND __MSABI_LONG(13007)
#define ERROR_IPSEC_TRANSPORT_FILTER_EXISTS __MSABI_LONG(13008)
#define ERROR_IPSEC_TRANSPORT_FILTER_NOT_FOUND __MSABI_LONG(13009)
#define ERROR_IPSEC_MM_AUTH_EXISTS __MSABI_LONG(13010)
#define ERROR_IPSEC_MM_AUTH_NOT_FOUND __MSABI_LONG(13011)
#define ERROR_IPSEC_MM_AUTH_IN_USE __MSABI_LONG(13012)
#define ERROR_IPSEC_DEFAULT_MM_POLICY_NOT_FOUND __MSABI_LONG(13013)
#define ERROR_IPSEC_DEFAULT_MM_AUTH_NOT_FOUND __MSABI_LONG(13014)
#define ERROR_IPSEC_DEFAULT_QM_POLICY_NOT_FOUND __MSABI_LONG(13015)
#define ERROR_IPSEC_TUNNEL_FILTER_EXISTS __MSABI_LONG(13016)
#define ERROR_IPSEC_TUNNEL_FILTER_NOT_FOUND __MSABI_LONG(13017)
#define ERROR_IPSEC_MM_FILTER_PENDING_DELETION __MSABI_LONG(13018)
#define ERROR_IPSEC_TRANSPORT_FILTER_PENDING_DELETION __MSABI_LONG(13019)
#define ERROR_IPSEC_TUNNEL_FILTER_PENDING_DELETION __MSABI_LONG(13020)
#define ERROR_IPSEC_MM_POLICY_PENDING_DELETION __MSABI_LONG(13021)
#define ERROR_IPSEC_MM_AUTH_PENDING_DELETION __MSABI_LONG(13022)
#define ERROR_IPSEC_QM_POLICY_PENDING_DELETION __MSABI_LONG(13023)
#define WARNING_IPSEC_MM_POLICY_PRUNED __MSABI_LONG(13024)
#define WARNING_IPSEC_QM_POLICY_PRUNED __MSABI_LONG(13025)
#define ERROR_IPSEC_IKE_NEG_STATUS_BEGIN __MSABI_LONG(13800)
#define ERROR_IPSEC_IKE_AUTH_FAIL __MSABI_LONG(13801)
#define ERROR_IPSEC_IKE_ATTRIB_FAIL __MSABI_LONG(13802)
#define ERROR_IPSEC_IKE_NEGOTIATION_PENDING __MSABI_LONG(13803)
#define ERROR_IPSEC_IKE_GENERAL_PROCESSING_ERROR __MSABI_LONG(13804)
#define ERROR_IPSEC_IKE_TIMED_OUT __MSABI_LONG(13805)
#define ERROR_IPSEC_IKE_NO_CERT __MSABI_LONG(13806)
#define ERROR_IPSEC_IKE_SA_DELETED __MSABI_LONG(13807)
#define ERROR_IPSEC_IKE_SA_REAPED __MSABI_LONG(13808)
#define ERROR_IPSEC_IKE_MM_ACQUIRE_DROP __MSABI_LONG(13809)
#define ERROR_IPSEC_IKE_QM_ACQUIRE_DROP __MSABI_LONG(13810)
#define ERROR_IPSEC_IKE_QUEUE_DROP_MM __MSABI_LONG(13811)
#define ERROR_IPSEC_IKE_QUEUE_DROP_NO_MM __MSABI_LONG(13812)
#define ERROR_IPSEC_IKE_DROP_NO_RESPONSE __MSABI_LONG(13813)
#define ERROR_IPSEC_IKE_MM_DELAY_DROP __MSABI_LONG(13814)
#define ERROR_IPSEC_IKE_QM_DELAY_DROP __MSABI_LONG(13815)
#define ERROR_IPSEC_IKE_ERROR __MSABI_LONG(13816)
#define ERROR_IPSEC_IKE_CRL_FAILED __MSABI_LONG(13817)
#define ERROR_IPSEC_IKE_INVALID_KEY_USAGE __MSABI_LONG(13818)
#define ERROR_IPSEC_IKE_INVALID_CERT_TYPE __MSABI_LONG(13819)
#define ERROR_IPSEC_IKE_NO_PRIVATE_KEY __MSABI_LONG(13820)
#define ERROR_IPSEC_IKE_DH_FAIL __MSABI_LONG(13822)
#define ERROR_IPSEC_IKE_INVALID_HEADER __MSABI_LONG(13824)
#define ERROR_IPSEC_IKE_NO_POLICY __MSABI_LONG(13825)
#define ERROR_IPSEC_IKE_INVALID_SIGNATURE __MSABI_LONG(13826)
#define ERROR_IPSEC_IKE_KERBEROS_ERROR __MSABI_LONG(13827)
#define ERROR_IPSEC_IKE_NO_PUBLIC_KEY __MSABI_LONG(13828)
#define ERROR_IPSEC_IKE_PROCESS_ERR __MSABI_LONG(13829)
#define ERROR_IPSEC_IKE_PROCESS_ERR_SA __MSABI_LONG(13830)
#define ERROR_IPSEC_IKE_PROCESS_ERR_PROP __MSABI_LONG(13831)
#define ERROR_IPSEC_IKE_PROCESS_ERR_TRANS __MSABI_LONG(13832)
#define ERROR_IPSEC_IKE_PROCESS_ERR_KE __MSABI_LONG(13833)
#define ERROR_IPSEC_IKE_PROCESS_ERR_ID __MSABI_LONG(13834)
#define ERROR_IPSEC_IKE_PROCESS_ERR_CERT __MSABI_LONG(13835)
#define ERROR_IPSEC_IKE_PROCESS_ERR_CERT_REQ __MSABI_LONG(13836)
#define ERROR_IPSEC_IKE_PROCESS_ERR_HASH __MSABI_LONG(13837)
#define ERROR_IPSEC_IKE_PROCESS_ERR_SIG __MSABI_LONG(13838)
#define ERROR_IPSEC_IKE_PROCESS_ERR_NONCE __MSABI_LONG(13839)
#define ERROR_IPSEC_IKE_PROCESS_ERR_NOTIFY __MSABI_LONG(13840)
#define ERROR_IPSEC_IKE_PROCESS_ERR_DELETE __MSABI_LONG(13841)
#define ERROR_IPSEC_IKE_PROCESS_ERR_VENDOR __MSABI_LONG(13842)
#define ERROR_IPSEC_IKE_INVALID_PAYLOAD __MSABI_LONG(13843)
#define ERROR_IPSEC_IKE_LOAD_SOFT_SA __MSABI_LONG(13844)
#define ERROR_IPSEC_IKE_SOFT_SA_TORN_DOWN __MSABI_LONG(13845)
#define ERROR_IPSEC_IKE_INVALID_COOKIE __MSABI_LONG(13846)
#define ERROR_IPSEC_IKE_NO_PEER_CERT __MSABI_LONG(13847)
#define ERROR_IPSEC_IKE_PEER_CRL_FAILED __MSABI_LONG(13848)
#define ERROR_IPSEC_IKE_POLICY_CHANGE __MSABI_LONG(13849)
#define ERROR_IPSEC_IKE_NO_MM_POLICY __MSABI_LONG(13850)
#define ERROR_IPSEC_IKE_NOTCBPRIV __MSABI_LONG(13851)
#define ERROR_IPSEC_IKE_SECLOADFAIL __MSABI_LONG(13852)
#define ERROR_IPSEC_IKE_FAILSSPINIT __MSABI_LONG(13853)
#define ERROR_IPSEC_IKE_FAILQUERYSSP __MSABI_LONG(13854)
#define ERROR_IPSEC_IKE_SRVACQFAIL __MSABI_LONG(13855)
#define ERROR_IPSEC_IKE_SRVQUERYCRED __MSABI_LONG(13856)
#define ERROR_IPSEC_IKE_GETSPIFAIL __MSABI_LONG(13857)
#define ERROR_IPSEC_IKE_INVALID_FILTER __MSABI_LONG(13858)
#define ERROR_IPSEC_IKE_OUT_OF_MEMORY __MSABI_LONG(13859)
#define ERROR_IPSEC_IKE_ADD_UPDATE_KEY_FAILED __MSABI_LONG(13860)
#define ERROR_IPSEC_IKE_INVALID_POLICY __MSABI_LONG(13861)
#define ERROR_IPSEC_IKE_UNKNOWN_DOI __MSABI_LONG(13862)
#define ERROR_IPSEC_IKE_INVALID_SITUATION __MSABI_LONG(13863)
#define ERROR_IPSEC_IKE_DH_FAILURE __MSABI_LONG(13864)
#define ERROR_IPSEC_IKE_INVALID_GROUP __MSABI_LONG(13865)
#define ERROR_IPSEC_IKE_ENCRYPT __MSABI_LONG(13866)
#define ERROR_IPSEC_IKE_DECRYPT __MSABI_LONG(13867)
#define ERROR_IPSEC_IKE_POLICY_MATCH __MSABI_LONG(13868)
#define ERROR_IPSEC_IKE_UNSUPPORTED_ID __MSABI_LONG(13869)
#define ERROR_IPSEC_IKE_INVALID_HASH __MSABI_LONG(13870)
#define ERROR_IPSEC_IKE_INVALID_HASH_ALG __MSABI_LONG(13871)
#define ERROR_IPSEC_IKE_INVALID_HASH_SIZE __MSABI_LONG(13872)
#define ERROR_IPSEC_IKE_INVALID_ENCRYPT_ALG __MSABI_LONG(13873)
#define ERROR_IPSEC_IKE_INVALID_AUTH_ALG __MSABI_LONG(13874)
#define ERROR_IPSEC_IKE_INVALID_SIG __MSABI_LONG(13875)
#define ERROR_IPSEC_IKE_LOAD_FAILED __MSABI_LONG(13876)
#define ERROR_IPSEC_IKE_RPC_DELETE __MSABI_LONG(13877)
#define ERROR_IPSEC_IKE_BENIGN_REINIT __MSABI_LONG(13878)
#define ERROR_IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY __MSABI_LONG(13879)
#define ERROR_IPSEC_IKE_INVALID_CERT_KEYLEN __MSABI_LONG(13881)
#define ERROR_IPSEC_IKE_MM_LIMIT __MSABI_LONG(13882)
#define ERROR_IPSEC_IKE_NEGOTIATION_DISABLED __MSABI_LONG(13883)
#define ERROR_IPSEC_IKE_QM_LIMIT __MSABI_LONG(13884)
#define ERROR_IPSEC_IKE_MM_EXPIRED __MSABI_LONG(13885)
#define ERROR_IPSEC_IKE_PEER_MM_ASSUMED_INVALID __MSABI_LONG(13886)
#define ERROR_IPSEC_IKE_CERT_CHAIN_POLICY_MISMATCH __MSABI_LONG(13887)
#define ERROR_IPSEC_IKE_UNEXPECTED_MESSAGE_ID __MSABI_LONG(13888)
#define ERROR_IPSEC_IKE_INVALID_AUTH_PAYLOAD __MSABI_LONG(13889)
#define ERROR_IPSEC_IKE_DOS_COOKIE_SENT __MSABI_LONG(13890)
#define ERROR_IPSEC_IKE_SHUTTING_DOWN __MSABI_LONG(13891)
#define ERROR_IPSEC_IKE_CGA_AUTH_FAILED __MSABI_LONG(13892)
#define ERROR_IPSEC_IKE_PROCESS_ERR_NATOA __MSABI_LONG(13893)
#define ERROR_IPSEC_IKE_INVALID_MM_FOR_QM __MSABI_LONG(13894)
#define ERROR_IPSEC_IKE_QM_EXPIRED __MSABI_LONG(13895)
#define ERROR_IPSEC_IKE_TOO_MANY_FILTERS __MSABI_LONG(13896)
#define ERROR_IPSEC_IKE_NEG_STATUS_END __MSABI_LONG(13897)
#define ERROR_IPSEC_IKE_KILL_DUMMY_NAP_TUNNEL __MSABI_LONG(13898)
#define ERROR_IPSEC_IKE_INNER_IP_ASSIGNMENT_FAILURE __MSABI_LONG(13899)
#define ERROR_IPSEC_IKE_REQUIRE_CP_PAYLOAD_MISSING __MSABI_LONG(13900)
#define ERROR_IPSEC_KEY_MODULE_IMPERSONATION_NEGOTIATION_PENDING __MSABI_LONG(13901)
#define ERROR_IPSEC_IKE_COEXISTENCE_SUPPRESS __MSABI_LONG(13902)
#define ERROR_IPSEC_IKE_RATELIMIT_DROP __MSABI_LONG(13903)
#define ERROR_IPSEC_IKE_PEER_DOESNT_SUPPORT_MOBIKE __MSABI_LONG(13904)
#define ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE __MSABI_LONG(13905)
#define ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_FAILURE __MSABI_LONG(13906)
#define ERROR_IPSEC_IKE_AUTHORIZATION_FAILURE_WITH_OPTIONAL_RETRY __MSABI_LONG(13907)
#define ERROR_IPSEC_IKE_STRONG_CRED_AUTHORIZATION_AND_CERTMAP_FAILURE __MSABI_LONG(13908)
#define ERROR_IPSEC_IKE_NEG_STATUS_EXTENDED_END __MSABI_LONG(13909)
#define ERROR_IPSEC_BAD_SPI __MSABI_LONG(13910)
#define ERROR_IPSEC_SA_LIFETIME_EXPIRED __MSABI_LONG(13911)
#define ERROR_IPSEC_WRONG_SA __MSABI_LONG(13912)
#define ERROR_IPSEC_REPLAY_CHECK_FAILED __MSABI_LONG(13913)
#define ERROR_IPSEC_INVALID_PACKET __MSABI_LONG(13914)
#define ERROR_IPSEC_INTEGRITY_CHECK_FAILED __MSABI_LONG(13915)
#define ERROR_IPSEC_CLEAR_TEXT_DROP __MSABI_LONG(13916)
#define ERROR_IPSEC_AUTH_FIREWALL_DROP __MSABI_LONG(13917)
#define ERROR_IPSEC_THROTTLE_DROP __MSABI_LONG(13918)
#define ERROR_IPSEC_DOSP_BLOCK __MSABI_LONG(13925)
#define ERROR_IPSEC_DOSP_RECEIVED_MULTICAST __MSABI_LONG(13926)
#define ERROR_IPSEC_DOSP_INVALID_PACKET __MSABI_LONG(13927)
#define ERROR_IPSEC_DOSP_STATE_LOOKUP_FAILED __MSABI_LONG(13928)
#define ERROR_IPSEC_DOSP_MAX_ENTRIES __MSABI_LONG(13929)
#define ERROR_IPSEC_DOSP_KEYMOD_NOT_ALLOWED __MSABI_LONG(13930)
#define ERROR_IPSEC_DOSP_NOT_INSTALLED __MSABI_LONG(13931)
#define ERROR_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES __MSABI_LONG(13932)
#define ERROR_EVT_INVALID_CHANNEL_PATH __MSABI_LONG(15000)
#define ERROR_EVT_INVALID_QUERY __MSABI_LONG(15001)
#define ERROR_EVT_PUBLISHER_METADATA_NOT_FOUND __MSABI_LONG(15002)
#define ERROR_EVT_EVENT_TEMPLATE_NOT_FOUND __MSABI_LONG(15003)
#define ERROR_EVT_INVALID_PUBLISHER_NAME __MSABI_LONG(15004)
#define ERROR_EVT_INVALID_EVENT_DATA __MSABI_LONG(15005)
#define ERROR_EVT_CHANNEL_NOT_FOUND __MSABI_LONG(15007)
#define ERROR_EVT_MALFORMED_XML_TEXT __MSABI_LONG(15008)
#define ERROR_EVT_SUBSCRIPTION_TO_DIRECT_CHANNEL __MSABI_LONG(15009)
#define ERROR_EVT_CONFIGURATION_ERROR __MSABI_LONG(15010)
#define ERROR_EVT_QUERY_RESULT_STALE __MSABI_LONG(15011)
#define ERROR_EVT_QUERY_RESULT_INVALID_POSITION __MSABI_LONG(15012)
#define ERROR_EVT_NON_VALIDATING_MSXML __MSABI_LONG(15013)
#define ERROR_EVT_FILTER_ALREADYSCOPED __MSABI_LONG(15014)
#define ERROR_EVT_FILTER_NOTELTSET __MSABI_LONG(15015)
#define ERROR_EVT_FILTER_INVARG __MSABI_LONG(15016)
#define ERROR_EVT_FILTER_INVTEST __MSABI_LONG(15017)
#define ERROR_EVT_FILTER_INVTYPE __MSABI_LONG(15018)
#define ERROR_EVT_FILTER_PARSEERR __MSABI_LONG(15019)
#define ERROR_EVT_FILTER_UNSUPPORTEDOP __MSABI_LONG(15020)
#define ERROR_EVT_FILTER_UNEXPECTEDTOKEN __MSABI_LONG(15021)
#define ERROR_EVT_INVALID_OPERATION_OVER_ENABLED_DIRECT_CHANNEL __MSABI_LONG(15022)
#define ERROR_EVT_INVALID_CHANNEL_PROPERTY_VALUE __MSABI_LONG(15023)
#define ERROR_EVT_INVALID_PUBLISHER_PROPERTY_VALUE __MSABI_LONG(15024)
#define ERROR_EVT_CHANNEL_CANNOT_ACTIVATE __MSABI_LONG(15025)
#define ERROR_EVT_FILTER_TOO_COMPLEX __MSABI_LONG(15026)
#define ERROR_EVT_MESSAGE_NOT_FOUND __MSABI_LONG(15027)
#define ERROR_EVT_MESSAGE_ID_NOT_FOUND __MSABI_LONG(15028)
#define ERROR_EVT_UNRESOLVED_VALUE_INSERT __MSABI_LONG(15029)
#define ERROR_EVT_UNRESOLVED_PARAMETER_INSERT __MSABI_LONG(15030)
#define ERROR_EVT_MAX_INSERTS_REACHED __MSABI_LONG(15031)
#define ERROR_EVT_EVENT_DEFINITION_NOT_FOUND __MSABI_LONG(15032)
#define ERROR_EVT_MESSAGE_LOCALE_NOT_FOUND __MSABI_LONG(15033)
#define ERROR_EVT_VERSION_TOO_OLD __MSABI_LONG(15034)
#define ERROR_EVT_VERSION_TOO_NEW __MSABI_LONG(15035)
#define ERROR_EVT_CANNOT_OPEN_CHANNEL_OF_QUERY __MSABI_LONG(15036)
#define ERROR_EVT_PUBLISHER_DISABLED __MSABI_LONG(15037)
#define ERROR_EVT_FILTER_OUT_OF_RANGE __MSABI_LONG(15038)
#define ERROR_EC_SUBSCRIPTION_CANNOT_ACTIVATE __MSABI_LONG(15080)
#define ERROR_EC_LOG_DISABLED __MSABI_LONG(15081)
#define ERROR_EC_CIRCULAR_FORWARDING __MSABI_LONG(15082)
#define ERROR_EC_CREDSTORE_FULL __MSABI_LONG(15083)
#define ERROR_EC_CRED_NOT_FOUND __MSABI_LONG(15084)
#define ERROR_EC_NO_ACTIVE_CHANNEL __MSABI_LONG(15085)
#define ERROR_MUI_FILE_NOT_FOUND __MSABI_LONG(15100)
#define ERROR_MUI_INVALID_FILE __MSABI_LONG(15101)
#define ERROR_MUI_INVALID_RC_CONFIG __MSABI_LONG(15102)
#define ERROR_MUI_INVALID_LOCALE_NAME __MSABI_LONG(15103)
#define ERROR_MUI_INVALID_ULTIMATEFALLBACK_NAME __MSABI_LONG(15104)
#define ERROR_MUI_FILE_NOT_LOADED __MSABI_LONG(15105)
#define ERROR_RESOURCE_ENUM_USER_STOP __MSABI_LONG(15106)
#define ERROR_MUI_INTLSETTINGS_UILANG_NOT_INSTALLED __MSABI_LONG(15107)
#define ERROR_MUI_INTLSETTINGS_INVALID_LOCALE_NAME __MSABI_LONG(15108)
#define ERROR_MRM_RUNTIME_NO_DEFAULT_OR_NEUTRAL_RESOURCE __MSABI_LONG(15110)
#define ERROR_MRM_INVALID_PRICONFIG __MSABI_LONG(15111)
#define ERROR_MRM_INVALID_FILE_TYPE __MSABI_LONG(15112)
#define ERROR_MRM_UNKNOWN_QUALIFIER __MSABI_LONG(15113)
#define ERROR_MRM_INVALID_QUALIFIER_VALUE __MSABI_LONG(15114)
#define ERROR_MRM_NO_CANDIDATE __MSABI_LONG(15115)
#define ERROR_MRM_NO_MATCH_OR_DEFAULT_CANDIDATE __MSABI_LONG(15116)
#define ERROR_MRM_RESOURCE_TYPE_MISMATCH __MSABI_LONG(15117)
#define ERROR_MRM_DUPLICATE_MAP_NAME __MSABI_LONG(15118)
#define ERROR_MRM_DUPLICATE_ENTRY __MSABI_LONG(15119)
#define ERROR_MRM_INVALID_RESOURCE_IDENTIFIER __MSABI_LONG(15120)
#define ERROR_MRM_FILEPATH_TOO_LONG __MSABI_LONG(15121)
#define ERROR_MRM_UNSUPPORTED_DIRECTORY_TYPE __MSABI_LONG(15122)
#define ERROR_MRM_INVALID_PRI_FILE __MSABI_LONG(15126)
#define ERROR_MRM_NAMED_RESOURCE_NOT_FOUND __MSABI_LONG(15127)
#define ERROR_MRM_MAP_NOT_FOUND __MSABI_LONG(15135)
#define ERROR_MRM_UNSUPPORTED_PROFILE_TYPE __MSABI_LONG(15136)
#define ERROR_MRM_INVALID_QUALIFIER_OPERATOR __MSABI_LONG(15137)
#define ERROR_MRM_INDETERMINATE_QUALIFIER_VALUE __MSABI_LONG(15138)
#define ERROR_MRM_AUTOMERGE_ENABLED __MSABI_LONG(15139)
#define ERROR_MRM_TOO_MANY_RESOURCES __MSABI_LONG(15140)
#define ERROR_MCA_INVALID_CAPABILITIES_STRING __MSABI_LONG(15200)
#define ERROR_MCA_INVALID_VCP_VERSION __MSABI_LONG(15201)
#define ERROR_MCA_MONITOR_VIOLATES_MCCS_SPECIFICATION __MSABI_LONG(15202)
#define ERROR_MCA_MCCS_VERSION_MISMATCH __MSABI_LONG(15203)
#define ERROR_MCA_UNSUPPORTED_MCCS_VERSION __MSABI_LONG(15204)
#define ERROR_MCA_INTERNAL_ERROR __MSABI_LONG(15205)
#define ERROR_MCA_INVALID_TECHNOLOGY_TYPE_RETURNED __MSABI_LONG(15206)
#define ERROR_MCA_UNSUPPORTED_COLOR_TEMPERATURE __MSABI_LONG(15207)
#define ERROR_AMBIGUOUS_SYSTEM_DEVICE __MSABI_LONG(15250)
#define ERROR_SYSTEM_DEVICE_NOT_FOUND __MSABI_LONG(15299)
#define ERROR_HASH_NOT_SUPPORTED __MSABI_LONG(15300)
#define ERROR_HASH_NOT_PRESENT __MSABI_LONG(15301)
#define ERROR_SECONDARY_IC_PROVIDER_NOT_REGISTERED __MSABI_LONG(15321)
#define ERROR_GPIO_CLIENT_INFORMATION_INVALID __MSABI_LONG(15322)
#define ERROR_GPIO_VERSION_NOT_SUPPORTED __MSABI_LONG(15323)
#define ERROR_GPIO_INVALID_REGISTRATION_PACKET __MSABI_LONG(15324)
#define ERROR_GPIO_OPERATION_DENIED __MSABI_LONG(15325)
#define ERROR_GPIO_INCOMPATIBLE_CONNECT_MODE __MSABI_LONG(15326)
#define ERROR_GPIO_INTERRUPT_ALREADY_UNMASKED __MSABI_LONG(15327)
#define ERROR_CANNOT_SWITCH_RUNLEVEL __MSABI_LONG(15400)
#define ERROR_INVALID_RUNLEVEL_SETTING __MSABI_LONG(15401)
#define ERROR_RUNLEVEL_SWITCH_TIMEOUT __MSABI_LONG(15402)
#define ERROR_RUNLEVEL_SWITCH_AGENT_TIMEOUT __MSABI_LONG(15403)
#define ERROR_RUNLEVEL_SWITCH_IN_PROGRESS __MSABI_LONG(15404)
#define ERROR_SERVICES_FAILED_AUTOSTART __MSABI_LONG(15405)
#define ERROR_COM_TASK_STOP_PENDING __MSABI_LONG(15501)
#define ERROR_INSTALL_OPEN_PACKAGE_FAILED __MSABI_LONG(15600)
#define ERROR_INSTALL_PACKAGE_NOT_FOUND __MSABI_LONG(15601)
#define ERROR_INSTALL_INVALID_PACKAGE __MSABI_LONG(15602)
#define ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED __MSABI_LONG(15603)
#define ERROR_INSTALL_OUT_OF_DISK_SPACE __MSABI_LONG(15604)
#define ERROR_INSTALL_NETWORK_FAILURE __MSABI_LONG(15605)
#define ERROR_INSTALL_REGISTRATION_FAILURE __MSABI_LONG(15606)
#define ERROR_INSTALL_DEREGISTRATION_FAILURE __MSABI_LONG(15607)
#define ERROR_INSTALL_CANCEL __MSABI_LONG(15608)
#define ERROR_INSTALL_FAILED __MSABI_LONG(15609)
#define ERROR_REMOVE_FAILED __MSABI_LONG(15610)
#define ERROR_PACKAGE_ALREADY_EXISTS __MSABI_LONG(15611)
#define ERROR_NEEDS_REMEDIATION __MSABI_LONG(15612)
#define ERROR_INSTALL_PREREQUISITE_FAILED __MSABI_LONG(15613)
#define ERROR_PACKAGE_REPOSITORY_CORRUPTED __MSABI_LONG(15614)
#define ERROR_INSTALL_POLICY_FAILURE __MSABI_LONG(15615)
#define ERROR_PACKAGE_UPDATING __MSABI_LONG(15616)
#define ERROR_DEPLOYMENT_BLOCKED_BY_POLICY __MSABI_LONG(15617)
#define ERROR_PACKAGES_IN_USE __MSABI_LONG(15618)
#define ERROR_RECOVERY_FILE_CORRUPT __MSABI_LONG(15619)
#define ERROR_INVALID_STAGED_SIGNATURE __MSABI_LONG(15620)
#define ERROR_DELETING_EXISTING_APPLICATIONDATA_STORE_FAILED __MSABI_LONG(15621)
#define ERROR_INSTALL_PACKAGE_DOWNGRADE __MSABI_LONG(15622)
#define ERROR_SYSTEM_NEEDS_REMEDIATION __MSABI_LONG(15623)
#define ERROR_APPX_INTEGRITY_FAILURE_CLR_NGEN __MSABI_LONG(15624)
#define ERROR_RESILIENCY_FILE_CORRUPT __MSABI_LONG(15625)
#define ERROR_INSTALL_FIREWALL_SERVICE_NOT_RUNNING __MSABI_LONG(15626)
#define APPMODEL_ERROR_NO_PACKAGE __MSABI_LONG(15700)
#define APPMODEL_ERROR_PACKAGE_RUNTIME_CORRUPT __MSABI_LONG(15701)
#define APPMODEL_ERROR_PACKAGE_IDENTITY_CORRUPT __MSABI_LONG(15702)
#define APPMODEL_ERROR_NO_APPLICATION __MSABI_LONG(15703)
#define ERROR_STATE_LOAD_STORE_FAILED __MSABI_LONG(15800)
#define ERROR_STATE_GET_VERSION_FAILED __MSABI_LONG(15801)
#define ERROR_STATE_SET_VERSION_FAILED __MSABI_LONG(15802)
#define ERROR_STATE_STRUCTURED_RESET_FAILED __MSABI_LONG(15803)
#define ERROR_STATE_OPEN_CONTAINER_FAILED __MSABI_LONG(15804)
#define ERROR_STATE_CREATE_CONTAINER_FAILED __MSABI_LONG(15805)
#define ERROR_STATE_DELETE_CONTAINER_FAILED __MSABI_LONG(15806)
#define ERROR_STATE_READ_SETTING_FAILED __MSABI_LONG(15807)
#define ERROR_STATE_WRITE_SETTING_FAILED __MSABI_LONG(15808)
#define ERROR_STATE_DELETE_SETTING_FAILED __MSABI_LONG(15809)
#define ERROR_STATE_QUERY_SETTING_FAILED __MSABI_LONG(15810)
#define ERROR_STATE_READ_COMPOSITE_SETTING_FAILED __MSABI_LONG(15811)
#define ERROR_STATE_WRITE_COMPOSITE_SETTING_FAILED __MSABI_LONG(15812)
#define ERROR_STATE_ENUMERATE_CONTAINER_FAILED __MSABI_LONG(15813)
#define ERROR_STATE_ENUMERATE_SETTINGS_FAILED __MSABI_LONG(15814)
#define ERROR_STATE_COMPOSITE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED __MSABI_LONG(15815)
#define ERROR_STATE_SETTING_VALUE_SIZE_LIMIT_EXCEEDED __MSABI_LONG(15816)
#define ERROR_STATE_SETTING_NAME_SIZE_LIMIT_EXCEEDED __MSABI_LONG(15817)
#define ERROR_STATE_CONTAINER_NAME_SIZE_LIMIT_EXCEEDED __MSABI_LONG(15818)
#define ERROR_API_UNAVAILABLE __MSABI_LONG(15841)
#define SEVERITY_SUCCESS 0
#define SEVERITY_ERROR 1
#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
#define FAILED(hr) ((HRESULT)(hr) < 0)
#define IS_ERROR(Status) ((unsigned __LONG32)(Status) >> 31==SEVERITY_ERROR)
#define HRESULT_CODE(hr) ((hr) & 0xFFFF)
#define SCODE_CODE(sc) ((sc) & 0xFFFF)
#define HRESULT_FACILITY(hr) (((hr) >> 16) & 0x1fff)
#define SCODE_FACILITY(sc) (((sc) >> 16) & 0x1fff)
#define HRESULT_SEVERITY(hr) (((hr) >> 31) & 0x1)
#define SCODE_SEVERITY(sc) (((sc) >> 31) & 0x1)
#define MAKE_HRESULT(sev,fac,code) ((HRESULT) (((unsigned __LONG32)(sev)<<31) | ((unsigned __LONG32)(fac)<<16) | ((unsigned __LONG32)(code))))
#define MAKE_SCODE(sev,fac,code) ((SCODE) (((unsigned __LONG32)(sev)<<31) | ((unsigned __LONG32)(fac)<<16) | ((unsigned __LONG32)(code))))
#define FACILITY_NT_BIT 0x10000000
#define __HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) : ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)))
#ifdef INLINE_HRESULT_FROM_WIN32
	#ifndef _HRESULT_DEFINED
	#define _HRESULT_DEFINED
	typedef __LONG32 HRESULT;
	#endif
	#ifndef __CRT__NO_INLINE
	__CRT_INLINE HRESULT HRESULT_FROM_WIN32(__LONG32 x)
	{
	return x <= 0 ? (HRESULT)x : (HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000);
	}
	#endif
#else
	#define HRESULT_FROM_WIN32(x) __HRESULT_FROM_WIN32(x)
#endif
#define HRESULT_FROM_NT(x) ((HRESULT) ((x) | FACILITY_NT_BIT))
#define GetScode(hr) ((SCODE) (hr))
#define ResultFromScode(sc) ((HRESULT) (sc))
#define PropagateResult(hrPrevious,scBase) ((HRESULT) scBase)
#if defined (RC_INVOKED) || defined (__WIDL__)
#define _HRESULT_TYPEDEF_(_sc) _sc
#else
#define _HRESULT_TYPEDEF_(_sc) ((HRESULT)_sc)
#endif
#define NOERROR 0
#define E_UNEXPECTED _HRESULT_TYPEDEF_(0x8000FFFF)
#define E_NOTIMPL _HRESULT_TYPEDEF_(0x80004001)
#define E_OUTOFMEMORY _HRESULT_TYPEDEF_(0x8007000E)
#define E_INVALIDARG _HRESULT_TYPEDEF_(0x80070057)
#define E_NOINTERFACE _HRESULT_TYPEDEF_(0x80004002)
#define E_POINTER _HRESULT_TYPEDEF_(0x80004003)
#define E_HANDLE _HRESULT_TYPEDEF_(0x80070006)
#define E_ABORT _HRESULT_TYPEDEF_(0x80004004)
#define E_FAIL _HRESULT_TYPEDEF_(0x80004005)
#define E_ACCESSDENIED _HRESULT_TYPEDEF_(0x80070005)
#define E_PENDING _HRESULT_TYPEDEF_(0x8000000A)
#define E_NOT_SUFFICIENT_BUFFER HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
#define CO_E_INIT_TLS _HRESULT_TYPEDEF_(0x80004006)
#define CO_E_INIT_SHARED_ALLOCATOR _HRESULT_TYPEDEF_(0x80004007)
#define CO_E_INIT_MEMORY_ALLOCATOR _HRESULT_TYPEDEF_(0x80004008)
#define CO_E_INIT_CLASS_CACHE _HRESULT_TYPEDEF_(0x80004009)
#define CO_E_INIT_RPC_CHANNEL _HRESULT_TYPEDEF_(0x8000400A)
#define CO_E_INIT_TLS_SET_CHANNEL_CONTROL _HRESULT_TYPEDEF_(0x8000400B)
#define CO_E_INIT_TLS_CHANNEL_CONTROL _HRESULT_TYPEDEF_(0x8000400C)
#define CO_E_INIT_UNACCEPTED_USER_ALLOCATOR _HRESULT_TYPEDEF_(0x8000400D)
#define CO_E_INIT_SCM_MUTEX_EXISTS _HRESULT_TYPEDEF_(0x8000400E)
#define CO_E_INIT_SCM_FILE_MAPPING_EXISTS _HRESULT_TYPEDEF_(0x8000400F)
#define CO_E_INIT_SCM_MAP_VIEW_OF_FILE _HRESULT_TYPEDEF_(0x80004010)
#define CO_E_INIT_SCM_EXEC_FAILURE _HRESULT_TYPEDEF_(0x80004011)
#define CO_E_INIT_ONLY_SINGLE_THREADED _HRESULT_TYPEDEF_(0x80004012)
#define CO_E_CANT_REMOTE _HRESULT_TYPEDEF_(0x80004013)
#define CO_E_BAD_SERVER_NAME _HRESULT_TYPEDEF_(0x80004014)
#define CO_E_WRONG_SERVER_IDENTITY _HRESULT_TYPEDEF_(0x80004015)
#define CO_E_OLE1DDE_DISABLED _HRESULT_TYPEDEF_(0x80004016)
#define CO_E_RUNAS_SYNTAX _HRESULT_TYPEDEF_(0x80004017)
#define CO_E_CREATEPROCESS_FAILURE _HRESULT_TYPEDEF_(0x80004018)
#define CO_E_RUNAS_CREATEPROCESS_FAILURE _HRESULT_TYPEDEF_(0x80004019)
#define CO_E_RUNAS_LOGON_FAILURE _HRESULT_TYPEDEF_(0x8000401A)
#define CO_E_LAUNCH_PERMSSION_DENIED _HRESULT_TYPEDEF_(0x8000401B)
#define CO_E_START_SERVICE_FAILURE _HRESULT_TYPEDEF_(0x8000401C)
#define CO_E_REMOTE_COMMUNICATION_FAILURE _HRESULT_TYPEDEF_(0x8000401D)
#define CO_E_SERVER_START_TIMEOUT _HRESULT_TYPEDEF_(0x8000401E)
#define CO_E_CLSREG_INCONSISTENT _HRESULT_TYPEDEF_(0x8000401F)
#define CO_E_IIDREG_INCONSISTENT _HRESULT_TYPEDEF_(0x80004020)
#define CO_E_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x80004021)
#define CO_E_RELOAD_DLL _HRESULT_TYPEDEF_(0x80004022)
#define CO_E_MSI_ERROR _HRESULT_TYPEDEF_(0x80004023)
#define CO_E_ATTEMPT_TO_CREATE_OUTSIDE_CLIENT_CONTEXT _HRESULT_TYPEDEF_(0x80004024)
#define CO_E_SERVER_PAUSED _HRESULT_TYPEDEF_(0x80004025)
#define CO_E_SERVER_NOT_PAUSED _HRESULT_TYPEDEF_(0x80004026)
#define CO_E_CLASS_DISABLED _HRESULT_TYPEDEF_(0x80004027)
#define CO_E_CLRNOTAVAILABLE _HRESULT_TYPEDEF_(0x80004028)
#define CO_E_ASYNC_WORK_REJECTED _HRESULT_TYPEDEF_(0x80004029)
#define CO_E_SERVER_INIT_TIMEOUT _HRESULT_TYPEDEF_(0x8000402A)
#define CO_E_NO_SECCTX_IN_ACTIVATE _HRESULT_TYPEDEF_(0x8000402B)
#define CO_E_TRACKER_CONFIG _HRESULT_TYPEDEF_(0x80004030)
#define CO_E_THREADPOOL_CONFIG _HRESULT_TYPEDEF_(0x80004031)
#define CO_E_SXS_CONFIG _HRESULT_TYPEDEF_(0x80004032)
#define CO_E_MALFORMED_SPN _HRESULT_TYPEDEF_(0x80004033)
#define S_OK ((HRESULT)0x00000000)
#define S_FALSE ((HRESULT)0x00000001)
#define OLE_E_FIRST ((HRESULT)0x80040000)
#define OLE_E_LAST ((HRESULT)0x800400FF)
#define OLE_S_FIRST ((HRESULT)0x00040000)
#define OLE_S_LAST ((HRESULT)0x000400FF)
#define OLE_E_OLEVERB _HRESULT_TYPEDEF_(0x80040000)
#define OLE_E_ADVF _HRESULT_TYPEDEF_(0x80040001)
#define OLE_E_ENUM_NOMORE _HRESULT_TYPEDEF_(0x80040002)
#define OLE_E_ADVISENOTSUPPORTED _HRESULT_TYPEDEF_(0x80040003)
#define OLE_E_NOCONNECTION _HRESULT_TYPEDEF_(0x80040004)
#define OLE_E_NOTRUNNING _HRESULT_TYPEDEF_(0x80040005)
#define OLE_E_NOCACHE _HRESULT_TYPEDEF_(0x80040006)
#define OLE_E_BLANK _HRESULT_TYPEDEF_(0x80040007)
#define OLE_E_CLASSDIFF _HRESULT_TYPEDEF_(0x80040008)
#define OLE_E_CANT_GETMONIKER _HRESULT_TYPEDEF_(0x80040009)
#define OLE_E_CANT_BINDTOSOURCE _HRESULT_TYPEDEF_(0x8004000A)
#define OLE_E_STATIC _HRESULT_TYPEDEF_(0x8004000B)
#define OLE_E_PROMPTSAVECANCELLED _HRESULT_TYPEDEF_(0x8004000C)
#define OLE_E_INVALIDRECT _HRESULT_TYPEDEF_(0x8004000D)
#define OLE_E_WRONGCOMPOBJ _HRESULT_TYPEDEF_(0x8004000E)
#define OLE_E_INVALIDHWND _HRESULT_TYPEDEF_(0x8004000F)
#define OLE_E_NOT_INPLACEACTIVE _HRESULT_TYPEDEF_(0x80040010)
#define OLE_E_CANTCONVERT _HRESULT_TYPEDEF_(0x80040011)
#define OLE_E_NOSTORAGE _HRESULT_TYPEDEF_(0x80040012)
#define DV_E_FORMATETC _HRESULT_TYPEDEF_(0x80040064)
#define DV_E_DVTARGETDEVICE _HRESULT_TYPEDEF_(0x80040065)
#define DV_E_STGMEDIUM _HRESULT_TYPEDEF_(0x80040066)
#define DV_E_STATDATA _HRESULT_TYPEDEF_(0x80040067)
#define DV_E_LINDEX _HRESULT_TYPEDEF_(0x80040068)
#define DV_E_TYMED _HRESULT_TYPEDEF_(0x80040069)
#define DV_E_CLIPFORMAT _HRESULT_TYPEDEF_(0x8004006A)
#define DV_E_DVASPECT _HRESULT_TYPEDEF_(0x8004006B)
#define DV_E_DVTARGETDEVICE_SIZE _HRESULT_TYPEDEF_(0x8004006C)
#define DV_E_NOIVIEWOBJECT _HRESULT_TYPEDEF_(0x8004006D)
#define DRAGDROP_E_FIRST __MSABI_LONG(0x80040100)
#define DRAGDROP_E_LAST __MSABI_LONG(0x8004010F)
#define DRAGDROP_S_FIRST __MSABI_LONG(0x00040100)
#define DRAGDROP_S_LAST __MSABI_LONG(0x0004010F)
#define DRAGDROP_E_NOTREGISTERED _HRESULT_TYPEDEF_(0x80040100)
#define DRAGDROP_E_ALREADYREGISTERED _HRESULT_TYPEDEF_(0x80040101)
#define DRAGDROP_E_INVALIDHWND _HRESULT_TYPEDEF_(0x80040102)
#define CLASSFACTORY_E_FIRST __MSABI_LONG(0x80040110)
#define CLASSFACTORY_E_LAST __MSABI_LONG(0x8004011F)
#define CLASSFACTORY_S_FIRST __MSABI_LONG(0x00040110)
#define CLASSFACTORY_S_LAST __MSABI_LONG(0x0004011F)
#define CLASS_E_NOAGGREGATION _HRESULT_TYPEDEF_(0x80040110)
#define CLASS_E_CLASSNOTAVAILABLE _HRESULT_TYPEDEF_(0x80040111)
#define CLASS_E_NOTLICENSED _HRESULT_TYPEDEF_(0x80040112)
#define MARSHAL_E_FIRST __MSABI_LONG(0x80040120)
#define MARSHAL_E_LAST __MSABI_LONG(0x8004012F)
#define MARSHAL_S_FIRST __MSABI_LONG(0x00040120)
#define MARSHAL_S_LAST __MSABI_LONG(0x0004012F)
#define DATA_E_FIRST __MSABI_LONG(0x80040130)
#define DATA_E_LAST __MSABI_LONG(0x8004013F)
#define DATA_S_FIRST __MSABI_LONG(0x00040130)
#define DATA_S_LAST __MSABI_LONG(0x0004013F)
#define VIEW_E_FIRST __MSABI_LONG(0x80040140)
#define VIEW_E_LAST __MSABI_LONG(0x8004014F)
#define VIEW_S_FIRST __MSABI_LONG(0x00040140)
#define VIEW_S_LAST __MSABI_LONG(0x0004014F)
#define VIEW_E_DRAW _HRESULT_TYPEDEF_(0x80040140)
#define REGDB_E_FIRST __MSABI_LONG(0x80040150)
#define REGDB_E_LAST __MSABI_LONG(0x8004015F)
#define REGDB_S_FIRST __MSABI_LONG(0x00040150)
#define REGDB_S_LAST __MSABI_LONG(0x0004015F)
#define REGDB_E_READREGDB _HRESULT_TYPEDEF_(0x80040150)
#define REGDB_E_WRITEREGDB _HRESULT_TYPEDEF_(0x80040151)
#define REGDB_E_KEYMISSING _HRESULT_TYPEDEF_(0x80040152)
#define REGDB_E_INVALIDVALUE _HRESULT_TYPEDEF_(0x80040153)
#define REGDB_E_CLASSNOTREG _HRESULT_TYPEDEF_(0x80040154)
#define REGDB_E_IIDNOTREG _HRESULT_TYPEDEF_(0x80040155)
#define REGDB_E_BADTHREADINGMODEL _HRESULT_TYPEDEF_(0x80040156)
#define CAT_E_FIRST __MSABI_LONG(0x80040160)
#define CAT_E_LAST __MSABI_LONG(0x80040161)
#define CAT_E_CATIDNOEXIST _HRESULT_TYPEDEF_(0x80040160)
#define CAT_E_NODESCRIPTION _HRESULT_TYPEDEF_(0x80040161)
#define CS_E_FIRST __MSABI_LONG(0x80040164)
#define CS_E_LAST __MSABI_LONG(0x8004016F)
#define CS_E_PACKAGE_NOTFOUND _HRESULT_TYPEDEF_(0x80040164)
#define CS_E_NOT_DELETABLE _HRESULT_TYPEDEF_(0x80040165)
#define CS_E_CLASS_NOTFOUND _HRESULT_TYPEDEF_(0x80040166)
#define CS_E_INVALID_VERSION _HRESULT_TYPEDEF_(0x80040167)
#define CS_E_NO_CLASSSTORE _HRESULT_TYPEDEF_(0x80040168)
#define CS_E_OBJECT_NOTFOUND _HRESULT_TYPEDEF_(0x80040169)
#define CS_E_OBJECT_ALREADY_EXISTS _HRESULT_TYPEDEF_(0x8004016A)
#define CS_E_INVALID_PATH _HRESULT_TYPEDEF_(0x8004016B)
#define CS_E_NETWORK_ERROR _HRESULT_TYPEDEF_(0x8004016C)
#define CS_E_ADMIN_LIMIT_EXCEEDED _HRESULT_TYPEDEF_(0x8004016D)
#define CS_E_SCHEMA_MISMATCH _HRESULT_TYPEDEF_(0x8004016E)
#define CS_E_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x8004016F)
#define CACHE_E_FIRST __MSABI_LONG(0x80040170)
#define CACHE_E_LAST __MSABI_LONG(0x8004017F)
#define CACHE_S_FIRST __MSABI_LONG(0x00040170)
#define CACHE_S_LAST __MSABI_LONG(0x0004017F)
#define CACHE_E_NOCACHE_UPDATED _HRESULT_TYPEDEF_(0x80040170)
#define OLEOBJ_E_FIRST __MSABI_LONG(0x80040180)
#define OLEOBJ_E_LAST __MSABI_LONG(0x8004018F)
#define OLEOBJ_S_FIRST __MSABI_LONG(0x00040180)
#define OLEOBJ_S_LAST __MSABI_LONG(0x0004018F)
#define OLEOBJ_E_NOVERBS _HRESULT_TYPEDEF_(0x80040180)
#define OLEOBJ_E_INVALIDVERB _HRESULT_TYPEDEF_(0x80040181)
#define CLIENTSITE_E_FIRST __MSABI_LONG(0x80040190)
#define CLIENTSITE_E_LAST __MSABI_LONG(0x8004019F)
#define CLIENTSITE_S_FIRST __MSABI_LONG(0x00040190)
#define CLIENTSITE_S_LAST __MSABI_LONG(0x0004019F)
#define INPLACE_E_NOTUNDOABLE _HRESULT_TYPEDEF_(0x800401A0)
#define INPLACE_E_NOTOOLSPACE _HRESULT_TYPEDEF_(0x800401A1)
#define INPLACE_E_FIRST __MSABI_LONG(0x800401A0)
#define INPLACE_E_LAST __MSABI_LONG(0x800401AF)
#define INPLACE_S_FIRST __MSABI_LONG(0x000401A0)
#define INPLACE_S_LAST __MSABI_LONG(0x000401AF)
#define ENUM_E_FIRST __MSABI_LONG(0x800401B0)
#define ENUM_E_LAST __MSABI_LONG(0x800401BF)
#define ENUM_S_FIRST __MSABI_LONG(0x000401B0)
#define ENUM_S_LAST __MSABI_LONG(0x000401BF)
#define CONVERT10_E_FIRST __MSABI_LONG(0x800401C0)
#define CONVERT10_E_LAST __MSABI_LONG(0x800401CF)
#define CONVERT10_S_FIRST __MSABI_LONG(0x000401C0)
#define CONVERT10_S_LAST __MSABI_LONG(0x000401CF)
#define CONVERT10_E_OLESTREAM_GET _HRESULT_TYPEDEF_(0x800401C0)
#define CONVERT10_E_OLESTREAM_PUT _HRESULT_TYPEDEF_(0x800401C1)
#define CONVERT10_E_OLESTREAM_FMT _HRESULT_TYPEDEF_(0x800401C2)
#define CONVERT10_E_OLESTREAM_BITMAP_TO_DIB _HRESULT_TYPEDEF_(0x800401C3)
#define CONVERT10_E_STG_FMT _HRESULT_TYPEDEF_(0x800401C4)
#define CONVERT10_E_STG_NO_STD_STREAM _HRESULT_TYPEDEF_(0x800401C5)
#define CONVERT10_E_STG_DIB_TO_BITMAP _HRESULT_TYPEDEF_(0x800401C6)
#define CLIPBRD_E_FIRST __MSABI_LONG(0x800401D0)
#define CLIPBRD_E_LAST __MSABI_LONG(0x800401DF)
#define CLIPBRD_S_FIRST __MSABI_LONG(0x000401D0)
#define CLIPBRD_S_LAST __MSABI_LONG(0x000401DF)
#define CLIPBRD_E_CANT_OPEN _HRESULT_TYPEDEF_(0x800401D0)
#define CLIPBRD_E_CANT_EMPTY _HRESULT_TYPEDEF_(0x800401D1)
#define CLIPBRD_E_CANT_SET _HRESULT_TYPEDEF_(0x800401D2)
#define CLIPBRD_E_BAD_DATA _HRESULT_TYPEDEF_(0x800401D3)
#define CLIPBRD_E_CANT_CLOSE _HRESULT_TYPEDEF_(0x800401D4)
#define MK_E_FIRST __MSABI_LONG(0x800401E0)
#define MK_E_LAST __MSABI_LONG(0x800401EF)
#define MK_S_FIRST __MSABI_LONG(0x000401E0)
#define MK_S_LAST __MSABI_LONG(0x000401EF)
#define MK_E_CONNECTMANUALLY _HRESULT_TYPEDEF_(0x800401E0)
#define MK_E_EXCEEDEDDEADLINE _HRESULT_TYPEDEF_(0x800401E1)
#define MK_E_NEEDGENERIC _HRESULT_TYPEDEF_(0x800401E2)
#define MK_E_UNAVAILABLE _HRESULT_TYPEDEF_(0x800401E3)
#define MK_E_SYNTAX _HRESULT_TYPEDEF_(0x800401E4)
#define MK_E_NOOBJECT _HRESULT_TYPEDEF_(0x800401E5)
#define MK_E_INVALIDEXTENSION _HRESULT_TYPEDEF_(0x800401E6)
#define MK_E_INTERMEDIATEINTERFACENOTSUPPORTED _HRESULT_TYPEDEF_(0x800401E7)
#define MK_E_NOTBINDABLE _HRESULT_TYPEDEF_(0x800401E8)
#define MK_E_NOTBOUND _HRESULT_TYPEDEF_(0x800401E9)
#define MK_E_CANTOPENFILE _HRESULT_TYPEDEF_(0x800401EA)
#define MK_E_MUSTBOTHERUSER _HRESULT_TYPEDEF_(0x800401EB)
#define MK_E_NOINVERSE _HRESULT_TYPEDEF_(0x800401EC)
#define MK_E_NOSTORAGE _HRESULT_TYPEDEF_(0x800401ED)
#define MK_E_NOPREFIX _HRESULT_TYPEDEF_(0x800401EE)
#define MK_E_ENUMERATION_FAILED _HRESULT_TYPEDEF_(0x800401EF)
#define CO_E_FIRST __MSABI_LONG(0x800401F0)
#define CO_E_LAST __MSABI_LONG(0x800401FF)
#define CO_S_FIRST __MSABI_LONG(0x000401F0)
#define CO_S_LAST __MSABI_LONG(0x000401FF)
#define CO_E_NOTINITIALIZED _HRESULT_TYPEDEF_(0x800401F0)
#define CO_E_ALREADYINITIALIZED _HRESULT_TYPEDEF_(0x800401F1)
#define CO_E_CANTDETERMINECLASS _HRESULT_TYPEDEF_(0x800401F2)
#define CO_E_CLASSSTRING _HRESULT_TYPEDEF_(0x800401F3)
#define CO_E_IIDSTRING _HRESULT_TYPEDEF_(0x800401F4)
#define CO_E_APPNOTFOUND _HRESULT_TYPEDEF_(0x800401F5)
#define CO_E_APPSINGLEUSE _HRESULT_TYPEDEF_(0x800401F6)
#define CO_E_ERRORINAPP _HRESULT_TYPEDEF_(0x800401F7)
#define CO_E_DLLNOTFOUND _HRESULT_TYPEDEF_(0x800401F8)
#define CO_E_ERRORINDLL _HRESULT_TYPEDEF_(0x800401F9)
#define CO_E_WRONGOSFORAPP _HRESULT_TYPEDEF_(0x800401FA)
#define CO_E_OBJNOTREG _HRESULT_TYPEDEF_(0x800401FB)
#define CO_E_OBJISREG _HRESULT_TYPEDEF_(0x800401FC)
#define CO_E_OBJNOTCONNECTED _HRESULT_TYPEDEF_(0x800401FD)
#define CO_E_APPDIDNTREG _HRESULT_TYPEDEF_(0x800401FE)
#define CO_E_RELEASED _HRESULT_TYPEDEF_(0x800401FF)
#define EVENT_E_FIRST __MSABI_LONG(0x80040200)
#define EVENT_E_LAST __MSABI_LONG(0x8004021F)
#define EVENT_S_FIRST __MSABI_LONG(0x00040200)
#define EVENT_S_LAST __MSABI_LONG(0x0004021F)
#define EVENT_S_SOME_SUBSCRIBERS_FAILED _HRESULT_TYPEDEF_(0x00040200)
#define EVENT_E_ALL_SUBSCRIBERS_FAILED _HRESULT_TYPEDEF_(0x80040201)
#define EVENT_S_NOSUBSCRIBERS _HRESULT_TYPEDEF_(0x00040202)
#define EVENT_E_QUERYSYNTAX _HRESULT_TYPEDEF_(0x80040203)
#define EVENT_E_QUERYFIELD _HRESULT_TYPEDEF_(0x80040204)
#define EVENT_E_INTERNALEXCEPTION _HRESULT_TYPEDEF_(0x80040205)
#define EVENT_E_INTERNALERROR _HRESULT_TYPEDEF_(0x80040206)
#define EVENT_E_INVALID_PER_USER_SID _HRESULT_TYPEDEF_(0x80040207)
#define EVENT_E_USER_EXCEPTION _HRESULT_TYPEDEF_(0x80040208)
#define EVENT_E_TOO_MANY_METHODS _HRESULT_TYPEDEF_(0x80040209)
#define EVENT_E_MISSING_EVENTCLASS _HRESULT_TYPEDEF_(0x8004020A)
#define EVENT_E_NOT_ALL_REMOVED _HRESULT_TYPEDEF_(0x8004020B)
#define EVENT_E_COMPLUS_NOT_INSTALLED _HRESULT_TYPEDEF_(0x8004020C)
#define EVENT_E_CANT_MODIFY_OR_DELETE_UNCONFIGURED_OBJECT _HRESULT_TYPEDEF_(0x8004020D)
#define EVENT_E_CANT_MODIFY_OR_DELETE_CONFIGURED_OBJECT _HRESULT_TYPEDEF_(0x8004020E)
#define EVENT_E_INVALID_EVENT_CLASS_PARTITION _HRESULT_TYPEDEF_(0x8004020F)
#define EVENT_E_PER_USER_SID_NOT_LOGGED_ON _HRESULT_TYPEDEF_(0x80040210)
#define XACT_E_FIRST 0x8004D000
#define XACT_E_LAST 0x8004D029
#define XACT_S_FIRST 0x0004D000
#define XACT_S_LAST 0x0004D010
#define XACT_E_ALREADYOTHERSINGLEPHASE _HRESULT_TYPEDEF_(0x8004D000)
#define XACT_E_CANTRETAIN _HRESULT_TYPEDEF_(0x8004D001)
#define XACT_E_COMMITFAILED _HRESULT_TYPEDEF_(0x8004D002)
#define XACT_E_COMMITPREVENTED _HRESULT_TYPEDEF_(0x8004D003)
#define XACT_E_HEURISTICABORT _HRESULT_TYPEDEF_(0x8004D004)
#define XACT_E_HEURISTICCOMMIT _HRESULT_TYPEDEF_(0x8004D005)
#define XACT_E_HEURISTICDAMAGE _HRESULT_TYPEDEF_(0x8004D006)
#define XACT_E_HEURISTICDANGER _HRESULT_TYPEDEF_(0x8004D007)
#define XACT_E_ISOLATIONLEVEL _HRESULT_TYPEDEF_(0x8004D008)
#define XACT_E_NOASYNC _HRESULT_TYPEDEF_(0x8004D009)
#define XACT_E_NOENLIST _HRESULT_TYPEDEF_(0x8004D00A)
#define XACT_E_NOISORETAIN _HRESULT_TYPEDEF_(0x8004D00B)
#define XACT_E_NORESOURCE _HRESULT_TYPEDEF_(0x8004D00C)
#define XACT_E_NOTCURRENT _HRESULT_TYPEDEF_(0x8004D00D)
#define XACT_E_NOTRANSACTION _HRESULT_TYPEDEF_(0x8004D00E)
#define XACT_E_NOTSUPPORTED _HRESULT_TYPEDEF_(0x8004D00F)
#define XACT_E_UNKNOWNRMGRID _HRESULT_TYPEDEF_(0x8004D010)
#define XACT_E_WRONGSTATE _HRESULT_TYPEDEF_(0x8004D011)
#define XACT_E_WRONGUOW _HRESULT_TYPEDEF_(0x8004D012)
#define XACT_E_XTIONEXISTS _HRESULT_TYPEDEF_(0x8004D013)
#define XACT_E_NOIMPORTOBJECT _HRESULT_TYPEDEF_(0x8004D014)
#define XACT_E_INVALIDCOOKIE _HRESULT_TYPEDEF_(0x8004D015)
#define XACT_E_INDOUBT _HRESULT_TYPEDEF_(0x8004D016)
#define XACT_E_NOTIMEOUT _HRESULT_TYPEDEF_(0x8004D017)
#define XACT_E_ALREADYINPROGRESS _HRESULT_TYPEDEF_(0x8004D018)
#define XACT_E_ABORTED _HRESULT_TYPEDEF_(0x8004D019)
#define XACT_E_LOGFULL _HRESULT_TYPEDEF_(0x8004D01A)
#define XACT_E_TMNOTAVAILABLE _HRESULT_TYPEDEF_(0x8004D01B)
#define XACT_E_CONNECTION_DOWN _HRESULT_TYPEDEF_(0x8004D01C)
#define XACT_E_CONNECTION_DENIED _HRESULT_TYPEDEF_(0x8004D01D)
#define XACT_E_REENLISTTIMEOUT _HRESULT_TYPEDEF_(0x8004D01E)
#define XACT_E_TIP_CONNECT_FAILED _HRESULT_TYPEDEF_(0x8004D01F)
#define XACT_E_TIP_PROTOCOL_ERROR _HRESULT_TYPEDEF_(0x8004D020)
#define XACT_E_TIP_PULL_FAILED _HRESULT_TYPEDEF_(0x8004D021)
#define XACT_E_DEST_TMNOTAVAILABLE _HRESULT_TYPEDEF_(0x8004D022)
#define XACT_E_TIP_DISABLED _HRESULT_TYPEDEF_(0x8004D023)
#define XACT_E_NETWORK_TX_DISABLED _HRESULT_TYPEDEF_(0x8004D024)
#define XACT_E_PARTNER_NETWORK_TX_DISABLED _HRESULT_TYPEDEF_(0x8004D025)
#define XACT_E_XA_TX_DISABLED _HRESULT_TYPEDEF_(0x8004D026)
#define XACT_E_UNABLE_TO_READ_DTC_CONFIG _HRESULT_TYPEDEF_(0x8004D027)
#define XACT_E_UNABLE_TO_LOAD_DTC_PROXY _HRESULT_TYPEDEF_(0x8004D028)
#define XACT_E_ABORTING _HRESULT_TYPEDEF_(0x8004D029)
#define XACT_E_CLERKNOTFOUND _HRESULT_TYPEDEF_(0x8004D080)
#define XACT_E_CLERKEXISTS _HRESULT_TYPEDEF_(0x8004D081)
#define XACT_E_RECOVERYINPROGRESS _HRESULT_TYPEDEF_(0x8004D082)
#define XACT_E_TRANSACTIONCLOSED _HRESULT_TYPEDEF_(0x8004D083)
#define XACT_E_INVALIDLSN _HRESULT_TYPEDEF_(0x8004D084)
#define XACT_E_REPLAYREQUEST _HRESULT_TYPEDEF_(0x8004D085)
#define XACT_S_ASYNC _HRESULT_TYPEDEF_(0x0004D000)
#define XACT_S_DEFECT _HRESULT_TYPEDEF_(0x0004D001)
#define XACT_S_READONLY _HRESULT_TYPEDEF_(0x0004D002)
#define XACT_S_SOMENORETAIN _HRESULT_TYPEDEF_(0x0004D003)
#define XACT_S_OKINFORM _HRESULT_TYPEDEF_(0x0004D004)
#define XACT_S_MADECHANGESCONTENT _HRESULT_TYPEDEF_(0x0004D005)
#define XACT_S_MADECHANGESINFORM _HRESULT_TYPEDEF_(0x0004D006)
#define XACT_S_ALLNORETAIN _HRESULT_TYPEDEF_(0x0004D007)
#define XACT_S_ABORTING _HRESULT_TYPEDEF_(0x0004D008)
#define XACT_S_SINGLEPHASE _HRESULT_TYPEDEF_(0x0004D009)
#define XACT_S_LOCALLY_OK _HRESULT_TYPEDEF_(0x0004D00A)
#define XACT_S_LASTRESOURCEMANAGER _HRESULT_TYPEDEF_(0x0004D010)
#define CONTEXT_E_FIRST __MSABI_LONG(0x8004E000)
#define CONTEXT_E_LAST __MSABI_LONG(0x8004E02F)
#define CONTEXT_S_FIRST __MSABI_LONG(0x0004E000)
#define CONTEXT_S_LAST __MSABI_LONG(0x0004E02F)
#define CONTEXT_E_ABORTED _HRESULT_TYPEDEF_(0x8004E002)
#define CONTEXT_E_ABORTING _HRESULT_TYPEDEF_(0x8004E003)
#define CONTEXT_E_NOCONTEXT _HRESULT_TYPEDEF_(0x8004E004)
#define CONTEXT_E_WOULD_DEADLOCK _HRESULT_TYPEDEF_(0x8004E005)
#define CONTEXT_E_SYNCH_TIMEOUT _HRESULT_TYPEDEF_(0x8004E006)
#define CONTEXT_E_OLDREF _HRESULT_TYPEDEF_(0x8004E007)
#define CONTEXT_E_ROLENOTFOUND _HRESULT_TYPEDEF_(0x8004E00C)
#define CONTEXT_E_TMNOTAVAILABLE _HRESULT_TYPEDEF_(0x8004E00F)
#define CO_E_ACTIVATIONFAILED _HRESULT_TYPEDEF_(0x8004E021)
#define CO_E_ACTIVATIONFAILED_EVENTLOGGED _HRESULT_TYPEDEF_(0x8004E022)
#define CO_E_ACTIVATIONFAILED_CATALOGERROR _HRESULT_TYPEDEF_(0x8004E023)
#define CO_E_ACTIVATIONFAILED_TIMEOUT _HRESULT_TYPEDEF_(0x8004E024)
#define CO_E_INITIALIZATIONFAILED _HRESULT_TYPEDEF_(0x8004E025)
#define CONTEXT_E_NOJIT _HRESULT_TYPEDEF_(0x8004E026)
#define CONTEXT_E_NOTRANSACTION _HRESULT_TYPEDEF_(0x8004E027)
#define CO_E_THREADINGMODEL_CHANGED _HRESULT_TYPEDEF_(0x8004E028)
#define CO_E_NOIISINTRINSICS _HRESULT_TYPEDEF_(0x8004E029)
#define CO_E_NOCOOKIES _HRESULT_TYPEDEF_(0x8004E02A)
#define CO_E_DBERROR _HRESULT_TYPEDEF_(0x8004E02B)
#define CO_E_NOTPOOLED _HRESULT_TYPEDEF_(0x8004E02C)
#define CO_E_NOTCONSTRUCTED _HRESULT_TYPEDEF_(0x8004E02D)
#define CO_E_NOSYNCHRONIZATION _HRESULT_TYPEDEF_(0x8004E02E)
#define CO_E_ISOLEVELMISMATCH _HRESULT_TYPEDEF_(0x8004E02F)
#define OLE_S_USEREG _HRESULT_TYPEDEF_(0x00040000)
#define OLE_S_STATIC _HRESULT_TYPEDEF_(0x00040001)
#define OLE_S_MAC_CLIPFORMAT _HRESULT_TYPEDEF_(0x00040002)
#define DRAGDROP_S_DROP _HRESULT_TYPEDEF_(0x00040100)
#define DRAGDROP_S_CANCEL _HRESULT_TYPEDEF_(0x00040101)
#define DRAGDROP_S_USEDEFAULTCURSORS _HRESULT_TYPEDEF_(0x00040102)
#define DATA_S_SAMEFORMATETC _HRESULT_TYPEDEF_(0x00040130)
#define VIEW_S_ALREADY_FROZEN _HRESULT_TYPEDEF_(0x00040140)
#define CACHE_S_FORMATETC_NOTSUPPORTED _HRESULT_TYPEDEF_(0x00040170)
#define CACHE_S_SAMECACHE _HRESULT_TYPEDEF_(0x00040171)
#define CACHE_S_SOMECACHES_NOTUPDATED _HRESULT_TYPEDEF_(0x00040172)
#define OLEOBJ_S_INVALIDVERB _HRESULT_TYPEDEF_(0x00040180)
#define OLEOBJ_S_CANNOT_DOVERB_NOW _HRESULT_TYPEDEF_(0x00040181)
#define OLEOBJ_S_INVALIDHWND _HRESULT_TYPEDEF_(0x00040182)
#define INPLACE_S_TRUNCATED _HRESULT_TYPEDEF_(0x000401A0)
#define CONVERT10_S_NO_PRESENTATION _HRESULT_TYPEDEF_(0x000401C0)
#define MK_S_REDUCED_TO_SELF _HRESULT_TYPEDEF_(0x000401E2)
#define MK_S_ME _HRESULT_TYPEDEF_(0x000401E4)
#define MK_S_HIM _HRESULT_TYPEDEF_(0x000401E5)
#define MK_S_US _HRESULT_TYPEDEF_(0x000401E6)
#define MK_S_MONIKERALREADYREGISTERED _HRESULT_TYPEDEF_(0x000401E7)
#define SCHED_S_TASK_READY _HRESULT_TYPEDEF_(0x00041300)
#define SCHED_S_TASK_RUNNING _HRESULT_TYPEDEF_(0x00041301)
#define SCHED_S_TASK_DISABLED _HRESULT_TYPEDEF_(0x00041302)
#define SCHED_S_TASK_HAS_NOT_RUN _HRESULT_TYPEDEF_(0x00041303)
#define SCHED_S_TASK_NO_MORE_RUNS _HRESULT_TYPEDEF_(0x00041304)
#define SCHED_S_TASK_NOT_SCHEDULED _HRESULT_TYPEDEF_(0x00041305)
#define SCHED_S_TASK_TERMINATED _HRESULT_TYPEDEF_(0x00041306)
#define SCHED_S_TASK_NO_VALID_TRIGGERS _HRESULT_TYPEDEF_(0x00041307)
#define SCHED_S_EVENT_TRIGGER _HRESULT_TYPEDEF_(0x00041308)
#define SCHED_E_TRIGGER_NOT_FOUND _HRESULT_TYPEDEF_(0x80041309)
#define SCHED_E_TASK_NOT_READY _HRESULT_TYPEDEF_(0x8004130A)
#define SCHED_E_TASK_NOT_RUNNING _HRESULT_TYPEDEF_(0x8004130B)
#define SCHED_E_SERVICE_NOT_INSTALLED _HRESULT_TYPEDEF_(0x8004130C)
#define SCHED_E_CANNOT_OPEN_TASK _HRESULT_TYPEDEF_(0x8004130D)
#define SCHED_E_INVALID_TASK _HRESULT_TYPEDEF_(0x8004130E)
#define SCHED_E_ACCOUNT_INFORMATION_NOT_SET _HRESULT_TYPEDEF_(0x8004130F)
#define SCHED_E_ACCOUNT_NAME_NOT_FOUND _HRESULT_TYPEDEF_(0x80041310)
#define SCHED_E_ACCOUNT_DBASE_CORRUPT _HRESULT_TYPEDEF_(0x80041311)
#define SCHED_E_NO_SECURITY_SERVICES _HRESULT_TYPEDEF_(0x80041312)
#define SCHED_E_UNKNOWN_OBJECT_VERSION _HRESULT_TYPEDEF_(0x80041313)
#define SCHED_E_UNSUPPORTED_ACCOUNT_OPTION _HRESULT_TYPEDEF_(0x80041314)
#define SCHED_E_SERVICE_NOT_RUNNING _HRESULT_TYPEDEF_(0x80041315)
#define CO_E_CLASS_CREATE_FAILED _HRESULT_TYPEDEF_(0x80080001)
#define CO_E_SCM_ERROR _HRESULT_TYPEDEF_(0x80080002)
#define CO_E_SCM_RPC_FAILURE _HRESULT_TYPEDEF_(0x80080003)
#define CO_E_BAD_PATH _HRESULT_TYPEDEF_(0x80080004)
#define CO_E_SERVER_EXEC_FAILURE _HRESULT_TYPEDEF_(0x80080005)
#define CO_E_OBJSRV_RPC_FAILURE _HRESULT_TYPEDEF_(0x80080006)
#define MK_E_NO_NORMALIZED _HRESULT_TYPEDEF_(0x80080007)
#define CO_E_SERVER_STOPPING _HRESULT_TYPEDEF_(0x80080008)
#define MEM_E_INVALID_ROOT _HRESULT_TYPEDEF_(0x80080009)
#define MEM_E_INVALID_LINK _HRESULT_TYPEDEF_(0x80080010)
#define MEM_E_INVALID_SIZE _HRESULT_TYPEDEF_(0x80080011)
#define CO_S_NOTALLINTERFACES _HRESULT_TYPEDEF_(0x00080012)
#define CO_S_MACHINENAMENOTFOUND _HRESULT_TYPEDEF_(0x00080013)
#define DISP_E_UNKNOWNINTERFACE _HRESULT_TYPEDEF_(0x80020001)
#define DISP_E_MEMBERNOTFOUND _HRESULT_TYPEDEF_(0x80020003)
#define DISP_E_PARAMNOTFOUND _HRESULT_TYPEDEF_(0x80020004)
#define DISP_E_TYPEMISMATCH _HRESULT_TYPEDEF_(0x80020005)
#define DISP_E_UNKNOWNNAME _HRESULT_TYPEDEF_(0x80020006)
#define DISP_E_NONAMEDARGS _HRESULT_TYPEDEF_(0x80020007)
#define DISP_E_BADVARTYPE _HRESULT_TYPEDEF_(0x80020008)
#define DISP_E_EXCEPTION _HRESULT_TYPEDEF_(0x80020009)
#define DISP_E_OVERFLOW _HRESULT_TYPEDEF_(0x8002000A)
#define DISP_E_BADINDEX _HRESULT_TYPEDEF_(0x8002000B)
#define DISP_E_UNKNOWNLCID _HRESULT_TYPEDEF_(0x8002000C)
#define DISP_E_ARRAYISLOCKED _HRESULT_TYPEDEF_(0x8002000D)
#define DISP_E_BADPARAMCOUNT _HRESULT_TYPEDEF_(0x8002000E)
#define DISP_E_PARAMNOTOPTIONAL _HRESULT_TYPEDEF_(0x8002000F)
#define DISP_E_BADCALLEE _HRESULT_TYPEDEF_(0x80020010)
#define DISP_E_NOTACOLLECTION _HRESULT_TYPEDEF_(0x80020011)
#define DISP_E_DIVBYZERO _HRESULT_TYPEDEF_(0x80020012)
#define DISP_E_BUFFERTOOSMALL _HRESULT_TYPEDEF_(0x80020013)
#define TYPE_E_BUFFERTOOSMALL _HRESULT_TYPEDEF_(0x80028016)
#define TYPE_E_FIELDNOTFOUND _HRESULT_TYPEDEF_(0x80028017)
#define TYPE_E_INVDATAREAD _HRESULT_TYPEDEF_(0x80028018)
#define TYPE_E_UNSUPFORMAT _HRESULT_TYPEDEF_(0x80028019)
#define TYPE_E_REGISTRYACCESS _HRESULT_TYPEDEF_(0x8002801C)
#define TYPE_E_LIBNOTREGISTERED _HRESULT_TYPEDEF_(0x8002801D)
#define TYPE_E_UNDEFINEDTYPE _HRESULT_TYPEDEF_(0x80028027)
#define TYPE_E_QUALIFIEDNAMEDISALLOWED _HRESULT_TYPEDEF_(0x80028028)
#define TYPE_E_INVALIDSTATE _HRESULT_TYPEDEF_(0x80028029)
#define TYPE_E_WRONGTYPEKIND _HRESULT_TYPEDEF_(0x8002802A)
#define TYPE_E_ELEMENTNOTFOUND _HRESULT_TYPEDEF_(0x8002802B)
#define TYPE_E_AMBIGUOUSNAME _HRESULT_TYPEDEF_(0x8002802C)
#define TYPE_E_NAMECONFLICT _HRESULT_TYPEDEF_(0x8002802D)
#define TYPE_E_UNKNOWNLCID _HRESULT_TYPEDEF_(0x8002802E)
#define TYPE_E_DLLFUNCTIONNOTFOUND _HRESULT_TYPEDEF_(0x8002802F)
#define TYPE_E_BADMODULEKIND _HRESULT_TYPEDEF_(0x800288BD)
#define TYPE_E_SIZETOOBIG _HRESULT_TYPEDEF_(0x800288C5)
#define TYPE_E_DUPLICATEID _HRESULT_TYPEDEF_(0x800288C6)
#define TYPE_E_INVALIDID _HRESULT_TYPEDEF_(0x800288CF)
#define TYPE_E_TYPEMISMATCH _HRESULT_TYPEDEF_(0x80028CA0)
#define TYPE_E_OUTOFBOUNDS _HRESULT_TYPEDEF_(0x80028CA1)
#define TYPE_E_IOERROR _HRESULT_TYPEDEF_(0x80028CA2)
#define TYPE_E_CANTCREATETMPFILE _HRESULT_TYPEDEF_(0x80028CA3)
#define TYPE_E_CANTLOADLIBRARY _HRESULT_TYPEDEF_(0x80029C4A)
#define TYPE_E_INCONSISTENTPROPFUNCS _HRESULT_TYPEDEF_(0x80029C83)
#define TYPE_E_CIRCULARTYPE _HRESULT_TYPEDEF_(0x80029C84)
#define STG_E_INVALIDFUNCTION _HRESULT_TYPEDEF_(0x80030001)
#define STG_E_FILENOTFOUND _HRESULT_TYPEDEF_(0x80030002)
#define STG_E_PATHNOTFOUND _HRESULT_TYPEDEF_(0x80030003)
#define STG_E_TOOMANYOPENFILES _HRESULT_TYPEDEF_(0x80030004)
#define STG_E_ACCESSDENIED _HRESULT_TYPEDEF_(0x80030005)
#define STG_E_INVALIDHANDLE _HRESULT_TYPEDEF_(0x80030006)
#define STG_E_INSUFFICIENTMEMORY _HRESULT_TYPEDEF_(0x80030008)
#define STG_E_INVALIDPOINTER _HRESULT_TYPEDEF_(0x80030009)
#define STG_E_NOMOREFILES _HRESULT_TYPEDEF_(0x80030012)
#define STG_E_DISKISWRITEPROTECTED _HRESULT_TYPEDEF_(0x80030013)
#define STG_E_SEEKERROR _HRESULT_TYPEDEF_(0x80030019)
#define STG_E_WRITEFAULT _HRESULT_TYPEDEF_(0x8003001D)
#define STG_E_READFAULT _HRESULT_TYPEDEF_(0x8003001E)
#define STG_E_SHAREVIOLATION _HRESULT_TYPEDEF_(0x80030020)
#define STG_E_LOCKVIOLATION _HRESULT_TYPEDEF_(0x80030021)
#define STG_E_FILEALREADYEXISTS _HRESULT_TYPEDEF_(0x80030050)
#define STG_E_INVALIDPARAMETER _HRESULT_TYPEDEF_(0x80030057)
#define STG_E_MEDIUMFULL _HRESULT_TYPEDEF_(0x80030070)
#define STG_E_PROPSETMISMATCHED _HRESULT_TYPEDEF_(0x800300F0)
#define STG_E_ABNORMALAPIEXIT _HRESULT_TYPEDEF_(0x800300FA)
#define STG_E_INVALIDHEADER _HRESULT_TYPEDEF_(0x800300FB)
#define STG_E_INVALIDNAME _HRESULT_TYPEDEF_(0x800300FC)
#define STG_E_UNKNOWN _HRESULT_TYPEDEF_(0x800300FD)
#define STG_E_UNIMPLEMENTEDFUNCTION _HRESULT_TYPEDEF_(0x800300FE)
#define STG_E_INVALIDFLAG _HRESULT_TYPEDEF_(0x800300FF)
#define STG_E_INUSE _HRESULT_TYPEDEF_(0x80030100)
#define STG_E_NOTCURRENT _HRESULT_TYPEDEF_(0x80030101)
#define STG_E_REVERTED _HRESULT_TYPEDEF_(0x80030102)
#define STG_E_CANTSAVE _HRESULT_TYPEDEF_(0x80030103)
#define STG_E_OLDFORMAT _HRESULT_TYPEDEF_(0x80030104)
#define STG_E_OLDDLL _HRESULT_TYPEDEF_(0x80030105)
#define STG_E_SHAREREQUIRED _HRESULT_TYPEDEF_(0x80030106)
#define STG_E_NOTFILEBASEDSTORAGE _HRESULT_TYPEDEF_(0x80030107)
#define STG_E_EXTANTMARSHALLINGS _HRESULT_TYPEDEF_(0x80030108)
#define STG_E_DOCFILECORRUPT _HRESULT_TYPEDEF_(0x80030109)
#define STG_E_BADBASEADDRESS _HRESULT_TYPEDEF_(0x80030110)
#define STG_E_DOCFILETOOLARGE _HRESULT_TYPEDEF_(0x80030111)
#define STG_E_NOTSIMPLEFORMAT _HRESULT_TYPEDEF_(0x80030112)
#define STG_E_INCOMPLETE _HRESULT_TYPEDEF_(0x80030201)
#define STG_E_TERMINATED _HRESULT_TYPEDEF_(0x80030202)
#define STG_S_CONVERTED _HRESULT_TYPEDEF_(0x00030200)
#define STG_S_BLOCK _HRESULT_TYPEDEF_(0x00030201)
#define STG_S_RETRYNOW _HRESULT_TYPEDEF_(0x00030202)
#define STG_S_MONITORING _HRESULT_TYPEDEF_(0x00030203)
#define STG_S_MULTIPLEOPENS _HRESULT_TYPEDEF_(0x00030204)
#define STG_S_CONSOLIDATIONFAILED _HRESULT_TYPEDEF_(0x00030205)
#define STG_S_CANNOTCONSOLIDATE _HRESULT_TYPEDEF_(0x00030206)
#define STG_E_STATUS_COPY_PROTECTION_FAILURE _HRESULT_TYPEDEF_(0x80030305)
#define STG_E_CSS_AUTHENTICATION_FAILURE _HRESULT_TYPEDEF_(0x80030306)
#define STG_E_CSS_KEY_NOT_PRESENT _HRESULT_TYPEDEF_(0x80030307)
#define STG_E_CSS_KEY_NOT_ESTABLISHED _HRESULT_TYPEDEF_(0x80030308)
#define STG_E_CSS_SCRAMBLED_SECTOR _HRESULT_TYPEDEF_(0x80030309)
#define STG_E_CSS_REGION_MISMATCH _HRESULT_TYPEDEF_(0x8003030A)
#define STG_E_RESETS_EXHAUSTED _HRESULT_TYPEDEF_(0x8003030B)
#define RPC_E_CALL_REJECTED _HRESULT_TYPEDEF_(0x80010001)
#define RPC_E_CALL_CANCELED _HRESULT_TYPEDEF_(0x80010002)
#define RPC_E_CANTPOST_INSENDCALL _HRESULT_TYPEDEF_(0x80010003)
#define RPC_E_CANTCALLOUT_INASYNCCALL _HRESULT_TYPEDEF_(0x80010004)
#define RPC_E_CANTCALLOUT_INEXTERNALCALL _HRESULT_TYPEDEF_(0x80010005)
#define RPC_E_CONNECTION_TERMINATED _HRESULT_TYPEDEF_(0x80010006)
#define RPC_E_SERVER_DIED _HRESULT_TYPEDEF_(0x80010007)
#define RPC_E_CLIENT_DIED _HRESULT_TYPEDEF_(0x80010008)
#define RPC_E_INVALID_DATAPACKET _HRESULT_TYPEDEF_(0x80010009)
#define RPC_E_CANTTRANSMIT_CALL _HRESULT_TYPEDEF_(0x8001000A)
#define RPC_E_CLIENT_CANTMARSHAL_DATA _HRESULT_TYPEDEF_(0x8001000B)
#define RPC_E_CLIENT_CANTUNMARSHAL_DATA _HRESULT_TYPEDEF_(0x8001000C)
#define RPC_E_SERVER_CANTMARSHAL_DATA _HRESULT_TYPEDEF_(0x8001000D)
#define RPC_E_SERVER_CANTUNMARSHAL_DATA _HRESULT_TYPEDEF_(0x8001000E)
#define RPC_E_INVALID_DATA _HRESULT_TYPEDEF_(0x8001000F)
#define RPC_E_INVALID_PARAMETER _HRESULT_TYPEDEF_(0x80010010)
#define RPC_E_CANTCALLOUT_AGAIN _HRESULT_TYPEDEF_(0x80010011)
#define RPC_E_SERVER_DIED_DNE _HRESULT_TYPEDEF_(0x80010012)
#define RPC_E_SYS_CALL_FAILED _HRESULT_TYPEDEF_(0x80010100)
#define RPC_E_OUT_OF_RESOURCES _HRESULT_TYPEDEF_(0x80010101)
#define RPC_E_ATTEMPTED_MULTITHREAD _HRESULT_TYPEDEF_(0x80010102)
#define RPC_E_NOT_REGISTERED _HRESULT_TYPEDEF_(0x80010103)
#define RPC_E_FAULT _HRESULT_TYPEDEF_(0x80010104)
#define RPC_E_SERVERFAULT _HRESULT_TYPEDEF_(0x80010105)
#define RPC_E_CHANGED_MODE _HRESULT_TYPEDEF_(0x80010106)
#define RPC_E_INVALIDMETHOD _HRESULT_TYPEDEF_(0x80010107)
#define RPC_E_DISCONNECTED _HRESULT_TYPEDEF_(0x80010108)
#define RPC_E_RETRY _HRESULT_TYPEDEF_(0x80010109)
#define RPC_E_SERVERCALL_RETRYLATER _HRESULT_TYPEDEF_(0x8001010A)
#define RPC_E_SERVERCALL_REJECTED _HRESULT_TYPEDEF_(0x8001010B)
#define RPC_E_INVALID_CALLDATA _HRESULT_TYPEDEF_(0x8001010C)
#define RPC_E_CANTCALLOUT_ININPUTSYNCCALL _HRESULT_TYPEDEF_(0x8001010D)
#define RPC_E_WRONG_THREAD _HRESULT_TYPEDEF_(0x8001010E)
#define RPC_E_THREAD_NOT_INIT _HRESULT_TYPEDEF_(0x8001010F)
#define RPC_E_VERSION_MISMATCH _HRESULT_TYPEDEF_(0x80010110)
#define RPC_E_INVALID_HEADER _HRESULT_TYPEDEF_(0x80010111)
#define RPC_E_INVALID_EXTENSION _HRESULT_TYPEDEF_(0x80010112)
#define RPC_E_INVALID_IPID _HRESULT_TYPEDEF_(0x80010113)
#define RPC_E_INVALID_OBJECT _HRESULT_TYPEDEF_(0x80010114)
#define RPC_S_CALLPENDING _HRESULT_TYPEDEF_(0x80010115)
#define RPC_S_WAITONTIMER _HRESULT_TYPEDEF_(0x80010116)
#define RPC_E_CALL_COMPLETE _HRESULT_TYPEDEF_(0x80010117)
#define RPC_E_UNSECURE_CALL _HRESULT_TYPEDEF_(0x80010118)
#define RPC_E_TOO_LATE _HRESULT_TYPEDEF_(0x80010119)
#define RPC_E_NO_GOOD_SECURITY_PACKAGES _HRESULT_TYPEDEF_(0x8001011A)
#define RPC_E_ACCESS_DENIED _HRESULT_TYPEDEF_(0x8001011B)
#define RPC_E_REMOTE_DISABLED _HRESULT_TYPEDEF_(0x8001011C)
#define RPC_E_INVALID_OBJREF _HRESULT_TYPEDEF_(0x8001011D)
#define RPC_E_NO_CONTEXT _HRESULT_TYPEDEF_(0x8001011E)
#define RPC_E_TIMEOUT _HRESULT_TYPEDEF_(0x8001011F)
#define RPC_E_NO_SYNC _HRESULT_TYPEDEF_(0x80010120)
#define RPC_E_FULLSIC_REQUIRED _HRESULT_TYPEDEF_(0x80010121)
#define RPC_E_INVALID_STD_NAME _HRESULT_TYPEDEF_(0x80010122)
#define CO_E_FAILEDTOIMPERSONATE _HRESULT_TYPEDEF_(0x80010123)
#define CO_E_FAILEDTOGETSECCTX _HRESULT_TYPEDEF_(0x80010124)
#define CO_E_FAILEDTOOPENTHREADTOKEN _HRESULT_TYPEDEF_(0x80010125)
#define CO_E_FAILEDTOGETTOKENINFO _HRESULT_TYPEDEF_(0x80010126)
#define CO_E_TRUSTEEDOESNTMATCHCLIENT _HRESULT_TYPEDEF_(0x80010127)
#define CO_E_FAILEDTOQUERYCLIENTBLANKET _HRESULT_TYPEDEF_(0x80010128)
#define CO_E_FAILEDTOSETDACL _HRESULT_TYPEDEF_(0x80010129)
#define CO_E_ACCESSCHECKFAILED _HRESULT_TYPEDEF_(0x8001012A)
#define CO_E_NETACCESSAPIFAILED _HRESULT_TYPEDEF_(0x8001012B)
#define CO_E_WRONGTRUSTEENAMESYNTAX _HRESULT_TYPEDEF_(0x8001012C)
#define CO_E_INVALIDSID _HRESULT_TYPEDEF_(0x8001012D)
#define CO_E_CONVERSIONFAILED _HRESULT_TYPEDEF_(0x8001012E)
#define CO_E_NOMATCHINGSIDFOUND _HRESULT_TYPEDEF_(0x8001012F)
#define CO_E_LOOKUPACCSIDFAILED _HRESULT_TYPEDEF_(0x80010130)
#define CO_E_NOMATCHINGNAMEFOUND _HRESULT_TYPEDEF_(0x80010131)
#define CO_E_LOOKUPACCNAMEFAILED _HRESULT_TYPEDEF_(0x80010132)
#define CO_E_SETSERLHNDLFAILED _HRESULT_TYPEDEF_(0x80010133)
#define CO_E_FAILEDTOGETWINDIR _HRESULT_TYPEDEF_(0x80010134)
#define CO_E_PATHTOOLONG _HRESULT_TYPEDEF_(0x80010135)
#define CO_E_FAILEDTOGENUUID _HRESULT_TYPEDEF_(0x80010136)
#define CO_E_FAILEDTOCREATEFILE _HRESULT_TYPEDEF_(0x80010137)
#define CO_E_FAILEDTOCLOSEHANDLE _HRESULT_TYPEDEF_(0x80010138)
#define CO_E_EXCEEDSYSACLLIMIT _HRESULT_TYPEDEF_(0x80010139)
#define CO_E_ACESINWRONGORDER _HRESULT_TYPEDEF_(0x8001013A)
#define CO_E_INCOMPATIBLESTREAMVERSION _HRESULT_TYPEDEF_(0x8001013B)
#define CO_E_FAILEDTOOPENPROCESSTOKEN _HRESULT_TYPEDEF_(0x8001013C)
#define CO_E_DECODEFAILED _HRESULT_TYPEDEF_(0x8001013D)
#define CO_E_ACNOTINITIALIZED _HRESULT_TYPEDEF_(0x8001013F)
#define CO_E_CANCEL_DISABLED _HRESULT_TYPEDEF_(0x80010140)
#define RPC_E_UNEXPECTED _HRESULT_TYPEDEF_(0x8001FFFF)
#define ERROR_AUDITING_DISABLED _HRESULT_TYPEDEF_(0xC0090001)
#define ERROR_ALL_SIDS_FILTERED _HRESULT_TYPEDEF_(0xC0090002)
#define NTE_BAD_UID _HRESULT_TYPEDEF_(0x80090001)
#define NTE_BAD_HASH _HRESULT_TYPEDEF_(0x80090002)
#define NTE_BAD_KEY _HRESULT_TYPEDEF_(0x80090003)
#define NTE_BAD_LEN _HRESULT_TYPEDEF_(0x80090004)
#define NTE_BAD_DATA _HRESULT_TYPEDEF_(0x80090005)
#define NTE_BAD_SIGNATURE _HRESULT_TYPEDEF_(0x80090006)
#define NTE_BAD_VER _HRESULT_TYPEDEF_(0x80090007)
#define NTE_BAD_ALGID _HRESULT_TYPEDEF_(0x80090008)
#define NTE_BAD_FLAGS _HRESULT_TYPEDEF_(0x80090009)
#define NTE_BAD_TYPE _HRESULT_TYPEDEF_(0x8009000A)
#define NTE_BAD_KEY_STATE _HRESULT_TYPEDEF_(0x8009000B)
#define NTE_BAD_HASH_STATE _HRESULT_TYPEDEF_(0x8009000C)
#define NTE_NO_KEY _HRESULT_TYPEDEF_(0x8009000D)
#define NTE_NO_MEMORY _HRESULT_TYPEDEF_(0x8009000E)
#define NTE_EXISTS _HRESULT_TYPEDEF_(0x8009000F)
#define NTE_PERM _HRESULT_TYPEDEF_(0x80090010)
#define NTE_NOT_FOUND _HRESULT_TYPEDEF_(0x80090011)
#define NTE_DOUBLE_ENCRYPT _HRESULT_TYPEDEF_(0x80090012)
#define NTE_BAD_PROVIDER _HRESULT_TYPEDEF_(0x80090013)
#define NTE_BAD_PROV_TYPE _HRESULT_TYPEDEF_(0x80090014)
#define NTE_BAD_PUBLIC_KEY _HRESULT_TYPEDEF_(0x80090015)
#define NTE_BAD_KEYSET _HRESULT_TYPEDEF_(0x80090016)
#define NTE_PROV_TYPE_NOT_DEF _HRESULT_TYPEDEF_(0x80090017)
#define NTE_PROV_TYPE_ENTRY_BAD _HRESULT_TYPEDEF_(0x80090018)
#define NTE_KEYSET_NOT_DEF _HRESULT_TYPEDEF_(0x80090019)
#define NTE_KEYSET_ENTRY_BAD _HRESULT_TYPEDEF_(0x8009001A)
#define NTE_PROV_TYPE_NO_MATCH _HRESULT_TYPEDEF_(0x8009001B)
#define NTE_SIGNATURE_FILE_BAD _HRESULT_TYPEDEF_(0x8009001C)
#define NTE_PROVIDER_DLL_FAIL _HRESULT_TYPEDEF_(0x8009001D)
#define NTE_PROV_DLL_NOT_FOUND _HRESULT_TYPEDEF_(0x8009001E)
#define NTE_BAD_KEYSET_PARAM _HRESULT_TYPEDEF_(0x8009001F)
#define NTE_FAIL _HRESULT_TYPEDEF_(0x80090020)
#define NTE_SYS_ERR _HRESULT_TYPEDEF_(0x80090021)
#define NTE_SILENT_CONTEXT _HRESULT_TYPEDEF_(0x80090022)
#define NTE_TOKEN_KEYSET_STORAGE_FULL _HRESULT_TYPEDEF_(0x80090023)
#define NTE_TEMPORARY_PROFILE _HRESULT_TYPEDEF_(0x80090024)
#define NTE_FIXEDPARAMETER _HRESULT_TYPEDEF_(0x80090025)
#define SEC_E_INSUFFICIENT_MEMORY _HRESULT_TYPEDEF_(0x80090300)
#define SEC_E_INVALID_HANDLE _HRESULT_TYPEDEF_(0x80090301)
#define SEC_E_UNSUPPORTED_FUNCTION _HRESULT_TYPEDEF_(0x80090302)
#define SEC_E_TARGET_UNKNOWN _HRESULT_TYPEDEF_(0x80090303)
#define SEC_E_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x80090304)
#define SEC_E_SECPKG_NOT_FOUND _HRESULT_TYPEDEF_(0x80090305)
#define SEC_E_NOT_OWNER _HRESULT_TYPEDEF_(0x80090306)
#define SEC_E_CANNOT_INSTALL _HRESULT_TYPEDEF_(0x80090307)
#define SEC_E_INVALID_TOKEN _HRESULT_TYPEDEF_(0x80090308)
#define SEC_E_CANNOT_PACK _HRESULT_TYPEDEF_(0x80090309)
#define SEC_E_QOP_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009030A)
#define SEC_E_NO_IMPERSONATION _HRESULT_TYPEDEF_(0x8009030B)
#define SEC_E_LOGON_DENIED _HRESULT_TYPEDEF_(0x8009030C)
#define SEC_E_UNKNOWN_CREDENTIALS _HRESULT_TYPEDEF_(0x8009030D)
#define SEC_E_NO_CREDENTIALS _HRESULT_TYPEDEF_(0x8009030E)
#define SEC_E_MESSAGE_ALTERED _HRESULT_TYPEDEF_(0x8009030F)
#define SEC_E_OUT_OF_SEQUENCE _HRESULT_TYPEDEF_(0x80090310)
#define SEC_E_NO_AUTHENTICATING_AUTHORITY _HRESULT_TYPEDEF_(0x80090311)
#define SEC_I_CONTINUE_NEEDED _HRESULT_TYPEDEF_(0x00090312)
#define SEC_I_COMPLETE_NEEDED _HRESULT_TYPEDEF_(0x00090313)
#define SEC_I_COMPLETE_AND_CONTINUE _HRESULT_TYPEDEF_(0x00090314)
#define SEC_I_LOCAL_LOGON _HRESULT_TYPEDEF_(0x00090315)
#define SEC_E_BAD_PKGID _HRESULT_TYPEDEF_(0x80090316)
#define SEC_E_CONTEXT_EXPIRED _HRESULT_TYPEDEF_(0x80090317)
#define SEC_I_CONTEXT_EXPIRED _HRESULT_TYPEDEF_(0x00090317)
#define SEC_E_INCOMPLETE_MESSAGE _HRESULT_TYPEDEF_(0x80090318)
#define SEC_E_INCOMPLETE_CREDENTIALS _HRESULT_TYPEDEF_(0x80090320)
#define SEC_E_BUFFER_TOO_SMALL _HRESULT_TYPEDEF_(0x80090321)
#define SEC_I_INCOMPLETE_CREDENTIALS _HRESULT_TYPEDEF_(0x00090320)
#define SEC_I_RENEGOTIATE _HRESULT_TYPEDEF_(0x00090321)
#define SEC_E_WRONG_PRINCIPAL _HRESULT_TYPEDEF_(0x80090322)
#define SEC_I_NO_LSA_CONTEXT _HRESULT_TYPEDEF_(0x00090323)
#define SEC_E_TIME_SKEW _HRESULT_TYPEDEF_(0x80090324)
#define SEC_E_UNTRUSTED_ROOT _HRESULT_TYPEDEF_(0x80090325)
#define SEC_E_ILLEGAL_MESSAGE _HRESULT_TYPEDEF_(0x80090326)
#define SEC_E_CERT_UNKNOWN _HRESULT_TYPEDEF_(0x80090327)
#define SEC_E_CERT_EXPIRED _HRESULT_TYPEDEF_(0x80090328)
#define SEC_E_ENCRYPT_FAILURE _HRESULT_TYPEDEF_(0x80090329)
#define SEC_E_DECRYPT_FAILURE _HRESULT_TYPEDEF_(0x80090330)
#define SEC_E_ALGORITHM_MISMATCH _HRESULT_TYPEDEF_(0x80090331)
#define SEC_E_SECURITY_QOS_FAILED _HRESULT_TYPEDEF_(0x80090332)
#define SEC_E_UNFINISHED_CONTEXT_DELETED _HRESULT_TYPEDEF_(0x80090333)
#define SEC_E_NO_TGT_REPLY _HRESULT_TYPEDEF_(0x80090334)
#define SEC_E_NO_IP_ADDRESSES _HRESULT_TYPEDEF_(0x80090335)
#define SEC_E_WRONG_CREDENTIAL_HANDLE _HRESULT_TYPEDEF_(0x80090336)
#define SEC_E_CRYPTO_SYSTEM_INVALID _HRESULT_TYPEDEF_(0x80090337)
#define SEC_E_MAX_REFERRALS_EXCEEDED _HRESULT_TYPEDEF_(0x80090338)
#define SEC_E_MUST_BE_KDC _HRESULT_TYPEDEF_(0x80090339)
#define SEC_E_STRONG_CRYPTO_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009033A)
#define SEC_E_TOO_MANY_PRINCIPALS _HRESULT_TYPEDEF_(0x8009033B)
#define SEC_E_NO_PA_DATA _HRESULT_TYPEDEF_(0x8009033C)
#define SEC_E_PKINIT_NAME_MISMATCH _HRESULT_TYPEDEF_(0x8009033D)
#define SEC_E_SMARTCARD_LOGON_REQUIRED _HRESULT_TYPEDEF_(0x8009033E)
#define SEC_E_SHUTDOWN_IN_PROGRESS _HRESULT_TYPEDEF_(0x8009033F)
#define SEC_E_KDC_INVALID_REQUEST _HRESULT_TYPEDEF_(0x80090340)
#define SEC_E_KDC_UNABLE_TO_REFER _HRESULT_TYPEDEF_(0x80090341)
#define SEC_E_KDC_UNKNOWN_ETYPE _HRESULT_TYPEDEF_(0x80090342)
#define SEC_E_UNSUPPORTED_PREAUTH _HRESULT_TYPEDEF_(0x80090343)
#define SEC_E_DELEGATION_REQUIRED _HRESULT_TYPEDEF_(0x80090345)
#define SEC_E_BAD_BINDINGS _HRESULT_TYPEDEF_(0x80090346)
#define SEC_E_MULTIPLE_ACCOUNTS _HRESULT_TYPEDEF_(0x80090347)
#define SEC_E_NO_KERB_KEY _HRESULT_TYPEDEF_(0x80090348)
#define SEC_E_CERT_WRONG_USAGE _HRESULT_TYPEDEF_(0x80090349)
#define SEC_E_DOWNGRADE_DETECTED _HRESULT_TYPEDEF_(0x80090350)
#define SEC_E_SMARTCARD_CERT_REVOKED _HRESULT_TYPEDEF_(0x80090351)
#define SEC_E_ISSUING_CA_UNTRUSTED _HRESULT_TYPEDEF_(0x80090352)
#define SEC_E_REVOCATION_OFFLINE_C _HRESULT_TYPEDEF_(0x80090353)
#define SEC_E_PKINIT_CLIENT_FAILURE _HRESULT_TYPEDEF_(0x80090354)
#define SEC_E_SMARTCARD_CERT_EXPIRED _HRESULT_TYPEDEF_(0x80090355)
#define SEC_E_NO_S4U_PROT_SUPPORT _HRESULT_TYPEDEF_(0x80090356)
#define SEC_E_CROSSREALM_DELEGATION_FAILURE _HRESULT_TYPEDEF_(0x80090357)
#define SEC_E_REVOCATION_OFFLINE_KDC _HRESULT_TYPEDEF_(0x80090358)
#define SEC_E_ISSUING_CA_UNTRUSTED_KDC _HRESULT_TYPEDEF_(0x80090359)
#define SEC_E_KDC_CERT_EXPIRED _HRESULT_TYPEDEF_(0x8009035A)
#define SEC_E_KDC_CERT_REVOKED _HRESULT_TYPEDEF_(0x8009035B)
#define SEC_E_NO_SPM SEC_E_INTERNAL_ERROR
#define SEC_E_NOT_SUPPORTED SEC_E_UNSUPPORTED_FUNCTION
#define CRYPT_E_MSG_ERROR _HRESULT_TYPEDEF_(0x80091001)
#define CRYPT_E_UNKNOWN_ALGO _HRESULT_TYPEDEF_(0x80091002)
#define CRYPT_E_OID_FORMAT _HRESULT_TYPEDEF_(0x80091003)
#define CRYPT_E_INVALID_MSG_TYPE _HRESULT_TYPEDEF_(0x80091004)
#define CRYPT_E_UNEXPECTED_ENCODING _HRESULT_TYPEDEF_(0x80091005)
#define CRYPT_E_AUTH_ATTR_MISSING _HRESULT_TYPEDEF_(0x80091006)
#define CRYPT_E_HASH_VALUE _HRESULT_TYPEDEF_(0x80091007)
#define CRYPT_E_INVALID_INDEX _HRESULT_TYPEDEF_(0x80091008)
#define CRYPT_E_ALREADY_DECRYPTED _HRESULT_TYPEDEF_(0x80091009)
#define CRYPT_E_NOT_DECRYPTED _HRESULT_TYPEDEF_(0x8009100A)
#define CRYPT_E_RECIPIENT_NOT_FOUND _HRESULT_TYPEDEF_(0x8009100B)
#define CRYPT_E_CONTROL_TYPE _HRESULT_TYPEDEF_(0x8009100C)
#define CRYPT_E_ISSUER_SERIALNUMBER _HRESULT_TYPEDEF_(0x8009100D)
#define CRYPT_E_SIGNER_NOT_FOUND _HRESULT_TYPEDEF_(0x8009100E)
#define CRYPT_E_ATTRIBUTES_MISSING _HRESULT_TYPEDEF_(0x8009100F)
#define CRYPT_E_STREAM_MSG_NOT_READY _HRESULT_TYPEDEF_(0x80091010)
#define CRYPT_E_STREAM_INSUFFICIENT_DATA _HRESULT_TYPEDEF_(0x80091011)
#define CRYPT_I_NEW_PROTECTION_REQUIRED _HRESULT_TYPEDEF_(0x00091012)
#define CRYPT_E_BAD_LEN _HRESULT_TYPEDEF_(0x80092001)
#define CRYPT_E_BAD_ENCODE _HRESULT_TYPEDEF_(0x80092002)
#define CRYPT_E_FILE_ERROR _HRESULT_TYPEDEF_(0x80092003)
#define CRYPT_E_NOT_FOUND _HRESULT_TYPEDEF_(0x80092004)
#define CRYPT_E_EXISTS _HRESULT_TYPEDEF_(0x80092005)
#define CRYPT_E_NO_PROVIDER _HRESULT_TYPEDEF_(0x80092006)
#define CRYPT_E_SELF_SIGNED _HRESULT_TYPEDEF_(0x80092007)
#define CRYPT_E_DELETED_PREV _HRESULT_TYPEDEF_(0x80092008)
#define CRYPT_E_NO_MATCH _HRESULT_TYPEDEF_(0x80092009)
#define CRYPT_E_UNEXPECTED_MSG_TYPE _HRESULT_TYPEDEF_(0x8009200A)
#define CRYPT_E_NO_KEY_PROPERTY _HRESULT_TYPEDEF_(0x8009200B)
#define CRYPT_E_NO_DECRYPT_CERT _HRESULT_TYPEDEF_(0x8009200C)
#define CRYPT_E_BAD_MSG _HRESULT_TYPEDEF_(0x8009200D)
#define CRYPT_E_NO_SIGNER _HRESULT_TYPEDEF_(0x8009200E)
#define CRYPT_E_PENDING_CLOSE _HRESULT_TYPEDEF_(0x8009200F)
#define CRYPT_E_REVOKED _HRESULT_TYPEDEF_(0x80092010)
#define CRYPT_E_NO_REVOCATION_DLL _HRESULT_TYPEDEF_(0x80092011)
#define CRYPT_E_NO_REVOCATION_CHECK _HRESULT_TYPEDEF_(0x80092012)
#define CRYPT_E_REVOCATION_OFFLINE _HRESULT_TYPEDEF_(0x80092013)
#define CRYPT_E_NOT_IN_REVOCATION_DATABASE _HRESULT_TYPEDEF_(0x80092014)
#define CRYPT_E_INVALID_NUMERIC_STRING _HRESULT_TYPEDEF_(0x80092020)
#define CRYPT_E_INVALID_PRINTABLE_STRING _HRESULT_TYPEDEF_(0x80092021)
#define CRYPT_E_INVALID_IA5_STRING _HRESULT_TYPEDEF_(0x80092022)
#define CRYPT_E_INVALID_X500_STRING _HRESULT_TYPEDEF_(0x80092023)
#define CRYPT_E_NOT_CHAR_STRING _HRESULT_TYPEDEF_(0x80092024)
#define CRYPT_E_FILERESIZED _HRESULT_TYPEDEF_(0x80092025)
#define CRYPT_E_SECURITY_SETTINGS _HRESULT_TYPEDEF_(0x80092026)
#define CRYPT_E_NO_VERIFY_USAGE_DLL _HRESULT_TYPEDEF_(0x80092027)
#define CRYPT_E_NO_VERIFY_USAGE_CHECK _HRESULT_TYPEDEF_(0x80092028)
#define CRYPT_E_VERIFY_USAGE_OFFLINE _HRESULT_TYPEDEF_(0x80092029)
#define CRYPT_E_NOT_IN_CTL _HRESULT_TYPEDEF_(0x8009202A)
#define CRYPT_E_NO_TRUSTED_SIGNER _HRESULT_TYPEDEF_(0x8009202B)
#define CRYPT_E_MISSING_PUBKEY_PARA _HRESULT_TYPEDEF_(0x8009202C)
#define CRYPT_E_OSS_ERROR _HRESULT_TYPEDEF_(0x80093000)
#define OSS_MORE_BUF _HRESULT_TYPEDEF_(0x80093001)
#define OSS_NEGATIVE_UINTEGER _HRESULT_TYPEDEF_(0x80093002)
#define OSS_PDU_RANGE _HRESULT_TYPEDEF_(0x80093003)
#define OSS_MORE_INPUT _HRESULT_TYPEDEF_(0x80093004)
#define OSS_DATA_ERROR _HRESULT_TYPEDEF_(0x80093005)
#define OSS_BAD_ARG _HRESULT_TYPEDEF_(0x80093006)
#define OSS_BAD_VERSION _HRESULT_TYPEDEF_(0x80093007)
#define OSS_OUT_MEMORY _HRESULT_TYPEDEF_(0x80093008)
#define OSS_PDU_MISMATCH _HRESULT_TYPEDEF_(0x80093009)
#define OSS_LIMITED _HRESULT_TYPEDEF_(0x8009300A)
#define OSS_BAD_PTR _HRESULT_TYPEDEF_(0x8009300B)
#define OSS_BAD_TIME _HRESULT_TYPEDEF_(0x8009300C)
#define OSS_INDEFINITE_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009300D)
#define OSS_MEM_ERROR _HRESULT_TYPEDEF_(0x8009300E)
#define OSS_BAD_TABLE _HRESULT_TYPEDEF_(0x8009300F)
#define OSS_TOO_LONG _HRESULT_TYPEDEF_(0x80093010)
#define OSS_CONSTRAINT_VIOLATED _HRESULT_TYPEDEF_(0x80093011)
#define OSS_FATAL_ERROR _HRESULT_TYPEDEF_(0x80093012)
#define OSS_ACCESS_SERIALIZATION_ERROR _HRESULT_TYPEDEF_(0x80093013)
#define OSS_NULL_TBL _HRESULT_TYPEDEF_(0x80093014)
#define OSS_NULL_FCN _HRESULT_TYPEDEF_(0x80093015)
#define OSS_BAD_ENCRULES _HRESULT_TYPEDEF_(0x80093016)
#define OSS_UNAVAIL_ENCRULES _HRESULT_TYPEDEF_(0x80093017)
#define OSS_CANT_OPEN_TRACE_WINDOW _HRESULT_TYPEDEF_(0x80093018)
#define OSS_UNIMPLEMENTED _HRESULT_TYPEDEF_(0x80093019)
#define OSS_OID_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x8009301A)
#define OSS_CANT_OPEN_TRACE_FILE _HRESULT_TYPEDEF_(0x8009301B)
#define OSS_TRACE_FILE_ALREADY_OPEN _HRESULT_TYPEDEF_(0x8009301C)
#define OSS_TABLE_MISMATCH _HRESULT_TYPEDEF_(0x8009301D)
#define OSS_TYPE_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8009301E)
#define OSS_REAL_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x8009301F)
#define OSS_REAL_CODE_NOT_LINKED _HRESULT_TYPEDEF_(0x80093020)
#define OSS_OUT_OF_RANGE _HRESULT_TYPEDEF_(0x80093021)
#define OSS_COPIER_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093022)
#define OSS_CONSTRAINT_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093023)
#define OSS_COMPARATOR_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093024)
#define OSS_COMPARATOR_CODE_NOT_LINKED _HRESULT_TYPEDEF_(0x80093025)
#define OSS_MEM_MGR_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093026)
#define OSS_PDV_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093027)
#define OSS_PDV_CODE_NOT_LINKED _HRESULT_TYPEDEF_(0x80093028)
#define OSS_API_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x80093029)
#define OSS_BERDER_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x8009302A)
#define OSS_PER_DLL_NOT_LINKED _HRESULT_TYPEDEF_(0x8009302B)
#define OSS_OPEN_TYPE_ERROR _HRESULT_TYPEDEF_(0x8009302C)
#define OSS_MUTEX_NOT_CREATED _HRESULT_TYPEDEF_(0x8009302D)
#define OSS_CANT_CLOSE_TRACE_FILE _HRESULT_TYPEDEF_(0x8009302E)
#define CRYPT_E_ASN1_ERROR _HRESULT_TYPEDEF_(0x80093100)
#define CRYPT_E_ASN1_INTERNAL _HRESULT_TYPEDEF_(0x80093101)
#define CRYPT_E_ASN1_EOD _HRESULT_TYPEDEF_(0x80093102)
#define CRYPT_E_ASN1_CORRUPT _HRESULT_TYPEDEF_(0x80093103)
#define CRYPT_E_ASN1_LARGE _HRESULT_TYPEDEF_(0x80093104)
#define CRYPT_E_ASN1_CONSTRAINT _HRESULT_TYPEDEF_(0x80093105)
#define CRYPT_E_ASN1_MEMORY _HRESULT_TYPEDEF_(0x80093106)
#define CRYPT_E_ASN1_OVERFLOW _HRESULT_TYPEDEF_(0x80093107)
#define CRYPT_E_ASN1_BADPDU _HRESULT_TYPEDEF_(0x80093108)
#define CRYPT_E_ASN1_BADARGS _HRESULT_TYPEDEF_(0x80093109)
#define CRYPT_E_ASN1_BADREAL _HRESULT_TYPEDEF_(0x8009310A)
#define CRYPT_E_ASN1_BADTAG _HRESULT_TYPEDEF_(0x8009310B)
#define CRYPT_E_ASN1_CHOICE _HRESULT_TYPEDEF_(0x8009310C)
#define CRYPT_E_ASN1_RULE _HRESULT_TYPEDEF_(0x8009310D)
#define CRYPT_E_ASN1_UTF8 _HRESULT_TYPEDEF_(0x8009310E)
#define CRYPT_E_ASN1_PDU_TYPE _HRESULT_TYPEDEF_(0x80093133)
#define CRYPT_E_ASN1_NYI _HRESULT_TYPEDEF_(0x80093134)
#define CRYPT_E_ASN1_EXTENDED _HRESULT_TYPEDEF_(0x80093201)
#define CRYPT_E_ASN1_NOEOD _HRESULT_TYPEDEF_(0x80093202)
#define CERTSRV_E_BAD_REQUESTSUBJECT _HRESULT_TYPEDEF_(0x80094001)
#define CERTSRV_E_NO_REQUEST _HRESULT_TYPEDEF_(0x80094002)
#define CERTSRV_E_BAD_REQUESTSTATUS _HRESULT_TYPEDEF_(0x80094003)
#define CERTSRV_E_PROPERTY_EMPTY _HRESULT_TYPEDEF_(0x80094004)
#define CERTSRV_E_INVALID_CA_CERTIFICATE _HRESULT_TYPEDEF_(0x80094005)
#define CERTSRV_E_SERVER_SUSPENDED _HRESULT_TYPEDEF_(0x80094006)
#define CERTSRV_E_ENCODING_LENGTH _HRESULT_TYPEDEF_(0x80094007)
#define CERTSRV_E_ROLECONFLICT _HRESULT_TYPEDEF_(0x80094008)
#define CERTSRV_E_RESTRICTEDOFFICER _HRESULT_TYPEDEF_(0x80094009)
#define CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED _HRESULT_TYPEDEF_(0x8009400A)
#define CERTSRV_E_NO_VALID_KRA _HRESULT_TYPEDEF_(0x8009400B)
#define CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL _HRESULT_TYPEDEF_(0x8009400C)
#define CERTSRV_E_NO_CAADMIN_DEFINED _HRESULT_TYPEDEF_(0x8009400D)
#define CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE _HRESULT_TYPEDEF_(0x8009400E)
#define CERTSRV_E_NO_DB_SESSIONS _HRESULT_TYPEDEF_(0x8009400F)
#define CERTSRV_E_ALIGNMENT_FAULT _HRESULT_TYPEDEF_(0x80094010)
#define CERTSRV_E_ENROLL_DENIED _HRESULT_TYPEDEF_(0x80094011)
#define CERTSRV_E_TEMPLATE_DENIED _HRESULT_TYPEDEF_(0x80094012)
#define CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE _HRESULT_TYPEDEF_(0x80094013)
#define CERTSRV_E_UNSUPPORTED_CERT_TYPE _HRESULT_TYPEDEF_(0x80094800)
#define CERTSRV_E_NO_CERT_TYPE _HRESULT_TYPEDEF_(0x80094801)
#define CERTSRV_E_TEMPLATE_CONFLICT _HRESULT_TYPEDEF_(0x80094802)
#define CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED _HRESULT_TYPEDEF_(0x80094803)
#define CERTSRV_E_ARCHIVED_KEY_REQUIRED _HRESULT_TYPEDEF_(0x80094804)
#define CERTSRV_E_SMIME_REQUIRED _HRESULT_TYPEDEF_(0x80094805)
#define CERTSRV_E_BAD_RENEWAL_SUBJECT _HRESULT_TYPEDEF_(0x80094806)
#define CERTSRV_E_BAD_TEMPLATE_VERSION _HRESULT_TYPEDEF_(0x80094807)
#define CERTSRV_E_TEMPLATE_POLICY_REQUIRED _HRESULT_TYPEDEF_(0x80094808)
#define CERTSRV_E_SIGNATURE_POLICY_REQUIRED _HRESULT_TYPEDEF_(0x80094809)
#define CERTSRV_E_SIGNATURE_COUNT _HRESULT_TYPEDEF_(0x8009480A)
#define CERTSRV_E_SIGNATURE_REJECTED _HRESULT_TYPEDEF_(0x8009480B)
#define CERTSRV_E_ISSUANCE_POLICY_REQUIRED _HRESULT_TYPEDEF_(0x8009480C)
#define CERTSRV_E_SUBJECT_UPN_REQUIRED _HRESULT_TYPEDEF_(0x8009480D)
#define CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED _HRESULT_TYPEDEF_(0x8009480E)
#define CERTSRV_E_SUBJECT_DNS_REQUIRED _HRESULT_TYPEDEF_(0x8009480F)
#define CERTSRV_E_ARCHIVED_KEY_UNEXPECTED _HRESULT_TYPEDEF_(0x80094810)
#define CERTSRV_E_KEY_LENGTH _HRESULT_TYPEDEF_(0x80094811)
#define CERTSRV_E_SUBJECT_EMAIL_REQUIRED _HRESULT_TYPEDEF_(0x80094812)
#define CERTSRV_E_UNKNOWN_CERT_TYPE _HRESULT_TYPEDEF_(0x80094813)
#define CERTSRV_E_CERT_TYPE_OVERLAP _HRESULT_TYPEDEF_(0x80094814)
#define XENROLL_E_KEY_NOT_EXPORTABLE _HRESULT_TYPEDEF_(0x80095000)
#define XENROLL_E_CANNOT_ADD_ROOT_CERT _HRESULT_TYPEDEF_(0x80095001)
#define XENROLL_E_RESPONSE_KA_HASH_NOT_FOUND _HRESULT_TYPEDEF_(0x80095002)
#define XENROLL_E_RESPONSE_UNEXPECTED_KA_HASH _HRESULT_TYPEDEF_(0x80095003)
#define XENROLL_E_RESPONSE_KA_HASH_MISMATCH _HRESULT_TYPEDEF_(0x80095004)
#define XENROLL_E_KEYSPEC_SMIME_MISMATCH _HRESULT_TYPEDEF_(0x80095005)
#define TRUST_E_SYSTEM_ERROR _HRESULT_TYPEDEF_(0x80096001)
#define TRUST_E_NO_SIGNER_CERT _HRESULT_TYPEDEF_(0x80096002)
#define TRUST_E_COUNTER_SIGNER _HRESULT_TYPEDEF_(0x80096003)
#define TRUST_E_CERT_SIGNATURE _HRESULT_TYPEDEF_(0x80096004)
#define TRUST_E_TIME_STAMP _HRESULT_TYPEDEF_(0x80096005)
#define TRUST_E_BAD_DIGEST _HRESULT_TYPEDEF_(0x80096010)
#define TRUST_E_BASIC_CONSTRAINTS _HRESULT_TYPEDEF_(0x80096019)
#define TRUST_E_FINANCIAL_CRITERIA _HRESULT_TYPEDEF_(0x8009601E)
#define MSSIPOTF_E_OUTOFMEMRANGE _HRESULT_TYPEDEF_(0x80097001)
#define MSSIPOTF_E_CANTGETOBJECT _HRESULT_TYPEDEF_(0x80097002)
#define MSSIPOTF_E_NOHEADTABLE _HRESULT_TYPEDEF_(0x80097003)
#define MSSIPOTF_E_BAD_MAGICNUMBER _HRESULT_TYPEDEF_(0x80097004)
#define MSSIPOTF_E_BAD_OFFSET_TABLE _HRESULT_TYPEDEF_(0x80097005)
#define MSSIPOTF_E_TABLE_TAGORDER _HRESULT_TYPEDEF_(0x80097006)
#define MSSIPOTF_E_TABLE_LONGWORD _HRESULT_TYPEDEF_(0x80097007)
#define MSSIPOTF_E_BAD_FIRST_TABLE_PLACEMENT _HRESULT_TYPEDEF_(0x80097008)
#define MSSIPOTF_E_TABLES_OVERLAP _HRESULT_TYPEDEF_(0x80097009)
#define MSSIPOTF_E_TABLE_PADBYTES _HRESULT_TYPEDEF_(0x8009700A)
#define MSSIPOTF_E_FILETOOSMALL _HRESULT_TYPEDEF_(0x8009700B)
#define MSSIPOTF_E_TABLE_CHECKSUM _HRESULT_TYPEDEF_(0x8009700C)
#define MSSIPOTF_E_FILE_CHECKSUM _HRESULT_TYPEDEF_(0x8009700D)
#define MSSIPOTF_E_FAILED_POLICY _HRESULT_TYPEDEF_(0x80097010)
#define MSSIPOTF_E_FAILED_HINTS_CHECK _HRESULT_TYPEDEF_(0x80097011)
#define MSSIPOTF_E_NOT_OPENTYPE _HRESULT_TYPEDEF_(0x80097012)
#define MSSIPOTF_E_FILE _HRESULT_TYPEDEF_(0x80097013)
#define MSSIPOTF_E_CRYPT _HRESULT_TYPEDEF_(0x80097014)
#define MSSIPOTF_E_BADVERSION _HRESULT_TYPEDEF_(0x80097015)
#define MSSIPOTF_E_DSIG_STRUCTURE _HRESULT_TYPEDEF_(0x80097016)
#define MSSIPOTF_E_PCONST_CHECK _HRESULT_TYPEDEF_(0x80097017)
#define MSSIPOTF_E_STRUCTURE _HRESULT_TYPEDEF_(0x80097018)
#define NTE_OP_OK 0
#define TRUST_E_PROVIDER_UNKNOWN _HRESULT_TYPEDEF_(0x800B0001)
#define TRUST_E_ACTION_UNKNOWN _HRESULT_TYPEDEF_(0x800B0002)
#define TRUST_E_SUBJECT_FORM_UNKNOWN _HRESULT_TYPEDEF_(0x800B0003)
#define TRUST_E_SUBJECT_NOT_TRUSTED _HRESULT_TYPEDEF_(0x800B0004)
#define DIGSIG_E_ENCODE _HRESULT_TYPEDEF_(0x800B0005)
#define DIGSIG_E_DECODE _HRESULT_TYPEDEF_(0x800B0006)
#define DIGSIG_E_EXTENSIBILITY _HRESULT_TYPEDEF_(0x800B0007)
#define DIGSIG_E_CRYPTO _HRESULT_TYPEDEF_(0x800B0008)
#define PERSIST_E_SIZEDEFINITE _HRESULT_TYPEDEF_(0x800B0009)
#define PERSIST_E_SIZEINDEFINITE _HRESULT_TYPEDEF_(0x800B000A)
#define PERSIST_E_NOTSELFSIZING _HRESULT_TYPEDEF_(0x800B000B)
#define TRUST_E_NOSIGNATURE _HRESULT_TYPEDEF_(0x800B0100)
#define CERT_E_EXPIRED _HRESULT_TYPEDEF_(0x800B0101)
#define CERT_E_VALIDITYPERIODNESTING _HRESULT_TYPEDEF_(0x800B0102)
#define CERT_E_ROLE _HRESULT_TYPEDEF_(0x800B0103)
#define CERT_E_PATHLENCONST _HRESULT_TYPEDEF_(0x800B0104)
#define CERT_E_CRITICAL _HRESULT_TYPEDEF_(0x800B0105)
#define CERT_E_PURPOSE _HRESULT_TYPEDEF_(0x800B0106)
#define CERT_E_ISSUERCHAINING _HRESULT_TYPEDEF_(0x800B0107)
#define CERT_E_MALFORMED _HRESULT_TYPEDEF_(0x800B0108)
#define CERT_E_UNTRUSTEDROOT _HRESULT_TYPEDEF_(0x800B0109)
#define CERT_E_CHAINING _HRESULT_TYPEDEF_(0x800B010A)
#define TRUST_E_FAIL _HRESULT_TYPEDEF_(0x800B010B)
#define CERT_E_REVOKED _HRESULT_TYPEDEF_(0x800B010C)
#define CERT_E_UNTRUSTEDTESTROOT _HRESULT_TYPEDEF_(0x800B010D)
#define CERT_E_REVOCATION_FAILURE _HRESULT_TYPEDEF_(0x800B010E)
#define CERT_E_CN_NO_MATCH _HRESULT_TYPEDEF_(0x800B010F)
#define CERT_E_WRONG_USAGE _HRESULT_TYPEDEF_(0x800B0110)
#define TRUST_E_EXPLICIT_DISTRUST _HRESULT_TYPEDEF_(0x800B0111)
#define CERT_E_UNTRUSTEDCA _HRESULT_TYPEDEF_(0x800B0112)
#define CERT_E_INVALID_POLICY _HRESULT_TYPEDEF_(0x800B0113)
#define CERT_E_INVALID_NAME _HRESULT_TYPEDEF_(0x800B0114)
#define HRESULT_FROM_SETUPAPI(x) ((((x) & (APPLICATION_ERROR_MASK|ERROR_SEVERITY_ERROR))==(APPLICATION_ERROR_MASK|ERROR_SEVERITY_ERROR)) ? ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_SETUPAPI << 16) | 0x80000000)) : HRESULT_FROM_WIN32(x))
#define SPAPI_E_EXPECTED_SECTION_NAME _HRESULT_TYPEDEF_(0x800F0000)
#define SPAPI_E_BAD_SECTION_NAME_LINE _HRESULT_TYPEDEF_(0x800F0001)
#define SPAPI_E_SECTION_NAME_TOO_LONG _HRESULT_TYPEDEF_(0x800F0002)
#define SPAPI_E_GENERAL_SYNTAX _HRESULT_TYPEDEF_(0x800F0003)
#define SPAPI_E_WRONG_INF_STYLE _HRESULT_TYPEDEF_(0x800F0100)
#define SPAPI_E_SECTION_NOT_FOUND _HRESULT_TYPEDEF_(0x800F0101)
#define SPAPI_E_LINE_NOT_FOUND _HRESULT_TYPEDEF_(0x800F0102)
#define SPAPI_E_NO_BACKUP _HRESULT_TYPEDEF_(0x800F0103)
#define SPAPI_E_NO_ASSOCIATED_CLASS _HRESULT_TYPEDEF_(0x800F0200)
#define SPAPI_E_CLASS_MISMATCH _HRESULT_TYPEDEF_(0x800F0201)
#define SPAPI_E_DUPLICATE_FOUND _HRESULT_TYPEDEF_(0x800F0202)
#define SPAPI_E_NO_DRIVER_SELECTED _HRESULT_TYPEDEF_(0x800F0203)
#define SPAPI_E_KEY_DOES_NOT_EXIST _HRESULT_TYPEDEF_(0x800F0204)
#define SPAPI_E_INVALID_DEVINST_NAME _HRESULT_TYPEDEF_(0x800F0205)
#define SPAPI_E_INVALID_CLASS _HRESULT_TYPEDEF_(0x800F0206)
#define SPAPI_E_DEVINST_ALREADY_EXISTS _HRESULT_TYPEDEF_(0x800F0207)
#define SPAPI_E_DEVINFO_NOT_REGISTERED _HRESULT_TYPEDEF_(0x800F0208)
#define SPAPI_E_INVALID_REG_PROPERTY _HRESULT_TYPEDEF_(0x800F0209)
#define SPAPI_E_NO_INF _HRESULT_TYPEDEF_(0x800F020A)
#define SPAPI_E_NO_SUCH_DEVINST _HRESULT_TYPEDEF_(0x800F020B)
#define SPAPI_E_CANT_LOAD_CLASS_ICON _HRESULT_TYPEDEF_(0x800F020C)
#define SPAPI_E_INVALID_CLASS_INSTALLER _HRESULT_TYPEDEF_(0x800F020D)
#define SPAPI_E_DI_DO_DEFAULT _HRESULT_TYPEDEF_(0x800F020E)
#define SPAPI_E_DI_NOFILECOPY _HRESULT_TYPEDEF_(0x800F020F)
#define SPAPI_E_INVALID_HWPROFILE _HRESULT_TYPEDEF_(0x800F0210)
#define SPAPI_E_NO_DEVICE_SELECTED _HRESULT_TYPEDEF_(0x800F0211)
#define SPAPI_E_DEVINFO_LIST_LOCKED _HRESULT_TYPEDEF_(0x800F0212)
#define SPAPI_E_DEVINFO_DATA_LOCKED _HRESULT_TYPEDEF_(0x800F0213)
#define SPAPI_E_DI_BAD_PATH _HRESULT_TYPEDEF_(0x800F0214)
#define SPAPI_E_NO_CLASSINSTALL_PARAMS _HRESULT_TYPEDEF_(0x800F0215)
#define SPAPI_E_FILEQUEUE_LOCKED _HRESULT_TYPEDEF_(0x800F0216)
#define SPAPI_E_BAD_SERVICE_INSTALLSECT _HRESULT_TYPEDEF_(0x800F0217)
#define SPAPI_E_NO_CLASS_DRIVER_LIST _HRESULT_TYPEDEF_(0x800F0218)
#define SPAPI_E_NO_ASSOCIATED_SERVICE _HRESULT_TYPEDEF_(0x800F0219)
#define SPAPI_E_NO_DEFAULT_DEVICE_INTERFACE _HRESULT_TYPEDEF_(0x800F021A)
#define SPAPI_E_DEVICE_INTERFACE_ACTIVE _HRESULT_TYPEDEF_(0x800F021B)
#define SPAPI_E_DEVICE_INTERFACE_REMOVED _HRESULT_TYPEDEF_(0x800F021C)
#define SPAPI_E_BAD_INTERFACE_INSTALLSECT _HRESULT_TYPEDEF_(0x800F021D)
#define SPAPI_E_NO_SUCH_INTERFACE_CLASS _HRESULT_TYPEDEF_(0x800F021E)
#define SPAPI_E_INVALID_REFERENCE_STRING _HRESULT_TYPEDEF_(0x800F021F)
#define SPAPI_E_INVALID_MACHINENAME _HRESULT_TYPEDEF_(0x800F0220)
#define SPAPI_E_REMOTE_COMM_FAILURE _HRESULT_TYPEDEF_(0x800F0221)
#define SPAPI_E_MACHINE_UNAVAILABLE _HRESULT_TYPEDEF_(0x800F0222)
#define SPAPI_E_NO_CONFIGMGR_SERVICES _HRESULT_TYPEDEF_(0x800F0223)
#define SPAPI_E_INVALID_PROPPAGE_PROVIDER _HRESULT_TYPEDEF_(0x800F0224)
#define SPAPI_E_NO_SUCH_DEVICE_INTERFACE _HRESULT_TYPEDEF_(0x800F0225)
#define SPAPI_E_DI_POSTPROCESSING_REQUIRED _HRESULT_TYPEDEF_(0x800F0226)
#define SPAPI_E_INVALID_COINSTALLER _HRESULT_TYPEDEF_(0x800F0227)
#define SPAPI_E_NO_COMPAT_DRIVERS _HRESULT_TYPEDEF_(0x800F0228)
#define SPAPI_E_NO_DEVICE_ICON _HRESULT_TYPEDEF_(0x800F0229)
#define SPAPI_E_INVALID_INF_LOGCONFIG _HRESULT_TYPEDEF_(0x800F022A)
#define SPAPI_E_DI_DONT_INSTALL _HRESULT_TYPEDEF_(0x800F022B)
#define SPAPI_E_INVALID_FILTER_DRIVER _HRESULT_TYPEDEF_(0x800F022C)
#define SPAPI_E_NON_WINDOWS_NT_DRIVER _HRESULT_TYPEDEF_(0x800F022D)
#define SPAPI_E_NON_WINDOWS_DRIVER _HRESULT_TYPEDEF_(0x800F022E)
#define SPAPI_E_NO_CATALOG_FOR_OEM_INF _HRESULT_TYPEDEF_(0x800F022F)
#define SPAPI_E_DEVINSTALL_QUEUE_NONNATIVE _HRESULT_TYPEDEF_(0x800F0230)
#define SPAPI_E_NOT_DISABLEABLE _HRESULT_TYPEDEF_(0x800F0231)
#define SPAPI_E_CANT_REMOVE_DEVINST _HRESULT_TYPEDEF_(0x800F0232)
#define SPAPI_E_INVALID_TARGET _HRESULT_TYPEDEF_(0x800F0233)
#define SPAPI_E_DRIVER_NONNATIVE _HRESULT_TYPEDEF_(0x800F0234)
#define SPAPI_E_IN_WOW64 _HRESULT_TYPEDEF_(0x800F0235)
#define SPAPI_E_SET_SYSTEM_RESTORE_POINT _HRESULT_TYPEDEF_(0x800F0236)
#define SPAPI_E_INCORRECTLY_COPIED_INF _HRESULT_TYPEDEF_(0x800F0237)
#define SPAPI_E_SCE_DISABLED _HRESULT_TYPEDEF_(0x800F0238)
#define SPAPI_E_UNKNOWN_EXCEPTION _HRESULT_TYPEDEF_(0x800F0239)
#define SPAPI_E_PNP_REGISTRY_ERROR _HRESULT_TYPEDEF_(0x800F023A)
#define SPAPI_E_REMOTE_REQUEST_UNSUPPORTED _HRESULT_TYPEDEF_(0x800F023B)
#define SPAPI_E_NOT_AN_INSTALLED_OEM_INF _HRESULT_TYPEDEF_(0x800F023C)
#define SPAPI_E_INF_IN_USE_BY_DEVICES _HRESULT_TYPEDEF_(0x800F023D)
#define SPAPI_E_DI_FUNCTION_OBSOLETE _HRESULT_TYPEDEF_(0x800F023E)
#define SPAPI_E_NO_AUTHENTICODE_CATALOG _HRESULT_TYPEDEF_(0x800F023F)
#define SPAPI_E_AUTHENTICODE_DISALLOWED _HRESULT_TYPEDEF_(0x800F0240)
#define SPAPI_E_AUTHENTICODE_TRUSTED_PUBLISHER _HRESULT_TYPEDEF_(0x800F0241)
#define SPAPI_E_AUTHENTICODE_TRUST_NOT_ESTABLISHED _HRESULT_TYPEDEF_(0x800F0242)
#define SPAPI_E_AUTHENTICODE_PUBLISHER_NOT_TRUSTED _HRESULT_TYPEDEF_(0x800F0243)
#define SPAPI_E_SIGNATURE_OSATTRIBUTE_MISMATCH _HRESULT_TYPEDEF_(0x800F0244)
#define SPAPI_E_ONLY_VALIDATE_VIA_AUTHENTICODE _HRESULT_TYPEDEF_(0x800F0245)
#define SPAPI_E_UNRECOVERABLE_STACK_OVERFLOW _HRESULT_TYPEDEF_(0x800F0300)
#define SPAPI_E_ERROR_NOT_INSTALLED _HRESULT_TYPEDEF_(0x800F1000)
#define SCARD_S_SUCCESS NO_ERROR
#define SCARD_F_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x80100001)
#define SCARD_E_CANCELLED _HRESULT_TYPEDEF_(0x80100002)
#define SCARD_E_INVALID_HANDLE _HRESULT_TYPEDEF_(0x80100003)
#define SCARD_E_INVALID_PARAMETER _HRESULT_TYPEDEF_(0x80100004)
#define SCARD_E_INVALID_TARGET _HRESULT_TYPEDEF_(0x80100005)
#define SCARD_E_NO_MEMORY _HRESULT_TYPEDEF_(0x80100006)
#define SCARD_F_WAITED_TOO_LONG _HRESULT_TYPEDEF_(0x80100007)
#define SCARD_E_INSUFFICIENT_BUFFER _HRESULT_TYPEDEF_(0x80100008)
#define SCARD_E_UNKNOWN_READER _HRESULT_TYPEDEF_(0x80100009)
#define SCARD_E_TIMEOUT _HRESULT_TYPEDEF_(0x8010000A)
#define SCARD_E_SHARING_VIOLATION _HRESULT_TYPEDEF_(0x8010000B)
#define SCARD_E_NO_SMARTCARD _HRESULT_TYPEDEF_(0x8010000C)
#define SCARD_E_UNKNOWN_CARD _HRESULT_TYPEDEF_(0x8010000D)
#define SCARD_E_CANT_DISPOSE _HRESULT_TYPEDEF_(0x8010000E)
#define SCARD_E_PROTO_MISMATCH _HRESULT_TYPEDEF_(0x8010000F)
#define SCARD_E_NOT_READY _HRESULT_TYPEDEF_(0x80100010)
#define SCARD_E_INVALID_VALUE _HRESULT_TYPEDEF_(0x80100011)
#define SCARD_E_SYSTEM_CANCELLED _HRESULT_TYPEDEF_(0x80100012)
#define SCARD_F_COMM_ERROR _HRESULT_TYPEDEF_(0x80100013)
#define SCARD_F_UNKNOWN_ERROR _HRESULT_TYPEDEF_(0x80100014)
#define SCARD_E_INVALID_ATR _HRESULT_TYPEDEF_(0x80100015)
#define SCARD_E_NOT_TRANSACTED _HRESULT_TYPEDEF_(0x80100016)
#define SCARD_E_READER_UNAVAILABLE _HRESULT_TYPEDEF_(0x80100017)
#define SCARD_P_SHUTDOWN _HRESULT_TYPEDEF_(0x80100018)
#define SCARD_E_PCI_TOO_SMALL _HRESULT_TYPEDEF_(0x80100019)
#define SCARD_E_READER_UNSUPPORTED _HRESULT_TYPEDEF_(0x8010001A)
#define SCARD_E_DUPLICATE_READER _HRESULT_TYPEDEF_(0x8010001B)
#define SCARD_E_CARD_UNSUPPORTED _HRESULT_TYPEDEF_(0x8010001C)
#define SCARD_E_NO_SERVICE _HRESULT_TYPEDEF_(0x8010001D)
#define SCARD_E_SERVICE_STOPPED _HRESULT_TYPEDEF_(0x8010001E)
#define SCARD_E_UNEXPECTED _HRESULT_TYPEDEF_(0x8010001F)
#define SCARD_E_ICC_INSTALLATION _HRESULT_TYPEDEF_(0x80100020)
#define SCARD_E_ICC_CREATEORDER _HRESULT_TYPEDEF_(0x80100021)
#define SCARD_E_UNSUPPORTED_FEATURE _HRESULT_TYPEDEF_(0x80100022)
#define SCARD_E_DIR_NOT_FOUND _HRESULT_TYPEDEF_(0x80100023)
#define SCARD_E_FILE_NOT_FOUND _HRESULT_TYPEDEF_(0x80100024)
#define SCARD_E_NO_DIR _HRESULT_TYPEDEF_(0x80100025)
#define SCARD_E_NO_FILE _HRESULT_TYPEDEF_(0x80100026)
#define SCARD_E_NO_ACCESS _HRESULT_TYPEDEF_(0x80100027)
#define SCARD_E_WRITE_TOO_MANY _HRESULT_TYPEDEF_(0x80100028)
#define SCARD_E_BAD_SEEK _HRESULT_TYPEDEF_(0x80100029)
#define SCARD_E_INVALID_CHV _HRESULT_TYPEDEF_(0x8010002A)
#define SCARD_E_UNKNOWN_RES_MNG _HRESULT_TYPEDEF_(0x8010002B)
#define SCARD_E_NO_SUCH_CERTIFICATE _HRESULT_TYPEDEF_(0x8010002C)
#define SCARD_E_CERTIFICATE_UNAVAILABLE _HRESULT_TYPEDEF_(0x8010002D)
#define SCARD_E_NO_READERS_AVAILABLE _HRESULT_TYPEDEF_(0x8010002E)
#define SCARD_E_COMM_DATA_LOST _HRESULT_TYPEDEF_(0x8010002F)
#define SCARD_E_NO_KEY_CONTAINER _HRESULT_TYPEDEF_(0x80100030)
#define SCARD_E_SERVER_TOO_BUSY _HRESULT_TYPEDEF_(0x80100031)
#define SCARD_W_UNSUPPORTED_CARD _HRESULT_TYPEDEF_(0x80100065)
#define SCARD_W_UNRESPONSIVE_CARD _HRESULT_TYPEDEF_(0x80100066)
#define SCARD_W_UNPOWERED_CARD _HRESULT_TYPEDEF_(0x80100067)
#define SCARD_W_RESET_CARD _HRESULT_TYPEDEF_(0x80100068)
#define SCARD_W_REMOVED_CARD _HRESULT_TYPEDEF_(0x80100069)
#define SCARD_W_SECURITY_VIOLATION _HRESULT_TYPEDEF_(0x8010006A)
#define SCARD_W_WRONG_CHV _HRESULT_TYPEDEF_(0x8010006B)
#define SCARD_W_CHV_BLOCKED _HRESULT_TYPEDEF_(0x8010006C)
#define SCARD_W_EOF _HRESULT_TYPEDEF_(0x8010006D)
#define SCARD_W_CANCELLED_BY_USER _HRESULT_TYPEDEF_(0x8010006E)
#define SCARD_W_CARD_NOT_AUTHENTICATED _HRESULT_TYPEDEF_(0x8010006F)
#define SCARD_W_CACHE_ITEM_NOT_FOUND _HRESULT_TYPEDEF_(0x80100070)
#define SCARD_W_CACHE_ITEM_STALE _HRESULT_TYPEDEF_(0x80100071)
#define COMADMIN_E_OBJECTERRORS _HRESULT_TYPEDEF_(0x80110401)
#define COMADMIN_E_OBJECTINVALID _HRESULT_TYPEDEF_(0x80110402)
#define COMADMIN_E_KEYMISSING _HRESULT_TYPEDEF_(0x80110403)
#define COMADMIN_E_ALREADYINSTALLED _HRESULT_TYPEDEF_(0x80110404)
#define COMADMIN_E_APP_FILE_WRITEFAIL _HRESULT_TYPEDEF_(0x80110407)
#define COMADMIN_E_APP_FILE_READFAIL _HRESULT_TYPEDEF_(0x80110408)
#define COMADMIN_E_APP_FILE_VERSION _HRESULT_TYPEDEF_(0x80110409)
#define COMADMIN_E_BADPATH _HRESULT_TYPEDEF_(0x8011040A)
#define COMADMIN_E_APPLICATIONEXISTS _HRESULT_TYPEDEF_(0x8011040B)
#define COMADMIN_E_ROLEEXISTS _HRESULT_TYPEDEF_(0x8011040C)
#define COMADMIN_E_CANTCOPYFILE _HRESULT_TYPEDEF_(0x8011040D)
#define COMADMIN_E_NOUSER _HRESULT_TYPEDEF_(0x8011040F)
#define COMADMIN_E_INVALIDUSERIDS _HRESULT_TYPEDEF_(0x80110410)
#define COMADMIN_E_NOREGISTRYCLSID _HRESULT_TYPEDEF_(0x80110411)
#define COMADMIN_E_BADREGISTRYPROGID _HRESULT_TYPEDEF_(0x80110412)
#define COMADMIN_E_AUTHENTICATIONLEVEL _HRESULT_TYPEDEF_(0x80110413)
#define COMADMIN_E_USERPASSWDNOTVALID _HRESULT_TYPEDEF_(0x80110414)
#define COMADMIN_E_CLSIDORIIDMISMATCH _HRESULT_TYPEDEF_(0x80110418)
#define COMADMIN_E_REMOTEINTERFACE _HRESULT_TYPEDEF_(0x80110419)
#define COMADMIN_E_DLLREGISTERSERVER _HRESULT_TYPEDEF_(0x8011041A)
#define COMADMIN_E_NOSERVERSHARE _HRESULT_TYPEDEF_(0x8011041B)
#define COMADMIN_E_DLLLOADFAILED _HRESULT_TYPEDEF_(0x8011041D)
#define COMADMIN_E_BADREGISTRYLIBID _HRESULT_TYPEDEF_(0x8011041E)
#define COMADMIN_E_APPDIRNOTFOUND _HRESULT_TYPEDEF_(0x8011041F)
#define COMADMIN_E_REGISTRARFAILED _HRESULT_TYPEDEF_(0x80110423)
#define COMADMIN_E_COMPFILE_DOESNOTEXIST _HRESULT_TYPEDEF_(0x80110424)
#define COMADMIN_E_COMPFILE_LOADDLLFAIL _HRESULT_TYPEDEF_(0x80110425)
#define COMADMIN_E_COMPFILE_GETCLASSOBJ _HRESULT_TYPEDEF_(0x80110426)
#define COMADMIN_E_COMPFILE_CLASSNOTAVAIL _HRESULT_TYPEDEF_(0x80110427)
#define COMADMIN_E_COMPFILE_BADTLB _HRESULT_TYPEDEF_(0x80110428)
#define COMADMIN_E_COMPFILE_NOTINSTALLABLE _HRESULT_TYPEDEF_(0x80110429)
#define COMADMIN_E_NOTCHANGEABLE _HRESULT_TYPEDEF_(0x8011042A)
#define COMADMIN_E_NOTDELETEABLE _HRESULT_TYPEDEF_(0x8011042B)
#define COMADMIN_E_SESSION _HRESULT_TYPEDEF_(0x8011042C)
#define COMADMIN_E_COMP_MOVE_LOCKED _HRESULT_TYPEDEF_(0x8011042D)
#define COMADMIN_E_COMP_MOVE_BAD_DEST _HRESULT_TYPEDEF_(0x8011042E)
#define COMADMIN_E_REGISTERTLB _HRESULT_TYPEDEF_(0x80110430)
#define COMADMIN_E_SYSTEMAPP _HRESULT_TYPEDEF_(0x80110433)
#define COMADMIN_E_COMPFILE_NOREGISTRAR _HRESULT_TYPEDEF_(0x80110434)
#define COMADMIN_E_COREQCOMPINSTALLED _HRESULT_TYPEDEF_(0x80110435)
#define COMADMIN_E_SERVICENOTINSTALLED _HRESULT_TYPEDEF_(0x80110436)
#define COMADMIN_E_PROPERTYSAVEFAILED _HRESULT_TYPEDEF_(0x80110437)
#define COMADMIN_E_OBJECTEXISTS _HRESULT_TYPEDEF_(0x80110438)
#define COMADMIN_E_COMPONENTEXISTS _HRESULT_TYPEDEF_(0x80110439)
#define COMADMIN_E_REGFILE_CORRUPT _HRESULT_TYPEDEF_(0x8011043B)
#define COMADMIN_E_PROPERTY_OVERFLOW _HRESULT_TYPEDEF_(0x8011043C)
#define COMADMIN_E_NOTINREGISTRY _HRESULT_TYPEDEF_(0x8011043E)
#define COMADMIN_E_OBJECTNOTPOOLABLE _HRESULT_TYPEDEF_(0x8011043F)
#define COMADMIN_E_APPLID_MATCHES_CLSID _HRESULT_TYPEDEF_(0x80110446)
#define COMADMIN_E_ROLE_DOES_NOT_EXIST _HRESULT_TYPEDEF_(0x80110447)
#define COMADMIN_E_START_APP_NEEDS_COMPONENTS _HRESULT_TYPEDEF_(0x80110448)
#define COMADMIN_E_REQUIRES_DIFFERENT_PLATFORM _HRESULT_TYPEDEF_(0x80110449)
#define COMADMIN_E_CAN_NOT_EXPORT_APP_PROXY _HRESULT_TYPEDEF_(0x8011044A)
#define COMADMIN_E_CAN_NOT_START_APP _HRESULT_TYPEDEF_(0x8011044B)
#define COMADMIN_E_CAN_NOT_EXPORT_SYS_APP _HRESULT_TYPEDEF_(0x8011044C)
#define COMADMIN_E_CANT_SUBSCRIBE_TO_COMPONENT _HRESULT_TYPEDEF_(0x8011044D)
#define COMADMIN_E_EVENTCLASS_CANT_BE_SUBSCRIBER _HRESULT_TYPEDEF_(0x8011044E)
#define COMADMIN_E_LIB_APP_PROXY_INCOMPATIBLE _HRESULT_TYPEDEF_(0x8011044F)
#define COMADMIN_E_BASE_PARTITION_ONLY _HRESULT_TYPEDEF_(0x80110450)
#define COMADMIN_E_START_APP_DISABLED _HRESULT_TYPEDEF_(0x80110451)
#define COMADMIN_E_CAT_DUPLICATE_PARTITION_NAME _HRESULT_TYPEDEF_(0x80110457)
#define COMADMIN_E_CAT_INVALID_PARTITION_NAME _HRESULT_TYPEDEF_(0x80110458)
#define COMADMIN_E_CAT_PARTITION_IN_USE _HRESULT_TYPEDEF_(0x80110459)
#define COMADMIN_E_FILE_PARTITION_DUPLICATE_FILES _HRESULT_TYPEDEF_(0x8011045A)
#define COMADMIN_E_CAT_IMPORTED_COMPONENTS_NOT_ALLOWED _HRESULT_TYPEDEF_(0x8011045B)
#define COMADMIN_E_AMBIGUOUS_APPLICATION_NAME _HRESULT_TYPEDEF_(0x8011045C)
#define COMADMIN_E_AMBIGUOUS_PARTITION_NAME _HRESULT_TYPEDEF_(0x8011045D)
#define COMADMIN_E_REGDB_NOTINITIALIZED _HRESULT_TYPEDEF_(0x80110472)
#define COMADMIN_E_REGDB_NOTOPEN _HRESULT_TYPEDEF_(0x80110473)
#define COMADMIN_E_REGDB_SYSTEMERR _HRESULT_TYPEDEF_(0x80110474)
#define COMADMIN_E_REGDB_ALREADYRUNNING _HRESULT_TYPEDEF_(0x80110475)
#define COMADMIN_E_MIG_VERSIONNOTSUPPORTED _HRESULT_TYPEDEF_(0x80110480)
#define COMADMIN_E_MIG_SCHEMANOTFOUND _HRESULT_TYPEDEF_(0x80110481)
#define COMADMIN_E_CAT_BITNESSMISMATCH _HRESULT_TYPEDEF_(0x80110482)
#define COMADMIN_E_CAT_UNACCEPTABLEBITNESS _HRESULT_TYPEDEF_(0x80110483)
#define COMADMIN_E_CAT_WRONGAPPBITNESS _HRESULT_TYPEDEF_(0x80110484)
#define COMADMIN_E_CAT_PAUSE_RESUME_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x80110485)
#define COMADMIN_E_CAT_SERVERFAULT _HRESULT_TYPEDEF_(0x80110486)
#define COMQC_E_APPLICATION_NOT_QUEUED _HRESULT_TYPEDEF_(0x80110600)
#define COMQC_E_NO_QUEUEABLE_INTERFACES _HRESULT_TYPEDEF_(0x80110601)
#define COMQC_E_QUEUING_SERVICE_NOT_AVAILABLE _HRESULT_TYPEDEF_(0x80110602)
#define COMQC_E_NO_IPERSISTSTREAM _HRESULT_TYPEDEF_(0x80110603)
#define COMQC_E_BAD_MESSAGE _HRESULT_TYPEDEF_(0x80110604)
#define COMQC_E_UNAUTHENTICATED _HRESULT_TYPEDEF_(0x80110605)
#define COMQC_E_UNTRUSTED_ENQUEUER _HRESULT_TYPEDEF_(0x80110606)
#define MSDTC_E_DUPLICATE_RESOURCE _HRESULT_TYPEDEF_(0x80110701)
#define COMADMIN_E_OBJECT_PARENT_MISSING _HRESULT_TYPEDEF_(0x80110808)
#define COMADMIN_E_OBJECT_DOES_NOT_EXIST _HRESULT_TYPEDEF_(0x80110809)
#define COMADMIN_E_APP_NOT_RUNNING _HRESULT_TYPEDEF_(0x8011080A)
#define COMADMIN_E_INVALID_PARTITION _HRESULT_TYPEDEF_(0x8011080B)
#define COMADMIN_E_SVCAPP_NOT_POOLABLE_OR_RECYCLABLE _HRESULT_TYPEDEF_(0x8011080D)
#define COMADMIN_E_USER_IN_SET _HRESULT_TYPEDEF_(0x8011080E)
#define COMADMIN_E_CANTRECYCLELIBRARYAPPS _HRESULT_TYPEDEF_(0x8011080F)
#define COMADMIN_E_CANTRECYCLESERVICEAPPS _HRESULT_TYPEDEF_(0x80110811)
#define COMADMIN_E_PROCESSALREADYRECYCLED _HRESULT_TYPEDEF_(0x80110812)
#define COMADMIN_E_PAUSEDPROCESSMAYNOTBERECYCLED _HRESULT_TYPEDEF_(0x80110813)
#define COMADMIN_E_CANTMAKEINPROCSERVICE _HRESULT_TYPEDEF_(0x80110814)
#define COMADMIN_E_PROGIDINUSEBYCLSID _HRESULT_TYPEDEF_(0x80110815)
#define COMADMIN_E_DEFAULT_PARTITION_NOT_IN_SET _HRESULT_TYPEDEF_(0x80110816)
#define COMADMIN_E_RECYCLEDPROCESSMAYNOTBEPAUSED _HRESULT_TYPEDEF_(0x80110817)
#define COMADMIN_E_PARTITION_ACCESSDENIED _HRESULT_TYPEDEF_(0x80110818)
#define COMADMIN_E_PARTITION_MSI_ONLY _HRESULT_TYPEDEF_(0x80110819)
#define COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_1_0_FORMAT _HRESULT_TYPEDEF_(0x8011081A)
#define COMADMIN_E_LEGACYCOMPS_NOT_ALLOWED_IN_NONBASE_PARTITIONS _HRESULT_TYPEDEF_(0x8011081B)
#define COMADMIN_E_COMP_MOVE_SOURCE _HRESULT_TYPEDEF_(0x8011081C)
#define COMADMIN_E_COMP_MOVE_DEST _HRESULT_TYPEDEF_(0x8011081D)
#define COMADMIN_E_COMP_MOVE_PRIVATE _HRESULT_TYPEDEF_(0x8011081E)
#define COMADMIN_E_BASEPARTITION_REQUIRED_IN_SET _HRESULT_TYPEDEF_(0x8011081F)
#define COMADMIN_E_CANNOT_ALIAS_EVENTCLASS _HRESULT_TYPEDEF_(0x80110820)
#define COMADMIN_E_PRIVATE_ACCESSDENIED _HRESULT_TYPEDEF_(0x80110821)
#define COMADMIN_E_SAFERINVALID _HRESULT_TYPEDEF_(0x80110822)
#define COMADMIN_E_REGISTRY_ACCESSDENIED _HRESULT_TYPEDEF_(0x80110823)
#define COMADMIN_E_PARTITIONS_DISABLED _HRESULT_TYPEDEF_(0x80110824)
#define VSS_E_BAD_STATE _HRESULT_TYPEDEF_(0x80042301)
#define VSS_E_LEGACY_PROVIDER _HRESULT_TYPEDEF_(0x800423F7)
#define VSS_E_RESYNC_IN_PROGRESS _HRESULT_TYPEDEF_(0x800423FF)
#define VSS_E_SNAPSHOT_NOT_IN_SET _HRESULT_TYPEDEF_(0x8004232B)
#define VSS_E_MAXIMUM_NUMBER_OF_VOLUMES_REACHED _HRESULT_TYPEDEF_(0x80042312)
#define VSS_E_MAXIMUM_NUMBER_OF_SNAPSHOTS_REACHED _HRESULT_TYPEDEF_(0x80042317)
#define VSS_E_NESTED_VOLUME_LIMIT _HRESULT_TYPEDEF_(0x8004232C)
#define VSS_E_OBJECT_NOT_FOUND _HRESULT_TYPEDEF_(0x80042308)
#define VSS_E_PROVIDER_NOT_REGISTERED _HRESULT_TYPEDEF_(0x80042304)
#define VSS_E_PROVIDER_VETO _HRESULT_TYPEDEF_(0x80042306)
#define VSS_E_VOLUME_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x8004230C)
#define VSS_E_VOLUME_NOT_SUPPORTED_BY_PROVIDER _HRESULT_TYPEDEF_(0x8004230E)
#define VSS_E_UNEXPECTED _HRESULT_TYPEDEF_(0x80042302)
#define VSS_E_UNEXPECTED_PROVIDER_ERROR _HRESULT_TYPEDEF_(0x8004230F)
#define VSS_E_UNSELECTED_VOLUME _HRESULT_TYPEDEF_(0x8004232A)
#define VSS_E_CANNOT_REVERT_DISKID _HRESULT_TYPEDEF_(0x800423FE)
#define VSS_E_INVALID_XML_DOCUMENT _HRESULT_TYPEDEF_(0x80042311)
#define VSS_E_OBJECT_ALREADY_EXISTS _HRESULT_TYPEDEF_(0x8004230D)
#define DXGI_ERROR_INVALID_CALL _HRESULT_TYPEDEF_(0x887A0001)
#define DXGI_ERROR_NOT_FOUND _HRESULT_TYPEDEF_(0x887A0002)
#define DXGI_ERROR_MORE_DATA _HRESULT_TYPEDEF_(0x887A0003)
#define DXGI_ERROR_UNSUPPORTED _HRESULT_TYPEDEF_(0x887A0004)
#define DXGI_ERROR_DEVICE_REMOVED _HRESULT_TYPEDEF_(0x887A0005)
#define DXGI_ERROR_DEVICE_HUNG _HRESULT_TYPEDEF_(0x887A0006)
#define DXGI_ERROR_DEVICE_RESET _HRESULT_TYPEDEF_(0x887A0007)
#define DXGI_ERROR_WAS_STILL_DRAWING _HRESULT_TYPEDEF_(0x887A000A)
#define DXGI_ERROR_FRAME_STATISTICS_DISJOINT _HRESULT_TYPEDEF_(0x887A000B)
#define DXGI_ERROR_GRAPHICS_VIDPN_SOURCE_IN_USE _HRESULT_TYPEDEF_(0x887A000C)
#define DXGI_ERROR_DRIVER_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x887A0020)
#define DXGI_ERROR_NONEXCLUSIVE _HRESULT_TYPEDEF_(0x887A0021)
#define DXGI_ERROR_NOT_CURRENTLY_AVAILABLE _HRESULT_TYPEDEF_(0x887A0022)
#define DXGI_ERROR_REMOTE_CLIENT_DISCONNECTED _HRESULT_TYPEDEF_(0x887A0023)
#define DXGI_ERROR_REMOTE_OUTOFMEMORY _HRESULT_TYPEDEF_(0x887A0024)
#define DXGI_ERROR_ACCESS_LOST _HRESULT_TYPEDEF_(0x887A0026)
#define DXGI_ERROR_WAIT_TIMEOUT _HRESULT_TYPEDEF_(0x887A0027)
#define DXGI_ERROR_SESSION_DISCONNECTED _HRESULT_TYPEDEF_(0x887A0028)
#define DXGI_ERROR_RESTRICT_TO_OUTPUT_STALE _HRESULT_TYPEDEF_(0x887A0029)
#define DXGI_ERROR_CANNOT_PROTECT_CONTENT _HRESULT_TYPEDEF_(0x887A002A)
#define DXGI_ERROR_ACCESS_DENIED _HRESULT_TYPEDEF_(0x887A002B)
#define DXGI_ERROR_NAME_ALREADY_EXISTS _HRESULT_TYPEDEF_(0x887A002C)
#define DXGI_ERROR_SDK_COMPONENT_MISSING _HRESULT_TYPEDEF_(0x887A002D)

#define TBS_SUCCESS 0U
#define TBS_E_INTERNAL_ERROR _HRESULT_TYPEDEF_(0x80284001)
#define TBS_E_BAD_PARAMETER _HRESULT_TYPEDEF_(0x80284002)
#define TBS_E_INVALID_OUTPUT_POINTER _HRESULT_TYPEDEF_(0x80284003)
#define TBS_E_INSUFFICIENT_BUFFER _HRESULT_TYPEDEF_(0x80284005)
#define TBS_E_IOERROR _HRESULT_TYPEDEF_(0x80284006)
#define TBS_E_INVALID_CONTEXT_PARAM _HRESULT_TYPEDEF_(0x80284007)
#define TBS_E_SERVICE_NOT_RUNNING _HRESULT_TYPEDEF_(0x80284008)
#define TBS_E_TOO_MANY_TBS_CONTEXTS _HRESULT_TYPEDEF_(0x80284009)
#define TBS_E_SERVICE_START_PENDING _HRESULT_TYPEDEF_(0x8028400B)
#define TBS_E_BUFFER_TOO_LARGE _HRESULT_TYPEDEF_(0x8028400E)
#define TBS_E_TPM_NOT_FOUND _HRESULT_TYPEDEF_(0x8028400F)
#define TBS_E_SERVICE_DISABLED _HRESULT_TYPEDEF_(0x80284010)
#define TBS_E_DEACTIVATED _HRESULT_TYPEDEF_(0x80284016)
#define FWP_E_CALLOUT_NOT_FOUND _HRESULT_TYPEDEF_(0x80320001)
#define FWP_E_CONDITION_NOT_FOUND _HRESULT_TYPEDEF_(0x80320002)
#define FWP_E_FILTER_NOT_FOUND _HRESULT_TYPEDEF_(0x80320003)
#define FWP_E_LAYER_NOT_FOUND _HRESULT_TYPEDEF_(0x80320004)
#define FWP_E_PROVIDER_NOT_FOUND _HRESULT_TYPEDEF_(0x80320005)
#define FWP_E_PROVIDER_CONTEXT_NOT_FOUND _HRESULT_TYPEDEF_(0x80320006)
#define FWP_E_SUBLAYER_NOT_FOUND _HRESULT_TYPEDEF_(0x80320007)
#define FWP_E_NOT_FOUND _HRESULT_TYPEDEF_(0x80320008)
#define FWP_E_ALREADY_EXISTS _HRESULT_TYPEDEF_(0x80320009)
#define FWP_E_IN_USE _HRESULT_TYPEDEF_(0x8032000A)
#define FWP_E_DYNAMIC_SESSION_IN_PROGRESS _HRESULT_TYPEDEF_(0x8032000B)
#define FWP_E_WRONG_SESSION _HRESULT_TYPEDEF_(0x8032000C)
#define FWP_E_NO_TXN_IN_PROGRESS _HRESULT_TYPEDEF_(0x8032000D)
#define FWP_E_TXN_IN_PROGRESS _HRESULT_TYPEDEF_(0x8032000E)
#define FWP_E_TXN_ABORTED _HRESULT_TYPEDEF_(0x8032000F)
#define FWP_E_SESSION_ABORTED _HRESULT_TYPEDEF_(0x80320010)
#define FWP_E_INCOMPATIBLE_TXN _HRESULT_TYPEDEF_(0x80320011)
#define FWP_E_TIMEOUT _HRESULT_TYPEDEF_(0x80320012)
#define FWP_E_NET_EVENTS_DISABLED _HRESULT_TYPEDEF_(0x80320013)
#define FWP_E_INCOMPATIBLE_LAYER _HRESULT_TYPEDEF_(0x80320014)
#define FWP_E_KM_CLIENTS_ONLY _HRESULT_TYPEDEF_(0x80320015)
#define FWP_E_LIFETIME_MISMATCH _HRESULT_TYPEDEF_(0x80320016)
#define FWP_E_BUILTIN_OBJECT _HRESULT_TYPEDEF_(0x80320017)
#define FWP_E_TOO_MANY_CALLOUTS _HRESULT_TYPEDEF_(0x80320018)
#define FWP_E_NOTIFICATION_DROPPED _HRESULT_TYPEDEF_(0x80320019)
#define FWP_E_TRAFFIC_MISMATCH _HRESULT_TYPEDEF_(0x8032001A)
#define FWP_E_INCOMPATIBLE_SA_STATE _HRESULT_TYPEDEF_(0x8032001B)
#define FWP_E_NULL_POINTER _HRESULT_TYPEDEF_(0x8032001C)
#define FWP_E_INVALID_ENUMERATOR _HRESULT_TYPEDEF_(0x8032001D)
#define FWP_E_INVALID_FLAGS _HRESULT_TYPEDEF_(0x8032001E)
#define FWP_E_INVALID_NET_MASK _HRESULT_TYPEDEF_(0x8032001F)
#define FWP_E_INVALID_RANGE _HRESULT_TYPEDEF_(0x80320020)
#define FWP_E_INVALID_INTERVAL _HRESULT_TYPEDEF_(0x80320021)
#define FWP_E_ZERO_LENGTH_ARRAY _HRESULT_TYPEDEF_(0x80320022)
#define FWP_E_NULL_DISPLAY_NAME _HRESULT_TYPEDEF_(0x80320023)
#define FWP_E_INVALID_ACTION_TYPE _HRESULT_TYPEDEF_(0x80320024)
#define FWP_E_INVALID_WEIGHT _HRESULT_TYPEDEF_(0x80320025)
#define FWP_E_MATCH_TYPE_MISMATCH _HRESULT_TYPEDEF_(0x80320026)
#define FWP_E_TYPE_MISMATCH _HRESULT_TYPEDEF_(0x80320027)
#define FWP_E_OUT_OF_BOUNDS _HRESULT_TYPEDEF_(0x80320028)
#define FWP_E_RESERVED _HRESULT_TYPEDEF_(0x80320029)
#define FWP_E_DUPLICATE_CONDITION _HRESULT_TYPEDEF_(0x8032002A)
#define FWP_E_DUPLICATE_KEYMOD _HRESULT_TYPEDEF_(0x8032002B)
#define FWP_E_ACTION_INCOMPATIBLE_WITH_LAYER _HRESULT_TYPEDEF_(0x8032002C)
#define FWP_E_ACTION_INCOMPATIBLE_WITH_SUBLAYER _HRESULT_TYPEDEF_(0x8032002D)
#define FWP_E_CONTEXT_INCOMPATIBLE_WITH_LAYER _HRESULT_TYPEDEF_(0x8032002E)
#define FWP_E_CONTEXT_INCOMPATIBLE_WITH_CALLOUT _HRESULT_TYPEDEF_(0x8032002F)
#define FWP_E_INCOMPATIBLE_AUTH_METHOD _HRESULT_TYPEDEF_(0x80320030)
#define FWP_E_INCOMPATIBLE_DH_GROUP _HRESULT_TYPEDEF_(0x80320031)
#define FWP_E_EM_NOT_SUPPORTED _HRESULT_TYPEDEF_(0x80320032)
#define FWP_E_NEVER_MATCH _HRESULT_TYPEDEF_(0x80320033)
#define FWP_E_PROVIDER_CONTEXT_MISMATCH _HRESULT_TYPEDEF_(0x80320034)
#define FWP_E_INVALID_PARAMETER _HRESULT_TYPEDEF_(0x80320035)
#define FWP_E_TOO_MANY_SUBLAYERS _HRESULT_TYPEDEF_(0x80320036)
#define FWP_E_CALLOUT_NOTIFICATION_FAILED _HRESULT_TYPEDEF_(0x80320037)
#define FWP_E_INVALID_AUTH_TRANSFORM _HRESULT_TYPEDEF_(0x80320038)
#define FWP_E_INVALID_CIPHER_TRANSFORM _HRESULT_TYPEDEF_(0x80320039)
#define NAP_E_INVALID_PACKET _HRESULT_TYPEDEF_(0x80270001)
#define NAP_E_MISSING_SOH _HRESULT_TYPEDEF_(0x80270002)
#define NAP_E_CONFLICTING_ID _HRESULT_TYPEDEF_(0x80270003)
#define NAP_E_NO_CACHED_SOH _HRESULT_TYPEDEF_(0x80270004)
#define NAP_E_STILL_BOUND _HRESULT_TYPEDEF_(0x80270005)
#define NAP_E_NOT_REGISTERED _HRESULT_TYPEDEF_(0x80270006)
#define NAP_E_NOT_INITIALIZED _HRESULT_TYPEDEF_(0x80270007)
#define NAP_E_MISMATCHED_ID _HRESULT_TYPEDEF_(0x80270008)
#define NAP_E_NOT_PENDING _HRESULT_TYPEDEF_(0x80270009)
#define NAP_E_ID_NOT_FOUND _HRESULT_TYPEDEF_(0x8027000A)
#define NAP_E_MAXSIZE_TOO_SMALL _HRESULT_TYPEDEF_(0x8027000B)
#define NAP_E_SERVICE_NOT_RUNNING _HRESULT_TYPEDEF_(0x8027000C)
#define NAP_S_CERT_ALREADY_PRESENT _HRESULT_TYPEDEF_(0x0027000D)
#define NAP_E_ENTITY_DISABLED _HRESULT_TYPEDEF_(0x8027000E)
#define NAP_E_NETSH_GROUPPOLICY_ERROR _HRESULT_TYPEDEF_(0x8027000F)
#define NAP_E_TOO_MANY_CALLS _HRESULT_TYPEDEF_(0x80270010)
#define NAP_E_SHV_CONFIG_EXISTED _HRESULT_TYPEDEF_(0x80270011)
#define NAP_E_SHV_CONFIG_NOT_FOUND _HRESULT_TYPEDEF_(0x80270012)
#define NAP_E_SHV_TIMEOUT _HRESULT_TYPEDEF_(0x80270013)


#define _FLT_WINERROR_

#define FILTER_HRESULT_FROM_FLT_NTSTATUS(x) (NT_ASSERT((x & 0xfff0000) == 0x001c0000),(HRESULT) (((x) & 0x8000ffff) | (FACILITY_USERMODE_FILTER_MANAGER << 16)))
#define FACILITY_USERMODE_FILTER_MANAGER 0x1f
#define ERROR_FLT_IO_COMPLETE ((HRESULT)0x001f0001)
#define ERROR_FLT_NO_HANDLER_DEFINED ((HRESULT)0x801f0001)
#define ERROR_FLT_CONTEXT_ALREADY_DEFINED ((HRESULT)0x801f0002)
#define ERROR_FLT_INVALID_ASYNCHRONOUS_REQUEST ((HRESULT)0x801f0003)
#define ERROR_FLT_DISALLOW_FAST_IO ((HRESULT)0x801f0004)
#define ERROR_FLT_INVALID_NAME_REQUEST ((HRESULT)0x801f0005)
#define ERROR_FLT_NOT_SAFE_TO_POST_OPERATION ((HRESULT)0x801f0006)
#define ERROR_FLT_NOT_INITIALIZED ((HRESULT)0x801f0007)
#define ERROR_FLT_FILTER_NOT_READY ((HRESULT)0x801f0008)
#define ERROR_FLT_POST_OPERATION_CLEANUP ((HRESULT)0x801f0009)
#define ERROR_FLT_INTERNAL_ERROR ((HRESULT)0x801f000a)
#define ERROR_FLT_DELETING_OBJECT ((HRESULT)0x801f000b)
#define ERROR_FLT_MUST_BE_NONPAGED_POOL ((HRESULT)0x801f000c)
#define ERROR_FLT_DUPLICATE_ENTRY ((HRESULT)0x801f000d)
#define ERROR_FLT_CBDQ_DISABLED ((HRESULT)0x801f000e)
#define ERROR_FLT_DO_NOT_ATTACH ((HRESULT)0x801f000f)
#define ERROR_FLT_DO_NOT_DETACH ((HRESULT)0x801f0010)
#define ERROR_FLT_INSTANCE_ALTITUDE_COLLISION ((HRESULT)0x801f0011)
#define ERROR_FLT_INSTANCE_NAME_COLLISION ((HRESULT)0x801f0012)
#define ERROR_FLT_FILTER_NOT_FOUND ((HRESULT)0x801f0013)
#define ERROR_FLT_VOLUME_NOT_FOUND ((HRESULT)0x801f0014)
#define ERROR_FLT_INSTANCE_NOT_FOUND ((HRESULT)0x801f0015)
#define ERROR_FLT_CONTEXT_ALLOCATION_NOT_FOUND ((HRESULT)0x801f0016)
#define ERROR_FLT_INVALID_CONTEXT_REGISTRATION ((HRESULT)0x801f0017)
#define ERROR_FLT_NAME_CACHE_MISS ((HRESULT)0x801f0018)
#define ERROR_FLT_NO_DEVICE_OBJECT ((HRESULT)0x801f0019)
#define ERROR_FLT_VOLUME_ALREADY_MOUNTED ((HRESULT)0x801f001a)
#define ERROR_FLT_ALREADY_ENLISTED ((HRESULT)0x801f001b)
#define ERROR_FLT_CONTEXT_ALREADY_LINKED ((HRESULT)0x801F001c)
#define ERROR_FLT_NO_WAITER_FOR_REPLY ((HRESULT)0x801f0020)
#define ERROR_FLT_REGISTRATION_BUSY ((HRESULT)0x801F0023)


#define SECTION_QUERY 0x0001
#define SECTION_MAP_WRITE 0x0002
#define SECTION_MAP_READ 0x0004
#define SECTION_MAP_EXECUTE 0x0008
#define SECTION_EXTEND_SIZE 0x0010
#define SECTION_MAP_EXECUTE_EXPLICIT 0x0020
#define SECTION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY| SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE)
#define SESSION_QUERY_ACCESS 0x1
#define SESSION_MODIFY_ACCESS 0x2
#define SESSION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SESSION_QUERY_ACCESS | SESSION_MODIFY_ACCESS)
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000
#define MEM_FREE 0x10000
#define MEM_PRIVATE 0x20000
#define MEM_MAPPED 0x40000
#define MEM_RESET 0x80000
#define MEM_TOP_DOWN 0x100000
#define MEM_WRITE_WATCH 0x200000
#define MEM_PHYSICAL 0x400000
#define MEM_ROTATE 0x800000
#define MEM_LARGE_PAGES 0x20000000
#define MEM_4MB_PAGES 0x80000000
#define SEC_FILE 0x800000
#define SEC_IMAGE 0x1000000
#define SEC_PROTECTED_IMAGE 0x2000000
#define SEC_RESERVE 0x4000000
#define SEC_COMMIT 0x8000000
#define SEC_NOCACHE 0x10000000
#define SEC_WRITECOMBINE 0x40000000
#define SEC_LARGE_PAGES 0x80000000
#define SEC_IMAGE_NO_EXECUTE (SEC_IMAGE | SEC_NOCACHE)
#define MEM_IMAGE SEC_IMAGE
#define WRITE_WATCH_FLAG_RESET 0x01
#define MEM_UNMAP_WITH_TRANSIENT_BOOST 0x01
#define FILE_READ_DATA (0x0001)
#define FILE_LIST_DIRECTORY (0x0001)
#define FILE_WRITE_DATA (0x0002)
#define FILE_ADD_FILE (0x0002)
#define FILE_APPEND_DATA (0x0004)
#define FILE_ADD_SUBDIRECTORY (0x0004)
#define FILE_CREATE_PIPE_INSTANCE (0x0004)
#define FILE_READ_EA (0x0008)
#define FILE_WRITE_EA (0x0010)
#define FILE_EXECUTE (0x0020)
#define FILE_TRAVERSE (0x0020)
#define FILE_DELETE_CHILD (0x0040)
#define FILE_READ_ATTRIBUTES (0x0080)
#define FILE_WRITE_ATTRIBUTES (0x0100)
#define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
#define FILE_GENERIC_READ (STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE)
#define FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE)
#define FILE_SUPERSEDE 0x00000000
#define FILE_OPEN 0x00000001
#define FILE_CREATE 0x00000002
#define FILE_OPEN_IF 0x00000003
#define FILE_OVERWRITE 0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_MAXIMUM_DISPOSITION 0x00000005
#define FILE_DIRECTORY_FILE 0x00000001
#define FILE_WRITE_THROUGH 0x00000002
#define FILE_SEQUENTIAL_ONLY 0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT 0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_NON_DIRECTORY_FILE 0x00000040
#define FILE_CREATE_TREE_CONNECTION 0x00000080
#define FILE_COMPLETE_IF_OPLOCKED 0x00000100
#define FILE_NO_EA_KNOWLEDGE 0x00000200
#define FILE_OPEN_REMOTE_INSTANCE 0x00000400
#define FILE_RANDOM_ACCESS 0x00000800
#define FILE_DELETE_ON_CLOSE 0x00001000
#define FILE_OPEN_BY_FILE_ID 0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_NO_COMPRESSION 0x00008000

#define FILE_OPEN_REQUIRING_OPLOCK 0x00010000
#define FILE_DISALLOW_EXCLUSIVE 0x00020000

#define FILE_RESERVE_OPFILTER 0x00100000
#define FILE_OPEN_REPARSE_POINT 0x00200000
#define FILE_OPEN_NO_RECALL 0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY 0x00800000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define FILE_SHARE_VALID_FLAGS 0x00000007
#define FILE_ATTRIBUTE_READONLY 0x00000001
#define FILE_ATTRIBUTE_HIDDEN 0x00000002
#define FILE_ATTRIBUTE_SYSTEM 0x00000004
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010
#define FILE_ATTRIBUTE_ARCHIVE 0x00000020
#define FILE_ATTRIBUTE_DEVICE 0x00000040
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_ATTRIBUTE_TEMPORARY 0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE 0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT 0x00000400
#define FILE_ATTRIBUTE_COMPRESSED 0x00000800
#define FILE_ATTRIBUTE_OFFLINE 0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED 0x00004000
#define FILE_ATTRIBUTE_VIRTUAL 0x00010000
#define FILE_NOTIFY_CHANGE_FILE_NAME 0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME 0x00000002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES 0x00000004
#define FILE_NOTIFY_CHANGE_SIZE 0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE 0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS 0x00000020
#define FILE_NOTIFY_CHANGE_CREATION 0x00000040
#define FILE_NOTIFY_CHANGE_SECURITY 0x00000100
#define FILE_ACTION_ADDED 0x00000001
#define FILE_ACTION_REMOVED 0x00000002
#define FILE_ACTION_MODIFIED 0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME 0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME 0x00000005
#define MAILSLOT_NO_MESSAGE ((DWORD)-1)
#define MAILSLOT_WAIT_FOREVER ((DWORD)-1)
#define FILE_CASE_SENSITIVE_SEARCH 0x00000001
#define FILE_CASE_PRESERVED_NAMES 0x00000002
#define FILE_UNICODE_ON_DISK 0x00000004
#define FILE_PERSISTENT_ACLS 0x00000008
#define FILE_FILE_COMPRESSION 0x00000010
#define FILE_VOLUME_QUOTAS 0x00000020
#define FILE_SUPPORTS_SPARSE_FILES 0x00000040
#define FILE_SUPPORTS_REPARSE_POINTS 0x00000080
#define FILE_SUPPORTS_REMOTE_STORAGE 0x00000100
#define FILE_VOLUME_IS_COMPRESSED 0x00008000
#define FILE_SUPPORTS_OBJECT_IDS 0x00010000
#define FILE_SUPPORTS_ENCRYPTION 0x00020000
#define FILE_NAMED_STREAMS 0x00040000
#define FILE_READ_ONLY_VOLUME 0x00080000
#define FILE_SEQUENTIAL_WRITE_ONCE 0x00100000
#define FILE_SUPPORTS_TRANSACTIONS 0x00200000
#define FILE_SUPPORTS_HARD_LINKS 0x00400000
#define FILE_SUPPORTS_EXTENDED_ATTRIBUTES 0x00800000
#define FILE_SUPPORTS_OPEN_BY_FILE_ID 0x01000000
#define FILE_SUPPORTS_USN_JOURNAL 0x02000000
#define FILE_SUPPORTS_INTEGRITY_STREAMS 0x04000000

typedef struct _MEMORY_BASIC_INFORMATION32
{
DWORD BaseAddress;
DWORD AllocationBase;
DWORD AllocationProtect;
DWORD RegionSize;
DWORD State;
DWORD Protect;
DWORD Type;
}
MEMORY_BASIC_INFORMATION32,*PMEMORY_BASIC_INFORMATION32;

typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64
{
ULONGLONG BaseAddress;
ULONGLONG AllocationBase;
DWORD AllocationProtect;
DWORD __alignment1;
ULONGLONG RegionSize;
DWORD State;
DWORD Protect;
DWORD Type;
DWORD __alignment2;
}

MEMORY_BASIC_INFORMATION64,*PMEMORY_BASIC_INFORMATION64;
typedef struct _MEMORY_BASIC_INFORMATION
{
PVOID BaseAddress;
PVOID AllocationBase;
DWORD AllocationProtect;
SIZE_T RegionSize;
DWORD State;
DWORD Protect;
DWORD Type;
}
MEMORY_BASIC_INFORMATION,*PMEMORY_BASIC_INFORMATION;


SIZE_T WINAPI VirtualQuery (LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
VOID WINAPI GetSystemInfo (LPSYSTEM_INFO lpSystemInfo);
WINBASEAPI WINBOOL WINAPI UnmapViewOfFile (LPCVOID lpBaseAddress);
WINBASEAPI LPVOID WINAPI VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI WINBOOL WINAPI VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI WINBOOL WINAPI VirtualProtect (LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

WINBASEAPI DWORD WINAPI GetLastError (VOID);
WINBASEAPI VOID WINAPI SetLastError (DWORD dwErrCode);


#define WINAPI_FAMILY_PARTITION(v) ((WINAPI_FAMILY & v) == v)
#define WINAPI_FAMILY_ONE_PARTITION(vset, v) ((WINAPI_FAMILY & vset) == v)

#ifdef __WIDL__
typedef struct
{
unsigned long Data1;
unsigned short Data2;
unsigned short Data3;
byte Data4[8];
}
GUID;
#else
typedef struct _GUID
{
unsigned __LONG32 Data1;
unsigned short Data2;
unsigned short Data3;
unsigned char Data4[8];
}
GUID;
#endif

#ifndef BASETYPES
#define BASETYPES
typedef unsigned __LONG32 ULONG;
typedef ULONG *PULONG;
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
typedef unsigned char UCHAR;
typedef UCHAR *PUCHAR;
typedef char *PSZ;
#endif


#define WM_NULL 0x0000
#define WM_CREATE 0x0001
#define WM_DESTROY 0x0002
#define WM_MOVE 0x0003
#define WM_SIZE 0x0005
#define WM_ACTIVATE 0x0006
#define WA_INACTIVE 0
#define WA_ACTIVE 1
#define WA_CLICKACTIVE 2
#define WM_SETFOCUS 0x0007
#define WM_KILLFOCUS 0x0008
#define WM_ENABLE 0x000A
#define WM_SETREDRAW 0x000B
#define WM_SETTEXT 0x000C
#define WM_GETTEXT 0x000D
#define WM_GETTEXTLENGTH 0x000E
#define WM_PAINT 0x000F
#define WM_CLOSE 0x0010
#define WM_QUERYENDSESSION 0x0011
#define WM_QUERYOPEN 0x0013
#define WM_ENDSESSION 0x0016
#define WM_QUIT 0x0012
#define WM_ERASEBKGND 0x0014
#define WM_SYSCOLORCHANGE 0x0015
#define WM_SHOWWINDOW 0x0018
#define WM_WININICHANGE 0x001A
#define WM_SETTINGCHANGE WM_WININICHANGE
#define WM_DEVMODECHANGE 0x001B
#define WM_ACTIVATEAPP 0x001C
#define WM_FONTCHANGE 0x001D
#define WM_TIMECHANGE 0x001E
#define WM_CANCELMODE 0x001F
#define WM_SETCURSOR 0x0020
#define WM_MOUSEACTIVATE 0x0021
#define WM_CHILDACTIVATE 0x0022
#define WM_QUEUESYNC 0x0023
#define WM_GETMINMAXINFO 0x0024
typedef struct tagMINMAXINFO
{
POINT ptReserved;
POINT ptMaxSize;
POINT ptMaxPosition;
POINT ptMinTrackSize;
POINT ptMaxTrackSize;
}
MINMAXINFO,*PMINMAXINFO,*LPMINMAXINFO;
#define WM_PAINTICON 0x0026
#define WM_ICONERASEBKGND 0x0027
#define WM_NEXTDLGCTL 0x0028
#define WM_SPOOLERSTATUS 0x002A
#define WM_DRAWITEM 0x002B
#define WM_MEASUREITEM 0x002C
#define WM_DELETEITEM 0x002D
#define WM_VKEYTOITEM 0x002E
#define WM_CHARTOITEM 0x002F
#define WM_SETFONT 0x0030
#define WM_GETFONT 0x0031
#define WM_SETHOTKEY 0x0032
#define WM_GETHOTKEY 0x0033
#define WM_QUERYDRAGICON 0x0037
#define WM_COMPAREITEM 0x0039
#define WM_GETOBJECT 0x003D
#define WM_COMPACTING 0x0041
#define WM_COMMNOTIFY 0x0044
#define WM_WINDOWPOSCHANGING 0x0046
#define WM_WINDOWPOSCHANGED 0x0047
#define WM_POWER 0x0048
#define PWR_OK 1
#define PWR_FAIL (-1)
#define PWR_SUSPENDREQUEST 1
#define PWR_SUSPENDRESUME 2
#define PWR_CRITICALRESUME 3
#define WM_COPYDATA 0x004A
#define WM_CANCELJOURNAL 0x004B

typedef struct tagCOPYDATASTRUCT
{
ULONG_PTR dwData;
DWORD cbData;
PVOID lpData;
}
COPYDATASTRUCT,*PCOPYDATASTRUCT;
typedef struct tagMDINEXTMENU
{
HMENU hmenuIn;
HMENU hmenuNext;
HWND hwndNext;
}
MDINEXTMENU,*PMDINEXTMENU,*LPMDINEXTMENU;

#define WM_NOTIFY 0x004E
#define WM_INPUTLANGCHANGEREQUEST 0x0050
#define WM_INPUTLANGCHANGE 0x0051
#define WM_TCARD 0x0052
#define WM_HELP 0x0053
#define WM_USERCHANGED 0x0054
#define WM_NOTIFYFORMAT 0x0055
#define NFR_ANSI 1
#define NFR_UNICODE 2
#define NF_QUERY 3
#define NF_REQUERY 4
#define WM_CONTEXTMENU 0x007B
#define WM_STYLECHANGING 0x007C
#define WM_STYLECHANGED 0x007D
#define WM_DISPLAYCHANGE 0x007E
#define WM_GETICON 0x007F
#define WM_SETICON 0x0080
#define WM_NCCREATE 0x0081
#define WM_NCDESTROY 0x0082
#define WM_NCCALCSIZE 0x0083
#define WM_NCHITTEST 0x0084
#define WM_NCPAINT 0x0085
#define WM_NCACTIVATE 0x0086
#define WM_GETDLGCODE 0x0087
#define WM_SYNCPAINT 0x0088
#define WM_NCMOUSEMOVE 0x00A0
#define WM_NCLBUTTONDOWN 0x00A1
#define WM_NCLBUTTONUP 0x00A2
#define WM_NCLBUTTONDBLCLK 0x00A3
#define WM_NCRBUTTONDOWN 0x00A4
#define WM_NCRBUTTONUP 0x00A5
#define WM_NCRBUTTONDBLCLK 0x00A6
#define WM_NCMBUTTONDOWN 0x00A7
#define WM_NCMBUTTONUP 0x00A8
#define WM_NCMBUTTONDBLCLK 0x00A9
#define WM_NCXBUTTONDOWN 0x00AB
#define WM_NCXBUTTONUP 0x00AC
#define WM_NCXBUTTONDBLCLK 0x00AD
#define WM_INPUT_DEVICE_CHANGE 0x00fe
#define WM_INPUT 0x00FF
#define WM_KEYFIRST 0x0100
#define WM_KEYDOWN 0x0100
#define WM_KEYUP 0x0101
#define WM_CHAR 0x0102
#define WM_DEADCHAR 0x0103
#define WM_SYSKEYDOWN 0x0104
#define WM_SYSKEYUP 0x0105
#define WM_SYSCHAR 0x0106
#define WM_SYSDEADCHAR 0x0107
#define WM_UNICHAR 0x0109
#define WM_KEYLAST 0x0109
#define UNICODE_NOCHAR 0xFFFF
#define WM_IME_STARTCOMPOSITION 0x010D
#define WM_IME_ENDCOMPOSITION 0x010E
#define WM_IME_COMPOSITION 0x010F
#define WM_IME_KEYLAST 0x010F
#define WM_INITDIALOG 0x0110
#define WM_COMMAND 0x0111
#define WM_SYSCOMMAND 0x0112
#define WM_TIMER 0x0113
#define WM_HSCROLL 0x0114
#define WM_VSCROLL 0x0115
#define WM_INITMENU 0x0116
#define WM_INITMENUPOPUP 0x0117
#define WM_MENUSELECT 0x011F
#define WM_GESTURE 0x0119
#define WM_GESTURENOTIFY 0x011A
#define WM_MENUCHAR 0x0120
#define WM_ENTERIDLE 0x0121
#define WM_MENURBUTTONUP 0x0122
#define WM_MENUDRAG 0x0123
#define WM_MENUGETOBJECT 0x0124
#define WM_UNINITMENUPOPUP 0x0125
#define WM_MENUCOMMAND 0x0126
#define WM_CHANGEUISTATE 0x0127
#define WM_UPDATEUISTATE 0x0128
#define WM_QUERYUISTATE 0x0129
#define UIS_SET 1
#define UIS_CLEAR 2
#define UIS_INITIALIZE 3
#define UISF_HIDEFOCUS 0x1
#define UISF_HIDEACCEL 0x2
#define UISF_ACTIVE 0x4
#define WM_CTLCOLORMSGBOX 0x0132
#define WM_CTLCOLOREDIT 0x0133
#define WM_CTLCOLORLISTBOX 0x0134
#define WM_CTLCOLORBTN 0x0135
#define WM_CTLCOLORDLG 0x0136
#define WM_CTLCOLORSCROLLBAR 0x0137
#define WM_CTLCOLORSTATIC 0x0138
#define MN_GETHMENU 0x01E1
#define WM_MOUSEFIRST 0x0200
#define WM_MOUSEMOVE 0x0200
#define WM_LBUTTONDOWN 0x0201
#define WM_LBUTTONUP 0x0202
#define WM_LBUTTONDBLCLK 0x0203
#define WM_RBUTTONDOWN 0x0204
#define WM_RBUTTONUP 0x0205
#define WM_RBUTTONDBLCLK 0x0206
#define WM_MBUTTONDOWN 0x0207
#define WM_MBUTTONUP 0x0208
#define WM_MBUTTONDBLCLK 0x0209
#define WM_MOUSEWHEEL 0x020A
#define WM_XBUTTONDOWN 0x020B
#define WM_XBUTTONUP 0x020C
#define WM_XBUTTONDBLCLK 0x020D
#define WM_MOUSEHWHEEL 0x020e
#if _WIN32_WINNT >= 0x0600
#define WM_MOUSELAST 0x020e
#else
#define WM_MOUSELAST 0x020d
#endif
#define WHEEL_DELTA 120
#define GET_WHEEL_DELTA_WPARAM(wParam) ((short)HIWORD(wParam))
#define WHEEL_PAGESCROLL (UINT_MAX)
#define GET_KEYSTATE_WPARAM(wParam) (LOWORD(wParam))
#define GET_NCHITTEST_WPARAM(wParam) ((short)LOWORD(wParam))
#define GET_XBUTTON_WPARAM(wParam) (HIWORD(wParam))
#define XBUTTON1 0x0001
#define XBUTTON2 0x0002
#define WM_PARENTNOTIFY 0x0210
#define WM_ENTERMENULOOP 0x0211
#define WM_EXITMENULOOP 0x0212
#define WM_NEXTMENU 0x0213
#define WM_SIZING 0x0214
#define WM_CAPTURECHANGED 0x0215
#define WM_MOVING 0x0216
#define WM_POWERBROADCAST 0x0218

#define PBT_APMQUERYSUSPEND 0x0000
#define PBT_APMQUERYSTANDBY 0x0001
#define PBT_APMQUERYSUSPENDFAILED 0x0002
#define PBT_APMQUERYSTANDBYFAILED 0x0003
#define PBT_APMSUSPEND 0x0004
#define PBT_APMSTANDBY 0x0005
#define PBT_APMRESUMECRITICAL 0x0006
#define PBT_APMRESUMESUSPEND 0x0007
#define PBT_APMRESUMESTANDBY 0x0008
#define PBTF_APMRESUMEFROMFAILURE 0x00000001
#define PBT_APMBATTERYLOW 0x0009
#define PBT_APMPOWERSTATUSCHANGE 0x000A
#define PBT_APMOEMEVENT 0x000B
#define PBT_APMRESUMEAUTOMATIC 0x0012

#define PBT_POWERSETTINGCHANGE 32787

typedef struct
{
GUID PowerSetting;
DWORD DataLength;
UCHAR Data[1];
}
POWERBROADCAST_SETTING,*PPOWERBROADCAST_SETTING;

#define WM_DEVICECHANGE 0x0219
#define WM_MDICREATE 0x0220
#define WM_MDIDESTROY 0x0221
#define WM_MDIACTIVATE 0x0222
#define WM_MDIRESTORE 0x0223
#define WM_MDINEXT 0x0224
#define WM_MDIMAXIMIZE 0x0225
#define WM_MDITILE 0x0226
#define WM_MDICASCADE 0x0227
#define WM_MDIICONARRANGE 0x0228
#define WM_MDIGETACTIVE 0x0229
#define WM_MDISETMENU 0x0230
#define WM_ENTERSIZEMOVE 0x0231
#define WM_EXITSIZEMOVE 0x0232
#define WM_DROPFILES 0x0233
#define WM_MDIREFRESHMENU 0x0234
#if WINVER >= 0x0602
#define WM_POINTERDEVICECHANGE 0x238
#define WM_POINTERDEVICEINRANGE 0x239
#define WM_POINTERDEVICEOUTOFRANGE 0x23a
#endif
#if WINVER >= 0x0601
#define WM_TOUCH 0x0240
#endif
#if WINVER >= 0x0602
#define WM_NCPOINTERUPDATE 0x0241
#define WM_NCPOINTERDOWN 0x0242
#define WM_NCPOINTERUP 0x0243
#define WM_POINTERUPDATE 0x0245
#define WM_POINTERDOWN 0x0246
#define WM_POINTERUP 0x0247
#define WM_POINTERENTER 0x0249
#define WM_POINTERLEAVE 0x024a
#define WM_POINTERACTIVATE 0x024b
#define WM_POINTERCAPTURECHANGED 0x024c
#define WM_TOUCHHITTESTING 0x024d
#define WM_POINTERWHEEL 0x024e
#define WM_POINTERHWHEEL 0x024f
#endif
#define WM_IME_SETCONTEXT 0x0281
#define WM_IME_NOTIFY 0x0282
#define WM_IME_CONTROL 0x0283
#define WM_IME_COMPOSITIONFULL 0x0284
#define WM_IME_SELECT 0x0285
#define WM_IME_CHAR 0x0286
#define WM_IME_REQUEST 0x0288
#define WM_IME_KEYDOWN 0x0290
#define WM_IME_KEYUP 0x0291
#define WM_MOUSEHOVER 0x02A1
#define WM_MOUSELEAVE 0x02A3
#define WM_NCMOUSEHOVER 0x02A0
#define WM_NCMOUSELEAVE 0x02A2
#define WM_WTSSESSION_CHANGE 0x02B1
#define WM_TABLET_FIRST 0x02c0
#define WM_TABLET_LAST 0x02df
#define WM_CUT 0x0300
#define WM_COPY 0x0301
#define WM_PASTE 0x0302
#define WM_CLEAR 0x0303
#define WM_UNDO 0x0304
#define WM_RENDERFORMAT 0x0305
#define WM_RENDERALLFORMATS 0x0306
#define WM_DESTROYCLIPBOARD 0x0307
#define WM_DRAWCLIPBOARD 0x0308
#define WM_PAINTCLIPBOARD 0x0309
#define WM_VSCROLLCLIPBOARD 0x030A
#define WM_SIZECLIPBOARD 0x030B
#define WM_ASKCBFORMATNAME 0x030C
#define WM_CHANGECBCHAIN 0x030D
#define WM_HSCROLLCLIPBOARD 0x030E
#define WM_QUERYNEWPALETTE 0x030F
#define WM_PALETTEISCHANGING 0x0310
#define WM_PALETTECHANGED 0x0311
#define WM_HOTKEY 0x0312
#define WM_PRINT 0x0317
#define WM_PRINTCLIENT 0x0318
#define WM_APPCOMMAND 0x0319
#define WM_THEMECHANGED 0x031A
#define WM_CLIPBOARDUPDATE 0x031d
#if _WIN32_WINNT >= 0x0600
#define WM_DWMCOMPOSITIONCHANGED 0x031e
#define WM_DWMNCRENDERINGCHANGED 0x031f
#define WM_DWMCOLORIZATIONCOLORCHANGED 0x0320
#define WM_DWMWINDOWMAXIMIZEDCHANGE 0x0321
#endif
#if _WIN32_WINNT >= 0x0601
#define WM_DWMSENDICONICTHUMBNAIL 0x0323
#define WM_DWMSENDICONICLIVEPREVIEWBITMAP 0x0326
#endif
#if WINVER >= 0x0600
#define WM_GETTITLEBARINFOEX 0x033f
#endif
#define WM_HANDHELDFIRST 0x0358
#define WM_HANDHELDLAST 0x035F
#define WM_AFXFIRST 0x0360
#define WM_AFXLAST 0x037F
#define WM_PENWINFIRST 0x0380
#define WM_PENWINLAST 0x038F
#define WM_APP 0x8000
#define WM_USER 0x0400
#define WMSZ_LEFT 1
#define WMSZ_RIGHT 2
#define WMSZ_TOP 3
#define WMSZ_TOPLEFT 4
#define WMSZ_TOPRIGHT 5
#define WMSZ_BOTTOM 6
#define WMSZ_BOTTOMLEFT 7
#define WMSZ_BOTTOMRIGHT 8

#define HTERROR (-2)
#define HTTRANSPARENT (-1)
#define HTNOWHERE 0
#define HTCLIENT 1
#define HTCAPTION 2
#define HTSYSMENU 3
#define HTGROWBOX 4
#define HTSIZE HTGROWBOX
#define HTMENU 5
#define HTHSCROLL 6
#define HTVSCROLL 7
#define HTMINBUTTON 8
#define HTMAXBUTTON 9
#define HTLEFT 10
#define HTRIGHT 11
#define HTTOP 12
#define HTTOPLEFT 13
#define HTTOPRIGHT 14
#define HTBOTTOM 15
#define HTBOTTOMLEFT 16
#define HTBOTTOMRIGHT 17
#define HTBORDER 18
#define HTREDUCE HTMINBUTTON
#define HTZOOM HTMAXBUTTON
#define HTSIZEFIRST HTLEFT
#define HTSIZELAST HTBOTTOMRIGHT
#define HTOBJECT 19
#define HTCLOSE 20
#define HTHELP 21
#define SMTO_NORMAL 0x0000
#define SMTO_BLOCK 0x0001
#define SMTO_ABORTIFHUNG 0x0002
#define SMTO_NOTIMEOUTIFNOTHUNG 0x0008
#if WINVER >= 0x0600
#define SMTO_ERRORONEXIT 0x0020
#endif
#define MA_ACTIVATE 1
#define MA_ACTIVATEANDEAT 2
#define MA_NOACTIVATE 3
#define MA_NOACTIVATEANDEAT 4
#define ICON_SMALL 0
#define ICON_BIG 1
#define ICON_SMALL2 2
#if WINAPI_FAMILY_PARTITION (WINAPI_PARTITION_DESKTOP)
#define RegisterWindowMessage __MINGW_NAME_AW(RegisterWindowMessage)
WINUSERAPI UINT WINAPI RegisterWindowMessageA(LPCSTR lpString);
WINUSERAPI UINT WINAPI RegisterWindowMessageW(LPCWSTR lpString);
#endif
#define SIZE_RESTORED 0
#define SIZE_MINIMIZED 1
#define SIZE_MAXIMIZED 2
#define SIZE_MAXSHOW 3
#define SIZE_MAXHIDE 4
#define SIZENORMAL SIZE_RESTORED
#define SIZEICONIC SIZE_MINIMIZED
#define SIZEFULLSCREEN SIZE_MAXIMIZED
#define SIZEZOOMSHOW SIZE_MAXSHOW
#define SIZEZOOMHIDE SIZE_MAXHIDE
#if WINAPI_FAMILY_PARTITION (WINAPI_PARTITION_DESKTOP)
typedef struct tagWINDOWPOS
{
HWND hwnd;
HWND hwndInsertAfter;
int x;
int y;
int cx;
int cy;
UINT flags;
}
WINDOWPOS,*LPWINDOWPOS,*PWINDOWPOS;
typedef struct tagNCCALCSIZE_PARAMS
{
RECT rgrc[3];
PWINDOWPOS lppos;
}
NCCALCSIZE_PARAMS,*LPNCCALCSIZE_PARAMS;
#endif
#define WVR_ALIGNTOP 0x0010
#define WVR_ALIGNLEFT 0x0020
#define WVR_ALIGNBOTTOM 0x0040
#define WVR_ALIGNRIGHT 0x0080
#define WVR_HREDRAW 0x0100
#define WVR_VREDRAW 0x0200
#define WVR_REDRAW (WVR_HREDRAW | WVR_VREDRAW)
#define WVR_VALIDRECTS 0x0400
#ifndef NOKEYSTATES
#define MK_LBUTTON 0x0001
#define MK_RBUTTON 0x0002
#define MK_SHIFT 0x0004
#define MK_CONTROL 0x0008
#define MK_MBUTTON 0x0010
#define MK_XBUTTON1 0x0020
#define MK_XBUTTON2 0x0040
#endif
#ifndef NOTRACKMOUSEEVENT
#define TME_HOVER 0x00000001
#define TME_LEAVE 0x00000002
#define TME_NONCLIENT 0x00000010
#define TME_QUERY 0x40000000
#define TME_CANCEL 0x80000000
#define HOVER_DEFAULT 0xFFFFFFFF
#endif

#ifndef NOSYSCOMMANDS
#define SC_SIZE 0xF000
#define SC_MOVE 0xF010
#define SC_MINIMIZE 0xF020
#define SC_MAXIMIZE 0xF030
#define SC_NEXTWINDOW 0xF040
#define SC_PREVWINDOW 0xF050
#define SC_CLOSE 0xF060
#define SC_VSCROLL 0xF070
#define SC_HSCROLL 0xF080
#define SC_MOUSEMENU 0xF090
#define SC_KEYMENU 0xF100
#define SC_ARRANGE 0xF110
#define SC_RESTORE 0xF120
#define SC_TASKLIST 0xF130
#define SC_SCREENSAVE 0xF140
#define SC_HOTKEY 0xF150
#define SC_DEFAULT 0xF160
#define SC_MONITORPOWER 0xF170
#define SC_CONTEXTHELP 0xF180
#define SC_SEPARATOR 0xF00F
#if WINVER >= 0x0600
#define SCF_ISSECURE 0x00000001
#endif
#define GET_SC_WPARAM(wParam) ((int)wParam &0xfff0)
#define SC_ICON SC_MINIMIZE
#define SC_ZOOM SC_MAXIMIZE
#endif

typedef WORD ATOM;
typedef int HFILE;
DECLARE_HANDLE (HINSTANCE);
DECLARE_HANDLE (HKEY);
typedef HKEY *PHKEY;
DECLARE_HANDLE (HKL);
DECLARE_HANDLE (HLSURF);
DECLARE_HANDLE (HMETAFILE);
typedef HINSTANCE HMODULE;
DECLARE_HANDLE (HRGN);
DECLARE_HANDLE (HRSRC);
DECLARE_HANDLE (HSPRITE);
DECLARE_HANDLE (HSTR);
DECLARE_HANDLE (HTASK);
DECLARE_HANDLE (HWINSTA);

WINUSERAPI HDC WINAPI GetWindowDC(HWND hWnd);
WINUSERAPI int WINAPI ReleaseDC(HWND hWnd,HDC hDC);
WINUSERAPI HDC WINAPI BeginPaint(HWND hWnd,LPPAINTSTRUCT lpPaint);
WINUSERAPI WINBOOL WINAPI EndPaint(HWND hWnd,CONST PAINTSTRUCT *lpPaint);
WINUSERAPI WINBOOL WINAPI GetUpdateRect(HWND hWnd,LPRECT lpRect,WINBOOL bErase);
WINUSERAPI int WINAPI GetUpdateRgn(HWND hWnd,HRGN hRgn,WINBOOL bErase);
WINUSERAPI int WINAPI SetWindowRgn(HWND hWnd,HRGN hRgn,WINBOOL bRedraw);
WINUSERAPI int WINAPI GetWindowRgn(HWND hWnd,HRGN hRgn);
WINUSERAPI int WINAPI GetWindowRgnBox(HWND hWnd,LPRECT lprc);
WINUSERAPI int WINAPI ExcludeUpdateRgn(HDC hDC,HWND hWnd);
WINUSERAPI WINBOOL WINAPI InvalidateRect(HWND hWnd,CONST RECT *lpRect,WINBOOL bErase);
WINUSERAPI WINBOOL WINAPI ValidateRect(HWND hWnd,CONST RECT *lpRect);
WINUSERAPI WINBOOL WINAPI InvalidateRgn(HWND hWnd,HRGN hRgn,WINBOOL bErase);
WINUSERAPI WINBOOL WINAPI ValidateRgn(HWND hWnd,HRGN hRgn);
WINUSERAPI WINBOOL WINAPI RedrawWindow(HWND hWnd,CONST RECT *lprcUpdate,HRGN hrgnUpdate,UINT flags);

typedef PVOID HDEVNOTIFY;
typedef HDEVNOTIFY *PHDEVNOTIFY;
WINUSERAPI HDEVNOTIFY WINAPI RegisterDeviceNotificationA(HANDLE hRecipient,LPVOID NotificationFilter,DWORD Flags);
WINUSERAPI HDEVNOTIFY WINAPI RegisterDeviceNotificationW(HANDLE hRecipient,LPVOID NotificationFilter,DWORD Flags);
WINUSERAPI WINBOOL WINAPI UnregisterDeviceNotification(HDEVNOTIFY Handle);

WINBASEAPI DWORD WINAPI TlsAlloc (VOID);
WINBASEAPI LPVOID WINAPI TlsGetValue (DWORD dwTlsIndex);
WINBASEAPI WINBOOL WINAPI TlsSetValue (DWORD dwTlsIndex, LPVOID lpTlsValue);
WINBASEAPI WINBOOL WINAPI TlsFree (DWORD dwTlsIndex);
WINBASEAPI HLOCAL WINAPI LocalAlloc (UINT uFlags, SIZE_T uBytes);
WINBASEAPI HLOCAL WINAPI LocalReAlloc (HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
WINBASEAPI LPVOID WINAPI LocalLock (HLOCAL hMem);
WINBASEAPI HLOCAL WINAPI LocalHandle (LPCVOID pMem);
WINBASEAPI WINBOOL WINAPI LocalUnlock (HLOCAL hMem);
WINBASEAPI SIZE_T WINAPI LocalSize (HLOCAL hMem);
WINBASEAPI UINT WINAPI LocalFlags (HLOCAL hMem);
WINBASEAPI HLOCAL WINAPI LocalFree (HLOCAL hMem);
WINBASEAPI SIZE_T WINAPI LocalShrink (HLOCAL hMem, UINT cbNewSize);
WINBASEAPI SIZE_T WINAPI LocalCompact (UINT uMinFree);

WINGDIAPI HBITMAP WINAPI CreateDIBSection(HDC hdc,CONST BITMAPINFO *lpbmi,UINT usage,VOID **ppvBits,HANDLE hSection,DWORD offset);

WINUSERAPI HWND WINAPI WindowFromDC(HDC hDC);
WINUSERAPI HDC WINAPI GetDC(HWND hWnd);
WINUSERAPI HDC WINAPI GetDCEx(HWND hWnd,HRGN hrgnClip,DWORD flags);
WINGDIAPI WINBOOL WINAPI DeleteDC(HDC hdc);
WINGDIAPI WINBOOL WINAPI DeleteMetaFile(HMETAFILE hmf);
WINGDIAPI WINBOOL WINAPI DeleteObject(HGDIOBJ ho);

WINBASEAPI DWORD WINAPI FormatMessageA (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
WINBASEAPI DWORD WINAPI FormatMessageW (DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPWSTR lpBuffer, DWORD nSize, va_list *Arguments);
#define FormatMessage __MINGW_NAME_AW(FormatMessage)
#define FORMAT_MESSAGE_IGNORE_INSERTS 0x00000200
#define FORMAT_MESSAGE_FROM_STRING 0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE 0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM 0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY 0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK 0x000000ff
#define FILE_ENCRYPTABLE 0
#define FILE_IS_ENCRYPTED 1
#define FILE_SYSTEM_ATTR 2
#define FILE_ROOT_DIR 3
#define FILE_SYSTEM_DIR 4
#define FILE_UNKNOWN 5
#define FILE_SYSTEM_NOT_SUPPORT 6
#define FILE_USER_DISALLOWED 7
#define FILE_READ_ONLY 8
#define FILE_DIR_DISALLOWED 9
#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define EFS_USE_RECOVERY_KEYS (0x1)
#define CREATE_FOR_IMPORT (1)
#define CREATE_FOR_DIR (2)
#define OVERWRITE_HIDDEN (4)
#define EFSRPC_SECURE_ONLY (8)

#define PROFILE_LINKED 'LINK'
#define PROFILE_EMBEDDED 'MBED'
#define BI_RGB __MSABI_LONG(0)
#define BI_RLE8 __MSABI_LONG(1)
#define BI_RLE4 __MSABI_LONG(2)
#define BI_BITFIELDS __MSABI_LONG(3)
#define BI_JPEG __MSABI_LONG(4)
#define BI_PNG __MSABI_LONG(5)

#define CreateWindowEx __MINGW_NAME_AW(CreateWindowEx)
#define CreateWindow __MINGW_NAME_AW(CreateWindow)
WINUSERAPI HWND WINAPI CreateWindowExA(DWORD dwExStyle,LPCSTR lpClassName,LPCSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam);
WINUSERAPI HWND WINAPI CreateWindowExW(DWORD dwExStyle,LPCWSTR lpClassName,LPCWSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam);
#define CreateWindowA(lpClassName,lpWindowName,dwStyle,x,y,nWidth,nHeight,hWndParent,hMenu,hInstance,lpParam) CreateWindowExA((DWORD)0,lpClassName,lpWindowName,dwStyle,x,y,nWidth,nHeight,hWndParent,hMenu,hInstance,lpParam)
#define CreateWindowW(lpClassName,lpWindowName,dwStyle,x,y,nWidth,nHeight,hWndParent,hMenu,hInstance,lpParam) CreateWindowExW((DWORD)0,lpClassName,lpWindowName,dwStyle,x,y,nWidth,nHeight,hWndParent,hMenu,hInstance,lpParam)
WINUSERAPI WINBOOL WINAPI IsWindow(HWND hWnd);
WINUSERAPI WINBOOL WINAPI IsMenu(HMENU hMenu);
WINUSERAPI WINBOOL WINAPI IsChild(HWND hWndParent,HWND hWnd);
WINUSERAPI WINBOOL WINAPI DestroyWindow(HWND hWnd);
WINUSERAPI WINBOOL WINAPI ShowWindow(HWND hWnd,int nCmdShow);
WINUSERAPI WINBOOL WINAPI AnimateWindow(HWND hWnd,DWORD dwTime,DWORD dwFlags);
WINUSERAPI WINBOOL WINAPI UpdateWindow(HWND hWnd);

WINUSERAPI WINBOOL WINAPI PostMessageA (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI WINBOOL WINAPI PostMessageW (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI WINBOOL WINAPI PostThreadMessageA (DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI WINBOOL WINAPI PostThreadMessageW (DWORD idThread, UINT Msg, WPARAM wParam, LPARAM lParam);
#define PostAppMessageA(idThread, wMsg, wParam, lParam) PostThreadMessageA ((DWORD)idThread, wMsg, wParam, lParam)
#define PostAppMessageW(idThread, wMsg, wParam, lParam) PostThreadMessageW ((DWORD)idThread, wMsg, wParam, lParam)
WINUSERAPI WINBOOL WINAPI AttachThreadInput (DWORD idAttach, DWORD idAttachTo, WINBOOL fAttach);
WINUSERAPI WINBOOL WINAPI ReplyMessage (LRESULT lResult);
WINUSERAPI WINBOOL WINAPI WaitMessage (VOID);
WINUSERAPI DWORD WINAPI WaitForInputIdle (HANDLE hProcess, DWORD dwMilliseconds);
WINUSERAPI LRESULT WINAPI DefWindowProcA (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI LRESULT WINAPI DefWindowProcW (HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI VOID WINAPI PostQuitMessage (int nExitCode);
WINUSERAPI WINBOOL WINAPI InSendMessage (VOID);
WINUSERAPI DWORD WINAPI InSendMessageEx (LPVOID lpReserved);
WINUSERAPI UINT WINAPI GetDoubleClickTime (VOID);
WINUSERAPI WINBOOL WINAPI SetDoubleClickTime (UINT);
WINUSERAPI ATOM WINAPI RegisterClassA (CONST WNDCLASSA *lpWndClass);
WINUSERAPI ATOM WINAPI RegisterClassW (CONST WNDCLASSW *lpWndClass);
WINUSERAPI WINBOOL WINAPI UnregisterClassA (LPCSTR lpClassName, HINSTANCE hInstance);
WINUSERAPI WINBOOL WINAPI UnregisterClassW (LPCWSTR lpClassName, HINSTANCE hInstance);
WINUSERAPI WINBOOL WINAPI GetClassInfoA (HINSTANCE hInstance, LPCSTR lpClassName, LPWNDCLASSA lpWndClass);
WINUSERAPI WINBOOL WINAPI GetClassInfoW (HINSTANCE hInstance, LPCWSTR lpClassName, LPWNDCLASSW lpWndClass);
WINUSERAPI ATOM WINAPI RegisterClassExA (CONST WNDCLASSEXA *);
WINUSERAPI ATOM WINAPI RegisterClassExW (CONST WNDCLASSEXW *);
WINUSERAPI WINBOOL WINAPI GetClassInfoExA (HINSTANCE hInstance, LPCSTR lpszClass, LPWNDCLASSEXA lpwcx);
WINUSERAPI WINBOOL WINAPI GetClassInfoExW (HINSTANCE hInstance, LPCWSTR lpszClass, LPWNDCLASSEXW lpwcx);
#ifdef STRICT
WINUSERAPI LRESULT WINAPI CallWindowProcA (WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI LRESULT WINAPI CallWindowProcW (WNDPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#else
WINUSERAPI LRESULT WINAPI CallWindowProcA (FARPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
WINUSERAPI LRESULT WINAPI CallWindowProcW (FARPROC lpPrevWndFunc, HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
#endif

#ifndef NOSHOWWINDOW
#define SW_HIDE 0
#define SW_SHOWNORMAL 1
#define SW_NORMAL 1
#define SW_SHOWMINIMIZED 2
#define SW_SHOWMAXIMIZED 3
#define SW_MAXIMIZE 3
#define SW_SHOWNOACTIVATE 4
#define SW_SHOW 5
#define SW_MINIMIZE 6
#define SW_SHOWMINNOACTIVE 7
#define SW_SHOWNA 8
#define SW_RESTORE 9
#define SW_SHOWDEFAULT 10
#define SW_FORCEMINIMIZE 11
#define SW_MAX 11
#define HIDE_WINDOW 0
#define SHOW_OPENWINDOW 1
#define SHOW_ICONWINDOW 2
#define SHOW_FULLSCREEN 3
#define SHOW_OPENNOACTIVATE 4
#define SW_PARENTCLOSING 1
#define SW_OTHERZOOM 2
#define SW_PARENTOPENING 3
#define SW_OTHERUNZOOM 4
#endif
#define AW_HOR_POSITIVE 0x00000001
#define AW_HOR_NEGATIVE 0x00000002
#define AW_VER_POSITIVE 0x00000004
#define AW_VER_NEGATIVE 0x00000008
#define AW_CENTER 0x00000010
#define AW_HIDE 0x00010000
#define AW_ACTIVATE 0x00020000
#define AW_SLIDE 0x00040000
#define AW_BLEND 0x00080000
#define KF_EXTENDED 0x0100
#define KF_DLGMODE 0x0800
#define KF_MENUMODE 0x1000
#define KF_ALTDOWN 0x2000
#define KF_REPEAT 0x4000
#define KF_UP 0x8000
#ifndef NOVIRTUALKEYCODES
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_CANCEL 0x03
#define VK_MBUTTON 0x04
#define VK_XBUTTON1 0x05
#define VK_XBUTTON2 0x06
#define VK_BACK 0x08
#define VK_TAB 0x09
#define VK_CLEAR 0x0C
#define VK_RETURN 0x0D
#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_PAUSE 0x13
#define VK_CAPITAL 0x14
#define VK_KANA 0x15
#define VK_HANGEUL 0x15
#define VK_HANGUL 0x15
#define VK_JUNJA 0x17
#define VK_FINAL 0x18
#define VK_HANJA 0x19
#define VK_KANJI 0x19
#define VK_ESCAPE 0x1B
#define VK_CONVERT 0x1C
#define VK_NONCONVERT 0x1D
#define VK_ACCEPT 0x1E
#define VK_MODECHANGE 0x1F
#define VK_SPACE 0x20
#define VK_PRIOR 0x21
#define VK_NEXT 0x22
#define VK_END 0x23
#define VK_HOME 0x24
#define VK_LEFT 0x25
#define VK_UP 0x26
#define VK_RIGHT 0x27
#define VK_DOWN 0x28
#define VK_SELECT 0x29
#define VK_PRINT 0x2A
#define VK_EXECUTE 0x2B
#define VK_SNAPSHOT 0x2C
#define VK_INSERT 0x2D
#define VK_DELETE 0x2E
#define VK_HELP 0x2F
#define VK_LWIN 0x5B
#define VK_RWIN 0x5C
#define VK_APPS 0x5D
#define VK_SLEEP 0x5F
#define VK_NUMPAD0 0x60
#define VK_NUMPAD1 0x61
#define VK_NUMPAD2 0x62
#define VK_NUMPAD3 0x63
#define VK_NUMPAD4 0x64
#define VK_NUMPAD5 0x65
#define VK_NUMPAD6 0x66
#define VK_NUMPAD7 0x67
#define VK_NUMPAD8 0x68
#define VK_NUMPAD9 0x69
#define VK_MULTIPLY 0x6A
#define VK_ADD 0x6B
#define VK_SEPARATOR 0x6C
#define VK_SUBTRACT 0x6D
#define VK_DECIMAL 0x6E
#define VK_DIVIDE 0x6F
#define VK_F1 0x70
#define VK_F2 0x71
#define VK_F3 0x72
#define VK_F4 0x73
#define VK_F5 0x74
#define VK_F6 0x75
#define VK_F7 0x76
#define VK_F8 0x77
#define VK_F9 0x78
#define VK_F10 0x79
#define VK_F11 0x7A
#define VK_F12 0x7B
#define VK_F13 0x7C
#define VK_F14 0x7D
#define VK_F15 0x7E
#define VK_F16 0x7F
#define VK_F17 0x80
#define VK_F18 0x81
#define VK_F19 0x82
#define VK_F20 0x83
#define VK_F21 0x84
#define VK_F22 0x85
#define VK_F23 0x86
#define VK_F24 0x87
#define VK_NUMLOCK 0x90
#define VK_SCROLL 0x91
#define VK_OEM_NEC_EQUAL 0x92
#define VK_OEM_FJ_JISHO 0x92
#define VK_OEM_FJ_MASSHOU 0x93
#define VK_OEM_FJ_TOUROKU 0x94
#define VK_OEM_FJ_LOYA 0x95
#define VK_OEM_FJ_ROYA 0x96
#define VK_LSHIFT 0xA0
#define VK_RSHIFT 0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_LMENU 0xA4
#define VK_RMENU 0xA5
#define VK_BROWSER_BACK 0xA6
#define VK_BROWSER_FORWARD 0xA7
#define VK_BROWSER_REFRESH 0xA8
#define VK_BROWSER_STOP 0xA9
#define VK_BROWSER_SEARCH 0xAA
#define VK_BROWSER_FAVORITES 0xAB
#define VK_BROWSER_HOME 0xAC
#define VK_VOLUME_MUTE 0xAD
#define VK_VOLUME_DOWN 0xAE
#define VK_VOLUME_UP 0xAF
#define VK_MEDIA_NEXT_TRACK 0xB0
#define VK_MEDIA_PREV_TRACK 0xB1
#define VK_MEDIA_STOP 0xB2
#define VK_MEDIA_PLAY_PAUSE 0xB3
#define VK_LAUNCH_MAIL 0xB4
#define VK_LAUNCH_MEDIA_SELECT 0xB5
#define VK_LAUNCH_APP1 0xB6
#define VK_LAUNCH_APP2 0xB7
#define VK_OEM_1 0xBA
#define VK_OEM_PLUS 0xBB
#define VK_OEM_COMMA 0xBC
#define VK_OEM_MINUS 0xBD
#define VK_OEM_PERIOD 0xBE
#define VK_OEM_2 0xBF
#define VK_OEM_3 0xC0
#define VK_OEM_4 0xDB
#define VK_OEM_5 0xDC
#define VK_OEM_6 0xDD
#define VK_OEM_7 0xDE
#define VK_OEM_8 0xDF
#define VK_OEM_AX 0xE1
#define VK_OEM_102 0xE2
#define VK_ICO_HELP 0xE3
#define VK_ICO_00 0xE4
#define VK_PROCESSKEY 0xE5
#define VK_ICO_CLEAR 0xE6
#define VK_PACKET 0xE7
#define VK_OEM_RESET 0xE9
#define VK_OEM_JUMP 0xEA
#define VK_OEM_PA1 0xEB
#define VK_OEM_PA2 0xEC
#define VK_OEM_PA3 0xED
#define VK_OEM_WSCTRL 0xEE
#define VK_OEM_CUSEL 0xEF
#define VK_OEM_ATTN 0xF0
#define VK_OEM_FINISH 0xF1
#define VK_OEM_COPY 0xF2
#define VK_OEM_AUTO 0xF3
#define VK_OEM_ENLW 0xF4
#define VK_OEM_BACKTAB 0xF5
#define VK_ATTN 0xF6
#define VK_CRSEL 0xF7
#define VK_EXSEL 0xF8
#define VK_EREOF 0xF9
#define VK_PLAY 0xFA
#define VK_ZOOM 0xFB
#define VK_NONAME 0xFC
#define VK_PA1 0xFD
#define VK_OEM_CLEAR 0xFE
#endif
#define WH_MIN (-1)
#define WH_MSGFILTER (-1)
#define WH_JOURNALRECORD 0
#define WH_JOURNALPLAYBACK 1
#define WH_KEYBOARD 2
#define WH_GETMESSAGE 3
#define WH_CALLWNDPROC 4
#define WH_CBT 5
#define WH_SYSMSGFILTER 6
#define WH_MOUSE 7
#define WH_HARDWARE 8
#define WH_DEBUG 9
#define WH_SHELL 10
#define WH_FOREGROUNDIDLE 11
#define WH_CALLWNDPROCRET 12
#define WH_KEYBOARD_LL 13
#define WH_MOUSE_LL 14
#define WH_MAX 14
#define WH_MINHOOK WH_MIN
#define WH_MAXHOOK WH_MAX
#define HC_ACTION 0
#define HC_GETNEXT 1
#define HC_SKIP 2
#define HC_NOREMOVE 3
#define HC_NOREM HC_NOREMOVE
#define HC_SYSMODALON 4
#define HC_SYSMODALOFF 5
#define HCBT_MOVESIZE 0
#define HCBT_MINMAX 1
#define HCBT_QS 2
#define HCBT_CREATEWND 3
#define HCBT_DESTROYWND 4
#define HCBT_ACTIVATE 5
#define HCBT_CLICKSKIPPED 6
#define HCBT_KEYSKIPPED 7
#define HCBT_SYSCOMMAND 8
#define HCBT_SETFOCUS 9

#define GetMessage __MINGW_NAME_AW(GetMessage)
#define DispatchMessage __MINGW_NAME_AW(DispatchMessage)
#define PeekMessage __MINGW_NAME_AW(PeekMessage)
WINUSERAPI WINBOOL WINAPI GetMessageA(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax);
WINUSERAPI WINBOOL WINAPI GetMessageW(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax);
WINUSERAPI WINBOOL WINAPI TranslateMessage(CONST MSG *lpMsg);
WINUSERAPI LRESULT WINAPI DispatchMessageA(CONST MSG *lpMsg);
WINUSERAPI LRESULT WINAPI DispatchMessageW(CONST MSG *lpMsg);
WINUSERAPI WINBOOL WINAPI SetMessageQueue(int cMessagesMax);
WINUSERAPI WINBOOL WINAPI PeekMessageA(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax,UINT wRemoveMsg);
WINUSERAPI WINBOOL WINAPI PeekMessageW(LPMSG lpMsg,HWND hWnd,UINT wMsgFilterMin,UINT wMsgFilterMax,UINT wRemoveMsg);
#define PM_NOREMOVE 0x0000
#define PM_REMOVE 0x0001
#define PM_NOYIELD 0x0002
#define PM_QS_INPUT (QS_INPUT << 16)
#define PM_QS_POSTMESSAGE ((QS_POSTMESSAGE | QS_HOTKEY | QS_TIMER) << 16)
#define PM_QS_PAINT (QS_PAINT << 16)
#define PM_QS_SENDMESSAGE (QS_SENDMESSAGE << 16)

WINGDIAPI HBITMAP WINAPI CreateCompatibleBitmap(HDC hdc,int cx,int cy);
WINGDIAPI HBITMAP WINAPI CreateDiscardableBitmap(HDC hdc,int cx,int cy);
WINGDIAPI HDC WINAPI CreateCompatibleDC(HDC hdc);
WINGDIAPI HGDIOBJ WINAPI SelectObject(HDC hdc,HGDIOBJ h);

typedef struct tagSIZE
{
LONG cx;
LONG cy;
}
SIZE,*PSIZE,*LPSIZE;
typedef SIZE SIZEL;
typedef SIZE *PSIZEL,*LPSIZEL;
typedef struct tagPOINTS
{
SHORT x;
SHORT y;
}
POINTS,*PPOINTS,*LPPOINTS;

typedef struct _BLENDFUNCTION
{
BYTE BlendOp;
BYTE BlendFlags;
BYTE SourceConstantAlpha;
BYTE AlphaFormat;
}
BLENDFUNCTION,*PBLENDFUNCTION;

typedef USHORT COLOR16;
typedef struct _TRIVERTEX
{
LONG x;
LONG y;
COLOR16 Red;
COLOR16 Green;
COLOR16 Blue;
COLOR16 Alpha;
}
TRIVERTEX,*PTRIVERTEX,*LPTRIVERTEX;

#define AC_SRC_OVER 0x00
#define AC_SRC_ALPHA 0x01
WINGDIAPI WINBOOL WINAPI AlphaBlend(HDC hdcDest,int xoriginDest,int yoriginDest,int wDest,int hDest,HDC hdcSrc,int xoriginSrc,int yoriginSrc,int wSrc,int hSrc,BLENDFUNCTION ftn);
WINGDIAPI WINBOOL WINAPI GdiAlphaBlend(HDC hdcDest,int xoriginDest,int yoriginDest,int wDest,int hDest,HDC hdcSrc,int xoriginSrc,int yoriginSrc,int wSrc,int hSrc,BLENDFUNCTION ftn);
WINGDIAPI WINBOOL WINAPI TransparentBlt(HDC hdcDest,int xoriginDest,int yoriginDest,int wDest,int hDest,HDC hdcSrc,int xoriginSrc,int yoriginSrc,int wSrc,int hSrc,UINT crTransparent);
WINGDIAPI WINBOOL WINAPI GdiTransparentBlt(HDC hdcDest,int xoriginDest,int yoriginDest,int wDest,int hDest,HDC hdcSrc,int xoriginSrc,int yoriginSrc,int wSrc,int hSrc,UINT crTransparent);
#define GRADIENT_FILL_RECT_H 0x00000000
#define GRADIENT_FILL_RECT_V 0x00000001
#define GRADIENT_FILL_TRIANGLE 0x00000002
#define GRADIENT_FILL_OP_FLAG 0x000000ff
WINGDIAPI WINBOOL WINAPI GradientFill(HDC hdc,PTRIVERTEX pVertex,ULONG nVertex,PVOID pMesh,ULONG nMesh,ULONG ulMode);
WINGDIAPI WINBOOL WINAPI GdiGradientFill(HDC hdc,PTRIVERTEX pVertex,ULONG nVertex,PVOID pMesh,ULONG nMesh,ULONG ulMode);

WINUSERAPI WINBOOL WINAPI UpdateLayeredWindow (HWND hWnd, HDC hdcDst, POINT *pptDst, SIZE *psize, HDC hdcSrc, POINT *pptSrc, COLORREF crKey, BLENDFUNCTION *pblend, DWORD dwFlags);
typedef struct tagUPDATELAYEREDWINDOWINFO
{
DWORD cbSize;
HDC hdcDst;
const POINT *pptDst;
const SIZE *psize;
HDC hdcSrc;
const POINT *pptSrc;
COLORREF crKey;
const BLENDFUNCTION *pblend;
DWORD dwFlags;
const RECT *prcDirty;
}
UPDATELAYEREDWINDOWINFO,*PUPDATELAYEREDWINDOWINFO;

#define LWA_COLORKEY 0x00000001
#define LWA_ALPHA 0x00000002
#define ULW_COLORKEY 0x00000001
#define ULW_ALPHA 0x00000002
#define ULW_OPAQUE 0x00000004
#define ULW_EX_NORESIZE 0x00000008
#define FLASHW_STOP 0
#define FLASHW_CAPTION 0x00000001
#define FLASHW_TRAY 0x00000002
#define FLASHW_ALL (FLASHW_CAPTION | FLASHW_TRAY)
#define FLASHW_TIMER 0x00000004
#define FLASHW_TIMERNOFG 0x0000000c

#define LoadString __MINGW_NAME_AW(LoadString)
#define GetModuleFileName __MINGW_NAME_AW(GetModuleFileName)
#define GetModuleHandle __MINGW_NAME_AW(GetModuleHandle)
#define LoadLibraryEx __MINGW_NAME_AW(LoadLibraryEx)
#define EnumResourceLanguages __MINGW_NAME_AW(EnumResourceLanguages)

#define DECLSPEC_NORETURN
typedef PVOID DLL_DIRECTORY_COOKIE, *PDLL_DIRECTORY_COOKIE;
WINBASEAPI HRSRC WINAPI FindResourceExW (HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage);
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI FreeLibraryAndExitThread (HMODULE hLibModule, DWORD dwExitCode);
WINBASEAPI WINBOOL WINAPI FreeResource (HGLOBAL hResData);
WINBASEAPI DWORD WINAPI GetModuleFileNameA (HMODULE hModule, LPSTR lpFilename, DWORD nSize);
WINBASEAPI DWORD WINAPI GetModuleFileNameW (HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
WINBASEAPI HMODULE WINAPI GetModuleHandleA (LPCSTR lpModuleName);
WINBASEAPI HMODULE WINAPI GetModuleHandleW (LPCWSTR lpModuleName);
WINBASEAPI HMODULE WINAPI LoadLibraryExA (LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
WINBASEAPI HMODULE WINAPI LoadLibraryExW (LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
WINBASEAPI HGLOBAL WINAPI LoadResource (HMODULE hModule, HRSRC hResInfo);
WINUSERAPI int WINAPI LoadStringA (HINSTANCE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax);
WINUSERAPI int WINAPI LoadStringW (HINSTANCE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax);
WINBASEAPI LPVOID WINAPI LockResource (HGLOBAL hResData);
WINBASEAPI DWORD WINAPI SizeofResource (HMODULE hModule, HRSRC hResInfo);
WINBASEAPI DLL_DIRECTORY_COOKIE WINAPI AddDllDirectory (PCWSTR NewDirectory);
WINBASEAPI WINBOOL WINAPI RemoveDllDirectory (DLL_DIRECTORY_COOKIE Cookie);
WINBASEAPI WINBOOL WINAPI SetDefaultDllDirectories (DWORD DirectoryFlags);
WINBASEAPI WINBOOL WINAPI GetModuleHandleExA (DWORD dwFlags, LPCSTR lpModuleName, HMODULE *phModule);
WINBASEAPI WINBOOL WINAPI GetModuleHandleExW (DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule);
#define PGET_MODULE_HANDLE_EX __MINGW_NAME_AW(PGET_MODULE_HANDLE_EX)
#define GetModuleHandleEx __MINGW_NAME_AW(GetModuleHandleEx)
WINGDIAPI HBRUSH WINAPI CreateSolidBrush(COLORREF color);
#define LoadCursor __MINGW_NAME_AW(LoadCursor)
WINUSERAPI HCURSOR WINAPI LoadCursorA(HINSTANCE hInstance,LPCSTR lpCursorName);
WINUSERAPI HCURSOR WINAPI LoadCursorW(HINSTANCE hInstance,LPCWSTR lpCursorName);
#define IDC_ARROW MAKEINTRESOURCE(32512)
#define IDC_IBEAM MAKEINTRESOURCE(32513)
#define IDC_WAIT MAKEINTRESOURCE(32514)
#define IDC_CROSS MAKEINTRESOURCE(32515)
#define IDC_UPARROW MAKEINTRESOURCE(32516)
#define IDC_SIZE MAKEINTRESOURCE(32640)
#define IDC_ICON MAKEINTRESOURCE(32641)
#define IDC_SIZENWSE MAKEINTRESOURCE(32642)
#define IDC_SIZENESW MAKEINTRESOURCE(32643)
#define IDC_SIZEWE MAKEINTRESOURCE(32644)
#define IDC_SIZENS MAKEINTRESOURCE(32645)
#define IDC_SIZEALL MAKEINTRESOURCE(32646)
#define IDC_NO MAKEINTRESOURCE(32648)
#define IDC_HAND MAKEINTRESOURCE(32649)
#define IDC_APPSTARTING MAKEINTRESOURCE(32650)
#define IDC_HELP MAKEINTRESOURCE(32651)
#define LoadIcon __MINGW_NAME_AW(LoadIcon)
WINUSERAPI HICON WINAPI LoadIconA(HINSTANCE hInstance,LPCSTR lpIconName);
WINUSERAPI HICON WINAPI LoadIconW(HINSTANCE hInstance,LPCWSTR lpIconName);
#ifndef NOICONS
#ifdef RC_INVOKED
#define IDI_APPLICATION 32512
#define IDI_HAND 32513
#define IDI_QUESTION 32514
#define IDI_EXCLAMATION 32515
#define IDI_ASTERISK 32516
#define IDI_WINLOGO 32517
#if WINVER >= 0x0600
#define IDI_SHIELD 32518
#endif
#else
#define IDI_APPLICATION MAKEINTRESOURCE(32512)
#define IDI_HAND MAKEINTRESOURCE(32513)
#define IDI_QUESTION MAKEINTRESOURCE(32514)
#define IDI_EXCLAMATION MAKEINTRESOURCE(32515)
#define IDI_ASTERISK MAKEINTRESOURCE(32516)
#define IDI_WINLOGO MAKEINTRESOURCE(32517)
#if WINVER >= 0x0600
#define IDI_SHIELD MAKEINTRESOURCE (32518)
#endif
#endif
#define IDI_WARNING IDI_EXCLAMATION
#define IDI_ERROR IDI_HAND
#define IDI_INFORMATION IDI_ASTERISK
#endif

#define RegisterDeviceNotification __MINGW_NAME_AW(RegisterDeviceNotification)
#define PostMessage __MINGW_NAME_AW(PostMessage)
#define PostThreadMessage __MINGW_NAME_AW(PostThreadMessage)
#define PostAppMessage __MINGW_NAME_AW(PostAppMessage)
#define DefWindowProc __MINGW_NAME_AW(DefWindowProc)
#define CallWindowProc __MINGW_NAME_AW(CallWindowProc)
#define RegisterClass __MINGW_NAME_AW(RegisterClass)
#define UnregisterClass __MINGW_NAME_AW(UnregisterClass)
#define GetClassInfo __MINGW_NAME_AW(GetClassInfo)
#define RegisterClassEx __MINGW_NAME_AW(RegisterClassEx)
#define GetClassInfoEx __MINGW_NAME_AW(GetClassInfoEx)
#define MessageBox __MINGW_NAME_AW(MessageBox)
#define MessageBoxEx __MINGW_NAME_AW(MessageBoxEx)
WINUSERAPI int WINAPI MessageBoxA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
WINUSERAPI int WINAPI MessageBoxW(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption,UINT uType);
WINUSERAPI int WINAPI MessageBoxExA(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType,WORD wLanguageId);
WINUSERAPI int WINAPI MessageBoxExW(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption,UINT uType,WORD wLanguageId);
#define MB_OK __MSABI_LONG(0x00000000)
#define MB_OKCANCEL __MSABI_LONG(0x00000001)
#define MB_ABORTRETRYIGNORE __MSABI_LONG(0x00000002)
#define MB_YESNOCANCEL __MSABI_LONG(0x00000003)
#define MB_YESNO __MSABI_LONG(0x00000004)
#define MB_RETRYCANCEL __MSABI_LONG(0x00000005)
#define MB_CANCELTRYCONTINUE __MSABI_LONG(0x00000006)
#define MB_ICONHAND __MSABI_LONG(0x00000010)
#define MB_ICONQUESTION __MSABI_LONG(0x00000020)
#define MB_ICONEXCLAMATION __MSABI_LONG(0x00000030)
#define MB_ICONASTERISK __MSABI_LONG(0x00000040)
#define MB_USERICON __MSABI_LONG(0x00000080)
#define MB_ICONWARNING MB_ICONEXCLAMATION
#define MB_ICONERROR MB_ICONHAND
#define MB_ICONINFORMATION MB_ICONASTERISK
#define MB_ICONSTOP MB_ICONHAND
#define MB_DEFBUTTON1 __MSABI_LONG(0x00000000)
#define MB_DEFBUTTON2 __MSABI_LONG(0x00000100)
#define MB_DEFBUTTON3 __MSABI_LONG(0x00000200)
#define MB_DEFBUTTON4 __MSABI_LONG(0x00000300)
#define MB_APPLMODAL __MSABI_LONG(0x00000000)
#define MB_SYSTEMMODAL __MSABI_LONG(0x00001000)
#define MB_TASKMODAL __MSABI_LONG(0x00002000)
#define MB_HELP __MSABI_LONG(0x00004000)
#define MB_NOFOCUS __MSABI_LONG(0x00008000)
#define MB_SETFOREGROUND __MSABI_LONG(0x00010000)
#define MB_DEFAULT_DESKTOP_ONLY __MSABI_LONG(0x00020000)
#define MB_TOPMOST __MSABI_LONG(0x00040000)
#define MB_RIGHT __MSABI_LONG(0x00080000)
#define MB_RTLREADING __MSABI_LONG(0x00100000)
#define MB_SERVICE_NOTIFICATION __MSABI_LONG(0x00200000)
#define MB_SERVICE_NOTIFICATION_NT3X __MSABI_LONG(0x00040000)
#define MB_TYPEMASK __MSABI_LONG(0x0000000F)
#define MB_ICONMASK __MSABI_LONG(0x000000F0)
#define MB_DEFMASK __MSABI_LONG(0x00000F00)
#define MB_MODEMASK __MSABI_LONG(0x00003000)
#define MB_MISCMASK __MSABI_LONG(0x0000C000)

#ifndef NOWINSTYLES
#define WS_OVERLAPPED __MSABI_LONG(0x00000000)
#define WS_POPUP __MSABI_LONG(0x80000000)
#define WS_CHILD __MSABI_LONG(0x40000000)
#define WS_MINIMIZE __MSABI_LONG(0x20000000)
#define WS_VISIBLE __MSABI_LONG(0x10000000)
#define WS_DISABLED __MSABI_LONG(0x08000000)
#define WS_CLIPSIBLINGS __MSABI_LONG(0x04000000)
#define WS_CLIPCHILDREN __MSABI_LONG(0x02000000)
#define WS_MAXIMIZE __MSABI_LONG(0x01000000)
#define WS_CAPTION __MSABI_LONG(0x00C00000)
#define WS_BORDER __MSABI_LONG(0x00800000)
#define WS_DLGFRAME __MSABI_LONG(0x00400000)
#define WS_VSCROLL __MSABI_LONG(0x00200000)
#define WS_HSCROLL __MSABI_LONG(0x00100000)
#define WS_SYSMENU __MSABI_LONG(0x00080000)
#define WS_THICKFRAME __MSABI_LONG(0x00040000)
#define WS_GROUP __MSABI_LONG(0x00020000)
#define WS_TABSTOP __MSABI_LONG(0x00010000)
#define WS_MINIMIZEBOX __MSABI_LONG(0x00020000)
#define WS_MAXIMIZEBOX __MSABI_LONG(0x00010000)
#define WS_TILED WS_OVERLAPPED
#define WS_ICONIC WS_MINIMIZE
#define WS_SIZEBOX WS_THICKFRAME
#define WS_TILEDWINDOW WS_OVERLAPPEDWINDOW
#define WS_OVERLAPPEDWINDOW (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
#define WS_POPUPWINDOW (WS_POPUP | WS_BORDER | WS_SYSMENU)
#define WS_CHILDWINDOW (WS_CHILD)
#define WS_EX_DLGMODALFRAME __MSABI_LONG(0x00000001)
#define WS_EX_NOPARENTNOTIFY __MSABI_LONG(0x00000004)
#define WS_EX_TOPMOST __MSABI_LONG(0x00000008)
#define WS_EX_ACCEPTFILES __MSABI_LONG(0x00000010)
#define WS_EX_TRANSPARENT __MSABI_LONG(0x00000020)
#define WS_EX_MDICHILD __MSABI_LONG(0x00000040)
#define WS_EX_TOOLWINDOW __MSABI_LONG(0x00000080)
#define WS_EX_WINDOWEDGE __MSABI_LONG(0x00000100)
#define WS_EX_CLIENTEDGE __MSABI_LONG(0x00000200)
#define WS_EX_CONTEXTHELP __MSABI_LONG(0x00000400)
#define WS_EX_RIGHT __MSABI_LONG(0x00001000)
#define WS_EX_LEFT __MSABI_LONG(0x00000000)
#define WS_EX_RTLREADING __MSABI_LONG(0x00002000)
#define WS_EX_LTRREADING __MSABI_LONG(0x00000000)
#define WS_EX_LEFTSCROLLBAR __MSABI_LONG(0x00004000)
#define WS_EX_RIGHTSCROLLBAR __MSABI_LONG(0x00000000)
#define WS_EX_CONTROLPARENT __MSABI_LONG(0x00010000)
#define WS_EX_STATICEDGE __MSABI_LONG(0x00020000)
#define WS_EX_APPWINDOW __MSABI_LONG(0x00040000)
#define WS_EX_OVERLAPPEDWINDOW (WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE)
#define WS_EX_PALETTEWINDOW (WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST)
#define WS_EX_LAYERED 0x00080000
#define WS_EX_NOINHERITLAYOUT __MSABI_LONG(0x00100000)
#if WINVER >= 0x0602
#define WS_EX_NOREDIRECTIONBITMAP __MSABI_LONG(0x00200000)
#endif
#define WS_EX_LAYOUTRTL __MSABI_LONG(0x00400000)
#define WS_EX_COMPOSITED __MSABI_LONG(0x02000000)
#define WS_EX_NOACTIVATE __MSABI_LONG(0x08000000)
#define CS_VREDRAW 0x0001
#define CS_HREDRAW 0x0002
#define CS_DBLCLKS 0x0008
#define CS_OWNDC 0x0020
#define CS_CLASSDC 0x0040
#define CS_PARENTDC 0x0080
#define CS_NOCLOSE 0x0200
#define CS_SAVEBITS 0x0800
#define CS_BYTEALIGNCLIENT 0x1000
#define CS_BYTEALIGNWINDOW 0x2000
#define CS_GLOBALCLASS 0x4000
#define CS_IME 0x00010000
#define CS_DROPSHADOW 0x00020000
#endif
#define PRF_CHECKVISIBLE __MSABI_LONG(0x00000001)
#define PRF_NONCLIENT __MSABI_LONG(0x00000002)
#define PRF_CLIENT __MSABI_LONG(0x00000004)
#define PRF_ERASEBKGND __MSABI_LONG(0x00000008)
#define PRF_CHILDREN __MSABI_LONG(0x00000010)
#define PRF_OWNED __MSABI_LONG(0x00000020)
#define BDR_RAISEDOUTER 0x0001
#define BDR_SUNKENOUTER 0x0002
#define BDR_RAISEDINNER 0x0004
#define BDR_SUNKENINNER 0x0008
#define BDR_OUTER (BDR_RAISEDOUTER | BDR_SUNKENOUTER)
#define BDR_INNER (BDR_RAISEDINNER | BDR_SUNKENINNER)
#define BDR_RAISED (BDR_RAISEDOUTER | BDR_RAISEDINNER)
#define BDR_SUNKEN (BDR_SUNKENOUTER | BDR_SUNKENINNER)
#define EDGE_RAISED (BDR_RAISEDOUTER | BDR_RAISEDINNER)
#define EDGE_SUNKEN (BDR_SUNKENOUTER | BDR_SUNKENINNER)
#define EDGE_ETCHED (BDR_SUNKENOUTER | BDR_RAISEDINNER)
#define EDGE_BUMP (BDR_RAISEDOUTER | BDR_SUNKENINNER)
#define BF_LEFT 0x0001
#define BF_TOP 0x0002
#define BF_RIGHT 0x0004
#define BF_BOTTOM 0x0008
#define BF_TOPLEFT (BF_TOP | BF_LEFT)
#define BF_TOPRIGHT (BF_TOP | BF_RIGHT)
#define BF_BOTTOMLEFT (BF_BOTTOM | BF_LEFT)
#define BF_BOTTOMRIGHT (BF_BOTTOM | BF_RIGHT)
#define BF_RECT (BF_LEFT | BF_TOP | BF_RIGHT | BF_BOTTOM)
#define BF_DIAGONAL 0x0010
#define BF_DIAGONAL_ENDTOPRIGHT (BF_DIAGONAL | BF_TOP | BF_RIGHT)
#define BF_DIAGONAL_ENDTOPLEFT (BF_DIAGONAL | BF_TOP | BF_LEFT)
#define BF_DIAGONAL_ENDBOTTOMLEFT (BF_DIAGONAL | BF_BOTTOM | BF_LEFT)
#define BF_DIAGONAL_ENDBOTTOMRIGHT (BF_DIAGONAL | BF_BOTTOM | BF_RIGHT)
#define BF_MIDDLE 0x0800
#define BF_SOFT 0x1000
#define BF_ADJUST 0x2000
#define BF_FLAT 0x4000
#define BF_MONO 0x8000
#if WINAPI_FAMILY_PARTITION (WINAPI_PARTITION_DESKTOP)
WINUSERAPI WINBOOL WINAPI DrawEdge(HDC hdc,LPRECT qrc,UINT edge,UINT grfFlags);
#endif
#define DFC_CAPTION 1
#define DFC_MENU 2
#define DFC_SCROLL 3
#define DFC_BUTTON 4
#define DFC_POPUPMENU 5
#define DFCS_CAPTIONCLOSE 0x0000
#define DFCS_CAPTIONMIN 0x0001
#define DFCS_CAPTIONMAX 0x0002
#define DFCS_CAPTIONRESTORE 0x0003
#define DFCS_CAPTIONHELP 0x0004
#define DFCS_MENUARROW 0x0000
#define DFCS_MENUCHECK 0x0001
#define DFCS_MENUBULLET 0x0002
#define DFCS_MENUARROWRIGHT 0x0004
#define DFCS_SCROLLUP 0x0000
#define DFCS_SCROLLDOWN 0x0001
#define DFCS_SCROLLLEFT 0x0002
#define DFCS_SCROLLRIGHT 0x0003
#define DFCS_SCROLLCOMBOBOX 0x0005
#define DFCS_SCROLLSIZEGRIP 0x0008
#define DFCS_SCROLLSIZEGRIPRIGHT 0x0010
#define DFCS_BUTTONCHECK 0x0000
#define DFCS_BUTTONRADIOIMAGE 0x0001
#define DFCS_BUTTONRADIOMASK 0x0002
#define DFCS_BUTTONRADIO 0x0004
#define DFCS_BUTTON3STATE 0x0008
#define DFCS_BUTTONPUSH 0x0010
#define DFCS_INACTIVE 0x0100
#define DFCS_PUSHED 0x0200
#define DFCS_CHECKED 0x0400
#define DFCS_TRANSPARENT 0x0800
#define DFCS_HOT 0x1000
#define DFCS_ADJUSTRECT 0x2000
#define DFCS_FLAT 0x4000
#define DFCS_MONO 0x8000
#if WINAPI_FAMILY_PARTITION (WINAPI_PARTITION_DESKTOP)
WINUSERAPI WINBOOL WINAPI DrawFrameControl(HDC,LPRECT,UINT,UINT);
#endif
#define DC_ACTIVE 0x0001
#define DC_SMALLCAP 0x0002
#define DC_ICON 0x0004
#define DC_TEXT 0x0008
#define DC_INBUTTON 0x0010
#define DC_GRADIENT 0x0020
#define DC_BUTTONS 0x1000

WINBASEAPI VOID WINAPI Sleep (DWORD dwMilliseconds);
WINBASEAPI HANDLE WINAPI CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI WINBOOL WINAPI SetThreadPriority (HANDLE hThread, int nPriority);
WINBASEAPI int WINAPI GetThreadPriority (HANDLE hThread);
WINBASEAPI DECLSPEC_NORETURN VOID WINAPI ExitThread (DWORD dwExitCode);
WINBASEAPI WINBOOL WINAPI GetExitCodeThread (HANDLE hThread, LPDWORD lpExitCode);
WINBASEAPI DWORD WINAPI SuspendThread (HANDLE hThread);
WINBASEAPI DWORD WINAPI ResumeThread (HANDLE hThread);

typedef struct _RTL_BARRIER
{
DWORD Reserved1;
DWORD Reserved2;
ULONG_PTR Reserved3[2];
DWORD Reserved4;
DWORD Reserved5;
}
RTL_BARRIER,*PRTL_BARRIER;

typedef VOID (APIENTRY *PTIMERAPCROUTINE) (LPVOID lpArgToCompletionRoutine, DWORD dwTimerLowValue, DWORD dwTimerHighValue);
typedef RTL_BARRIER SYNCHRONIZATION_BARRIER;
typedef PRTL_BARRIER PSYNCHRONIZATION_BARRIER;
typedef PRTL_BARRIER LPSYNCHRONIZATION_BARRIER;
#define SYNCHRONIZATION_BARRIER_FLAGS_SPIN_ONLY 0x01
#define SYNCHRONIZATION_BARRIER_FLAGS_BLOCK_ONLY 0x02
#define SYNCHRONIZATION_BARRIER_FLAGS_NO_DELETE 0x04

WINBASEAPI VOID WINAPI InitializeCriticalSection (LPCRITICAL_SECTION lpCriticalSection);
WINBASEAPI WINBOOL WINAPI InitializeCriticalSectionAndSpinCount (LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
WINBASEAPI DWORD WINAPI SetCriticalSectionSpinCount (LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount);
WINBASEAPI DWORD WINAPI WaitForSingleObject (HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI DWORD WINAPI SleepEx (DWORD dwMilliseconds, WINBOOL bAlertable);
WINBASEAPI HANDLE WINAPI CreateMutexA (LPSECURITY_ATTRIBUTES lpMutexAttributes, WINBOOL bInitialOwner, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI CreateMutexW (LPSECURITY_ATTRIBUTES lpMutexAttributes, WINBOOL bInitialOwner, LPCWSTR lpName);
WINBASEAPI HANDLE WINAPI CreateEventA (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI CreateEventW (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCWSTR lpName);
WINBASEAPI WINBOOL WINAPI SetWaitableTimer (HANDLE hTimer, const LARGE_INTEGER *lpDueTime, LONG lPeriod, PTIMERAPCROUTINE pfnCompletionRoutine, LPVOID lpArgToCompletionRoutine, WINBOOL fResume);
WINBASEAPI WINBOOL WINAPI CancelWaitableTimer (HANDLE hTimer);
WINBASEAPI HANDLE WINAPI OpenWaitableTimerW (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCWSTR lpTimerName);
WINBOOL WINAPI EnterSynchronizationBarrier (LPSYNCHRONIZATION_BARRIER lpBarrier, DWORD dwFlags);
WINBOOL WINAPI InitializeSynchronizationBarrier (LPSYNCHRONIZATION_BARRIER lpBarrier, LONG lTotalThreads, LONG lSpinCount);
WINBOOL WINAPI DeleteSynchronizationBarrier (LPSYNCHRONIZATION_BARRIER lpBarrier);
WINBASEAPI VOID WINAPI EnterCriticalSection (LPCRITICAL_SECTION lpCriticalSection);
WINBASEAPI VOID WINAPI LeaveCriticalSection (LPCRITICAL_SECTION lpCriticalSection);
WINBASEAPI WINBOOL WINAPI TryEnterCriticalSection (LPCRITICAL_SECTION lpCriticalSection);
WINBASEAPI VOID WINAPI DeleteCriticalSection (LPCRITICAL_SECTION lpCriticalSection);
WINBASEAPI WINBOOL WINAPI SetEvent (HANDLE hEvent);
WINBASEAPI WINBOOL WINAPI ResetEvent (HANDLE hEvent);
WINBASEAPI WINBOOL WINAPI ReleaseSemaphore (HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount);
WINBASEAPI WINBOOL WINAPI ReleaseMutex (HANDLE hMutex);
WINBASEAPI DWORD WINAPI WaitForSingleObjectEx (HANDLE hHandle, DWORD dwMilliseconds, WINBOOL bAlertable);
WINBASEAPI DWORD WINAPI WaitForMultipleObjectsEx (DWORD nCount, CONST HANDLE *lpHandles, WINBOOL bWaitAll, DWORD dwMilliseconds, WINBOOL bAlertable);
WINBASEAPI HANDLE WINAPI OpenMutexW (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCWSTR lpName);
WINBASEAPI HANDLE WINAPI OpenEventA (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI OpenEventW (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCWSTR lpName);
WINBASEAPI HANDLE WINAPI OpenSemaphoreW (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCWSTR lpName);
WINBOOL WINAPI WaitOnAddress (volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds);
VOID WINAPI WakeByAddressSingle (PVOID Address);
VOID WINAPI WakeByAddressAll (PVOID Address);

WINBASEAPI LONG WINAPI InterlockedIncrement (LONG volatile *lpAddend);
WINBASEAPI LONG WINAPI InterlockedDecrement (LONG volatile *lpAddend);
WINBASEAPI LONG WINAPI InterlockedExchange (LONG volatile *Target, LONG Value);
WINBASEAPI LONG WINAPI InterlockedExchangeAdd (LONG volatile *Addend, LONG Value);
WINBASEAPI LONG WINAPI InterlockedCompareExchange (LONG volatile *Destination, LONG Exchange, LONG Comperand);
WINBASEAPI LONGLONG WINAPI InterlockedCompareExchange64 (LONGLONG volatile *Destination, LONGLONG Exchange, LONGLONG Comperand);
#define InterlockedExchangePointer(Target, Value) (PVOID)InterlockedExchange ((PLONG) (Target),((LONG) (LONG_PTR) (Value)))
#define InterlockedExchangePointerNoFence InterlockedExchangePointer

WINBASEAPI HANDLE WINAPI OpenMutexA (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI CreateSemaphoreA (LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI OpenSemaphoreA (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI CreateWaitableTimerA (LPSECURITY_ATTRIBUTES lpTimerAttributes, WINBOOL bManualReset, LPCSTR lpTimerName);
WINBASEAPI HANDLE WINAPI CreateWaitableTimerW (LPSECURITY_ATTRIBUTES lpTimerAttributes, WINBOOL bManualReset, LPCWSTR lpTimerName);
WINBASEAPI HANDLE WINAPI OpenWaitableTimerA (DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCSTR lpTimerName);
WINBASEAPI HANDLE WINAPI CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI HANDLE WINAPI CreateSemaphoreW (LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCWSTR lpName);
WINBASEAPI HMODULE WINAPI LoadLibraryW (LPCWSTR lpLibFileName);

WINBASEAPI HANDLE WINAPI GetCurrentProcess (VOID);
WINBASEAPI DWORD WINAPI GetCurrentProcessId (VOID);
WINBASEAPI HANDLE WINAPI GetCurrentThread (VOID);
WINBASEAPI DWORD WINAPI GetCurrentThreadId (VOID);
WINBOOL WINAPI IsProcessorFeaturePresent (DWORD ProcessorFeature);

#endif /*Not ImWin*/
/* -extra- */
#ifndef HIWORD
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#endif
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp)    ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)    ((int)(short)HIWORD(lp))
#endif 
#define SETLPARAM(lw, hw) LOWORD(lw) | (LOWORD(hw) << 16)
/* -extra- */
#endif //!-----!//
