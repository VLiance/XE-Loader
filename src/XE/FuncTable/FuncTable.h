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
* Description:
* 
* Remap system function to custom ones 
*
* Usefull declaration                ------------------------    decorated
//void __cdecl foo(void);            ----------------------->    _foo
//void __cdecl foo(int a);           ----------------------->    _foo
//void __cdecl foo(int a, int b);    ----------------------->    _foo
//void __stdcall foo(void);          ----------------------->    _foo@0
//void __stdcall foo(int a);         ----------------------->    _foo@4
//void __stdcall foo(int a, int b);  ----------------------->    _foo@8
//void __fastcall foo(void);         ----------------------->    @foo@0
//void __fastcall foo(int a);        ----------------------->    @foo@4
//void __fastcall foo(int a, int b); ----------------------->    @foo@8
*
*/
#ifndef EXELOADER_FuncTable_H
#define EXELOADER_FuncTable_H

#include "XE/XE.h"
#include "XE/XEGI/XEGI.h"

/*
#ifndef ImWin
#define InCpcDosCore
#include "CPC_WPR.h"
#endif // ImWin
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <errno.h>
#include <conio.h>
#include <assert.h>
#include <stdarg.h>
#include <setjmp.h>
#include <locale.h>
#include <ctype.h>

#include "XE/FuncTable/DummyTable.h"

#include "XE/FuncTable/FT_Memory.h"

#include "XE/Module/PE/FT_pe.h"
#include "XE/Module/ELF/FT_elf.h"


#include "FT_Imp.h"
//#include "FuncTable/FuncTable_Remap_Common.h"
//#include "FuncTable/FuncTable_Remap_Windows.h"
	
#ifndef UseWinFunc
	//onCpcDos
//	#include "FuncTableRemap_CpcDos.h"
#endif


//extern "C" ULONG __chkstk();

fn void __register_frame(void* ptr);
fn void __deregister_frame(void* ptr);
//fn void __unwind_resume(void* object);




#ifdef HAVE_OPERATOR_NEW_INT
fn uint8_t* _Znwj(uint32_t);//new
fn uint8_t* _Znaj(uint32_t);//new
#endif

#ifdef HAVE_OPERATOR_NEW_LONG
fn uint8_t* _Znwm(uint32_t);//new
fn uint8_t* _Znam(uint32_t);//new
#endif

fn void _ZdlPv(uint8_t*);//delete
fn long __divdi3 (long a, long b);




/*
fn void* _aligned_malloc(size_t size,size_t alignment);
fn void  _aligned_free(void *memblock);
fn void* _aligned_realloc(void *memblock,size_t size,size_t alignment);
*/

//Linux
int optind = 1;
char* optarg = 0;


fn UINT ___lc_codepage_func(void);

#define _IOB_ENTRIES_ 20
FILE iob[_IOB_ENTRIES_] = {}; //TODO -> to test


FILE* stdout_; //Not used?
FILE* stderr_; //Not used?

 sFunc aTableFunc[] = {
 ////////// CPC DOS ///////////////////
//#include "FuncTable/CpcDosFuncTable.h"
//////////////////////////////////////
{"",			"func_NotImplemented" 		,(FUNC_) func_NotImplemented }, //Must be first

{"","__initenv" 	,(FUNC_) &__initenv }, //TODO -> to test //Special
{"","__p___initenv" 	,(FUNC_) imp_p__initenv }, //TODO -> to test //Special

{"","_iob" 			,(FUNC_) iob }, 	  //TODO -> to test //Special

{"","_fmode" 		,(FUNC_) &_fmode_ }, 

{"","_commode" 		,(FUNC_) &_commode },
{"","__p__commode" 	,(FUNC_) &imp_p__commode }, 

/////////// CRT /////////////
{"",			"_initterm"  		,(FUNC_) imp_initterm },
{"",			"_initterm_e"  	,(FUNC_) imp_initterm_e },
{"",			"__set_app_type"	  	,(FUNC_) imp_set_app_type },
{"",			"__p__fmode"  		,(FUNC_) imp_p__fmode },
{"",			"__lconv_init"  	,(FUNC_) imp_lconv_init },
{"",			"_acmdln"  			,(FUNC_) &__acmdln },
{"",			"__p__acmdln"  		,(FUNC_) imp_p__acmdln },
{"",			"__getmainargs"  	,(FUNC_) imp_getmainargs },
{"",			"_environ"  		,(FUNC_) (char***)&_environ_ },
{"",			"__p__environ"  	,(FUNC_) imp_p__environ },

/////// Linux /////
#ifdef HAVE_OPERATOR_NEW_INT
{"",			"_Znwj"  	,(FUNC_) _Znwj },//new
{"",			"_Znaj"  	,(FUNC_) _Znaj },//new
#endif
#ifdef HAVE_OPERATOR_NEW_LONG
{"",			"_Znwj"  	,(FUNC_) _Znwm },//TODO can we map int to long param?
{"",			"_Znaj"  	,(FUNC_) _Znam },//TODO can we map int to long param?
#endif
{"",			"_ZdlPv"  	,(FUNC_) _ZdlPv },//delete

{"",			"__cxa_finalize" ,(FUNC_)  imp_cxa_finalize }, //global destructor

{"",			"__divdi3"  	,(FUNC_) __divdi3 },
{"",			"__libc_start_main"  	,(FUNC_) imp_libc_start_main },
{"",			"XOpenDisplay"  	,(FUNC_) imp_XOpenDisplay },
{"",			"XMatchVisualInfo"  	,(FUNC_) imp_XMatchVisualInfo },
{"",			"XCreateColormap"  	,(FUNC_) imp_XCreateColormap },
{"",			"XCreateWindow"  	,(FUNC_) imp_XCreateWindow },
{"",			"XAllocWMHints"  	,(FUNC_) imp_XAllocWMHints },
{"",			"XShmCreateImage"  	,(FUNC_) imp_XShmCreateImage},
{"",			"XShmCreateImage"  	,(FUNC_) imp_XShmCreateImage},
{"",			"pthread_create"  	,(FUNC_) imp_pthread_create},
{"",			"clock_gettime" 	,(FUNC_) imp_clock_gettime},
{"",			"usleep" 	,(FUNC_) imp_usleep},
{"",			"XTranslateCoordinates" 	,(FUNC_) imp_XTranslateCoordinates},
{"",			"shmget" 		,(FUNC_) imp_shmget},
{"",			"shmat" 		,(FUNC_) imp_shmat},
{"",			"sleep" 		,(FUNC_) imp_sleep},
{"",			"usleep" 		,(FUNC_) imp_usleep},
{"",			"XPending" 		,(FUNC_) imp_XPending},
{"",			"XShmPutImage" 	,(FUNC_) imp_XShmPutImage},
{"",			"getopt" 		,(FUNC_) imp_getopt},
{"",			"optind" 		,(FUNC_) &optind}, 
{"",			"optarg" 		,(FUNC_) &optarg}, 
{"",			"stderr" 		,(FUNC_) &stderr_}, 
{"",			"stdout" 		,(FUNC_) &stdout_}, 
{"",			"__gmon_start__" ,(FUNC_)imp_gmon_start__}, //weak ref
{"",			"_Jv_RegisterClasses" ,(FUNC_)imp_Jv_RegisterClasses}, //weak ref
{"",			"fopen64" 		,(FUNC_) imp_fopen64}, 
{"",			"__stack_chk_fail" 		,(FUNC_) imp_stack_chk_fail}, 
{"",			"perror" 		,(FUNC_) imp_perror}, 
{"",			"__errno_location" 		,(FUNC_) imp_errno_location}, 
//{"",			"_Unwind_Resume"  	,(FUNC_) __unwind_resume  },
///////////////////



{"",			"GetProcAddress" 			,(FUNC_) imp_GetProcAddress }, 	//Special
{"",			"LoadLibraryA"    			,(FUNC_) imp_LoadLibraryA },  	//Special
{"",			"LoadLibraryW"    			,(FUNC_) imp_LoadLibraryW},  	//Special
{"",			"LoadLibraryExA"    		,(FUNC_) imp_LoadLibraryExA},  	//Special
{"",			"LoadLibraryExW"    		,(FUNC_) imp_LoadLibraryExW},  	//Special
{"",			"FreeLibrary"    			,(FUNC_) imp_FreeLibrary},  	
//{"LoadLibraryExW"  			,(FUNC_) LoadLibraryExW }, 			//TODO

{"",			"CommandLineToArgvW"  		,(FUNC_) imp_CommandLineToArgvW },
{"",			"GetCommandLineA"  			,(FUNC_) imp_GetCommandLineA },
{"",			"GetCommandLineW"  			,(FUNC_) imp_GetCommandLineW },
//{"chkstk"  					,(FUNC_) imp_chkstk },
#ifdef ImWin
//{"",			"chkstk"  					,(FUNC_) __chkstk }, //not in build x64
#endif

#ifdef USE_Platform_RegisterFrame
{"",			"__register_frame"  	,(FUNC_) __register_frame },
{"",			"__deregister_frame"  	,(FUNC_) __deregister_frame },
#else
{"",			"__register_frame"  	,(FUNC_) imp_register_frame },
{"",			"__deregister_frame"  	,(FUNC_) imp_deregister_frame },
#endif


#ifdef USE_Platform_AlignedAlloc
{"",			"_aligned_malloc"	,(FUNC_) _aligned_malloc },
{"",			"_aligned_realloc"	,(FUNC_) _aligned_realloc },
{"",			"_aligned_free"  	,(FUNC_) _aligned_free },
#else
{"",			"_aligned_malloc"	,(FUNC_) imp_aligned_malloc },
{"",			"_aligned_realloc"	,(FUNC_) imp_aligned_realloc },
{"",			"_aligned_free"  	,(FUNC_) imp_aligned_free },
#endif

/////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////// FUNC TABLE /////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////


#ifdef Func_Win 
{"",			"_onexit"  		,(FUNC_) _onexit },
#else
{"",			"_onexit"  		,(FUNC_) imp_onexit },
#endif

#ifdef Func_Win 
{"",			"___lc_codepage_func"  ,(FUNC_) ___lc_codepage_func },
#else
{"",			"___lc_codepage_func"  ,(FUNC_) imp_lc_codepage_func },
#endif



{"",			"localeconv"  	,(FUNC_) pipe_localeconv },
{"",			"_isctype"  	,(FUNC_) imp_isctype },


/////////////////////////////

//Temp

//{"wcscpy"  				,(FUNC_) wcscpy },
{"",			"sscanf"  				,(FUNC_) sscanf },
{"",			"bsearch"  			,(FUNC_) bsearch },

//{"GetModuleFileNameW"  	,(FUNC_) GetModuleFileNameW },
//{"_open"  				,(FUNC_) imp_open },

/*
{"",			"InitOnceExecuteOnce"  		,(FUNC_) InitOnceExecuteOnce },
{"",			"SleepConditionVariableCS"  	,(FUNC_) thread_SleepConditionVariableCS },
{"",			"InitializeConditionVariable"  ,(FUNC_) InitializeConditionVariable },
{"",			"WakeAllConditionVariable"  	,(FUNC_) WakeAllConditionVariable },
{"",			"WakeConditionVariable"  		,(FUNC_) thread_WakeConditionVariable },
*/

{"",			"CreateSemaphoreA"  		,(FUNC_) th_CreateSemaphoreA },
{"",			"CreateSemaphoreW"  		,(FUNC_) th_CreateSemaphoreW },
{"",			"WaitForSingleObject"  		,(FUNC_) th_WaitForSingleObject },
{"",			"ReleaseSemaphore"  		,(FUNC_) th_ReleaseSemaphore },


//////// Implemented ////////////////////////////////////////

{"",			"_strdup"  		,(FUNC_) imp_strdup },
{"",			"strncpy"  		,(FUNC_) imp_strncpy },
{"",			"isspace"  		,(FUNC_) imp_isspace },
{"",			"isupper"  		,(FUNC_ )imp_isupper },
{"",			"islower"  		,(FUNC_) imp_islower },

{"",			"_lock"  			,(FUNC_) imp_lock },
{"",			"_unlock"  		,(FUNC_) imp_unlock },

{"",			"_vscprintf"  		,(FUNC_) imp_vscprintf },
////////////////////////////////////////////////////////////

////// Special fn WGL ////////////////////////////////////
{"",			"GetPixelFormat"  		,(FUNC_) pipe_GetPixelFormat }, 
{"",			"SetPixelFormat"  		,(FUNC_) pipe_SetPixelFormat }, 
{"",			"ChoosePixelFormat"  	,(FUNC_) pipe_ChoosePixelFormat },
{"",			"DescribePixelFormat"  ,(FUNC_) pipe_DescribePixelFormat },
{"",			"SwapBuffers"  		,(FUNC_) pipe_SwapBuffers },
////////////////////////////////////////////////////////////

///////////////// System //////////////
{"",			"GetDpiForMonitor"  		,(FUNC_) sys_GetDpiForMonitor }, //Shcore.dll
{"",			"SetProcessDpiAwareness"  	,(FUNC_) sys_SetProcessDpiAwareness }, //Shcore.dll
{"",			"SetProcessDPIAware"  		,(FUNC_) sys_SetProcessDPIAware }, //Shcore.dll
////////////////////////////////////////

{"",			"VirtualAlloc"  			,(FUNC_) pipe_VirtualAlloc },
{"",			"VirtualFree"  				,(FUNC_) pipe_VirtualFree },
{"",			"VirtualProtect"  			,(FUNC_) pipe_VirtualProtect },
{"",			"HeapCreate"  				,(FUNC_) mem_HeapCreate },
{"",			"HeapAlloc"  				,(FUNC_) mem_HeapAlloc },
{"",			"HeapFree"  				,(FUNC_) mem_HeapFree },

{"",			"FlushInstructionCache"		,(FUNC_) pipe_FlushInstructionCache },
	
{"",			"setvbuf"  					,(FUNC_) pipe_setvbuf },
{"",			"_set_error_mode" 			,(FUNC_) pipe_set_error_mode },

{"",			"RegisterClassA"  			,(FUNC_) pipe_RegisterClassA }, 
{"",			"RegisterClassW"  			,(FUNC_) pipe_RegisterClassW }, 
{"",			"UnregisterClassA"  		,(FUNC_) pipe_UnregisterClassA }, 
{"",			"UnregisterClassW"  		,(FUNC_) pipe_UnregisterClassW }, 
{"",			"UnregisterClassW"  		,(FUNC_) pipe_UnregisterClassW }, 


{"",			"AdjustWindowRectEx"  		,(FUNC_) pipe_AdjustWindowRectEx }, 

{"",			"DispatchMessageA"  		,(FUNC_) pipe_DispatchMessageA }, 

{"",			"GetSystemInfo"  			,(FUNC_) pipe_GetSystemInfo }, 
{"",			"GetNativeSystemInfo"  		,(FUNC_) pipe_GetNativeSystemInfo }, 
{"",			"WindowFromDC"  			,(FUNC_) pipe_WindowFromDC }, 
{"",			"ClientToScreen"  			,(FUNC_) pipe_ClientToScreen }, 

{"",			"StretchDIBits"  			,(FUNC_) pipe_StretchDIBits },

{"",			"CallNextHookEx"  			,(FUNC_) pipe_CallNextHookEx },
{"",			"EnumDisplaySettingsA" 		,(FUNC_) pipe_EnumDisplaySettingsA },

{"",			"CreateToolhelp32Snapshot"  ,(FUNC_) pipe_CreateToolhelp32Snapshot },
{"",			"Thread32First"  			,(FUNC_) th_Thread32First },
{"",			"Thread32Next"  			,(FUNC_) th_Thread32Next },
{"",			"InterlockedIncrement"  	,(FUNC_) th_InterlockedIncrement },
{"",			"InterlockedDecrement"  	,(FUNC_) th_InterlockedDecrement },

{"",			"ShowWindow"  				,(FUNC_) pipe_ShowWindow },

{"",			"SetWindowsHookExA" 		,(FUNC_) pipe_SetWindowsHookExA },
{"",			"GetModuleHandleA" 			,(FUNC_) pipe_GetModuleHandleA },
{"",			"GetModuleHandleW"  		,(FUNC_) pipe_GetModuleHandleW },

{"",			"GetDC"  					,(FUNC_) sys_GetDC },
{"",			"CloseHandle"  				,(FUNC_) pipe_CloseHandle },

{"",			"LoadCursorA" 				,(FUNC_) pipe_LoadCursorA },
{"",			"LoadCursorW" 				,(FUNC_) pipe_LoadCursorW },
{"",			"LoadIconA"   				,(FUNC_) pipe_LoadIconA },
{"",			"LoadIconW"   				,(FUNC_) pipe_LoadIconW },


{"",			"ScreenToClient"  			,(FUNC_) pipe_ScreenToClient },
{"",			"WideCharToMultiByte"  		,(FUNC_) pipe_WideCharToMultiByte },
{"",			"MultiByteToWideChar"  		,(FUNC_) pipe_MultiByteToWideChar },

{"",			"GetCursorInfo"  			,(FUNC_) pipe_GetCursorInfo },
{"",			"SetWindowPos"  			,(FUNC_) pipe_SetWindowPos },

{"",			"MonitorFromRect" 			,(FUNC_) pipe_MonitorFromRect },
{"",			"GetMonitorInfoW"  			,(FUNC_) pipe_GetMonitorInfoW },


{"",			"OutputDebugStringA"  		,(FUNC_) pipe_OutputDebugStringA },
{"",			"OutputDebugStringW"  		,(FUNC_) pipe_OutputDebugStringW },

{"",			"GetConsoleWindow"  		,(FUNC_) pipe_GetConsoleWindow },

{"",			"GetStdHandle"  						,(FUNC_) pipe_GetStdHandle },
{"",			"GetConsoleScreenBufferInfo"			,(FUNC_) pipe_GetConsoleScreenBufferInfo },


{"",			"InitializeCriticalSectionEx" 			,(FUNC_) pipe_InitializeCriticalSectionEx },
{"",			"IsProcessorFeaturePresent" 			,(FUNC_) pipe_IsProcessorFeaturePresent },
{"",			"InitializeCriticalSectionAndSpinCount"	,(FUNC_) pipe_InitializeCriticalSectionAndSpinCount },


{"",			"InitializeSListHead"			,(FUNC_) sys_InitializeSListHead },


{"",			"setlocale"  				,(FUNC_) pipe_setlocale },
{"",			"getenv"  					,(FUNC_) pipe_getenv },
{"",			"_putenv"  					,(FUNC_) imp_putenv },

{"",			"IsDebuggerPresent"  	 	,(FUNC_) pipe_IsDebuggerPresent },
{"",			"UnhandledExceptionFilter" 	,(FUNC_) pipe_UnhandledExceptionFilter },

{"",			"GetCurrentProcess"  		,(FUNC_) pipe_GetCurrentProcess },
{"",			"TerminateProcess"  		,(FUNC_) pipe_TerminateProcess },
{"",			"GetStartupInoA"  			,(FUNC_) pipe_GetStartupInfoA },
{"",			"GetStartupInoW"  			,(FUNC_) pipe_GetStartupInfoW },

//Windows

{"",			"CreateWindowExA"  				,(FUNC_) sys_CreateWindowExA },
{"",			"CreateWindowExW"  				,(FUNC_) pipe_CreateWindowExW },
{"",			"GetClientRect"  				,(FUNC_) sys_GetClientRect },
{"",			"GetWindowRect"  				,(FUNC_) sys_GetWindowRect },

//Win Ini
{"",			"QueryPerformanceFrequency"  	,(FUNC_) sys_QueryPerformanceFrequency },
{"",			"QueryPerformanceCounter"  		,(FUNC_) sys_QueryPerformanceCounter },
{"",			"GetTickCount"  				,(FUNC_) sys_GetTickCount },
{"",			"GetCurrentThread"  			,(FUNC_) th_GetCurrentThread },
{"",			"GetCurrentThreadId"  			,(FUNC_) sys_GetCurrentThreadId },
{"",			"GetThreadPriority"  			,(FUNC_) th_GetThreadPriority },
{"",			"GetCurrentProcessId"  			,(FUNC_) sys_GetCurrentProcessId },
{"",			"GetSystemTimeAsFileTime"  		,(FUNC_) sys_GetSystemTimeAsFileTime },
{"",			"SetUnhandledExceptionFilter"  	,(FUNC_) sys_SetUnhandledExceptionFilter },
{"",			"CreateEventA"  				,(FUNC_) sys_CreateEventA },
{"",			"CreateEventW"  				,(FUNC_) sys_CreateEventW },

/////////
{"",			"TranslateMessage" 				,(FUNC_) sys_TranslateMessage },
{"",			"DispatchMessageW" 				,(FUNC_) sys_DispatchMessageW },
{"",			"DispatchMessageA" 				,(FUNC_) sys_DispatchMessageA },
{"",			"PeekMessageA"					,(FUNC_) sys_PeekMessageA },
{"",			"PeekMessageW"					,(FUNC_) sys_PeekMessageW },



{"",			"InitializeCriticalSection" 	,(FUNC_) th_InitializeCriticalSection },
{"",			"EnterCriticalSection" 			,(FUNC_) th_EnterCriticalSection },
{"",			"TryEnterCriticalSection" 		,(FUNC_) th_TryEnterCriticalSection },
{"",			"LeaveCriticalSection" 			,(FUNC_) th_LeaveCriticalSection },
{"",			"DeleteCriticalSection" 		,(FUNC_) th_DeleteCriticalSection },

{"",			"EnumerateLoadedModules64" 		,(FUNC_) sys_EnumerateLoadedModules64 },


{"",			"GetModuleFileNameA" 			,(FUNC_) sys_GetModuleFileNameA },
{"",			"GetModuleFileNameW" 			,(FUNC_) sys_GetModuleFileNameW },

{"",			"GetEnvironmentStrings" 		,(FUNC_) sys_GetEnvironmentStrings },
{"",			"GetEnvironmentStringsW" 		,(FUNC_) sys_GetEnvironmentStringsW },
{"",			"FreeEnvironmentStringsA" 		,(FUNC_) sys_FreeEnvironmentStringsA },
{"",			"FreeEnvironmentStringsW" 		,(FUNC_) sys_FreeEnvironmentStringsW },


{"",			"SetErrorMode"  			,(FUNC_) sys_SetErrorMode },

{"",			"DefWindowProcA"  			,(FUNC_) sys_DefWindowProcA },
{"",			"DefWindowProcW"  			,(FUNC_) sys_DefWindowProcW },
{"",			"Sleep"						,(FUNC_) th_Sleep },

{"",			"GetLastError"  			,(FUNC_) sys_GetLastError },
{"",			"SetLastError"  			,(FUNC_) sys_SetLastError },
{"",			"GetFileType"  				,(FUNC_) sys_GetFileType },
{"",			"GetCurrentDirectoryA"  	,(FUNC_) sys_GetCurrentDirectoryA },
{"",			"GetCurrentDirectoryW"  	,(FUNC_) sys_GetCurrentDirectoryW },
{"",			"VerSetConditionMask"  		,(FUNC_) sys_VerSetConditionMask },
{"",			"VerifyVersionInfoW"  		,(FUNC_) sys_VerifyVersionInfoW },
{"",			"DuplicateHandle"  			,(FUNC_) pipe_DuplicateHandle },
{"",			"GetKeyState"  				,(FUNC_) sys_GetKeyState },
{"",			"TrackMouseEvent"  			,(FUNC_) sys_TrackMouseEvent },


{"",			"_get_osfhandle"  			,(FUNC_) imp_get_osfhandle },
{"",			"_lseek"  					,(FUNC_) imp_lseek },
{"",			"_write"  					,(FUNC_) imp_write},
{"",			"_isatty"  					,(FUNC_) imp_isatty},


{"",			"_vsnprintf"  	,(FUNC_) imp_vsnprintf },
{"",			"_snwprintf"  	,(FUNC_) imp_snwprintf },
{"",			"fwprintf"  	,(FUNC_) imp_fwprintf },



{"",			"abort"  		,(FUNC_) imp_abort }, 

{"",			"_stricmp"  ,(FUNC_) imp_stricmp },





#ifdef USE_Platform_LocalAlloc
{"",			"LocalAlloc"  		,(FUNC_) LocalAlloc },
{"",			"LocalReAlloc"		,(FUNC_) LocalReAlloc },
{"",			"LocalSize"  		,(FUNC_) LocalSize },
{"",			"LocalFree"  		,(FUNC_) LocalFree },
#else
{"",			"LocalAlloc"  		,(FUNC_) imp_LocalAlloc },
{"",			"LocalReAlloc"		,(FUNC_) imp_LocalReAlloc },
{"",			"LocalSize"  		,(FUNC_) imp_LocalSize },
{"",			"LocalFree"  		,(FUNC_) imp_LocalFree },
#endif



#ifdef USE_Platform_ThreadStorage
{"",			"TlsAlloc"  		,(FUNC_) TlsAlloc },
{"",			"TlsGetValue" 		,(FUNC_) TlsGetValue },
{"",			"TlsSetValue"  		,(FUNC_) TlsSetValue },
{"",			"TlsFree"  			,(FUNC_) TlsFree },
#else
{"",			"TlsAlloc"  		,(FUNC_) th_TlsAlloc },
{"",			"TlsGetValue"  		,(FUNC_) th_TlsGetValue },
{"",			"TlsSetValue"  		,(FUNC_) th_TlsSetValue },
{"",			"TlsFree"  			,(FUNC_) th_TlsFree },
#endif



//Todo a implémenter
#ifdef InCpcDosCore
#else
/*
	/// UNICODE (not supported on CpcDos)
	{"",			"wcslen"  ,(FUNC_) wcslen },
	{"",			"_strnicmp"  ,(FUNC_) _strnicmp },
	{"",			"fwprintf"  ,(FUNC_) fwprintf },
	{"",			"_vsnprintf"  ,(FUNC_) _vsnprintf },
	{"",			"fputwc"  ,(FUNC_) fputwc },
	{"",			"putwc"  ,(FUNC_) putwc },
	{"",			"getwc"  ,(FUNC_) getwc },

	{"",			"_stricmp"  ,(FUNC_) _stricmp }, //Use stricmp?
	{"",			"GetFileAttributesW"  ,(FUNC_) GetFileAttributesW },
	*/
	
#endif

//{"setbuf"  ,(FUNC_) My_setbuf }, //!!!! Warning Dangerous function!
//{"LocalFree"  			,(FUNC_) LocalFree },








/*
{"",			"_write"  		,(FUNC_) fwrite }, //??
{"",			"_snwprintf"  	,(FUNC_) snprintf },//??
{"",			"wcscpy"  		,(FUNC_) strcpy },  //??
*/


{"",			"malloc"  	,(FUNC_) imp_malloc },
{"",			"calloc"  	,(FUNC_) imp_calloc },
{"",			"realloc"  ,(FUNC_) imp_realloc },
{"",			"free"  	,(FUNC_) imp_free },




{"",			"_snprintf"  		,(FUNC_) snprintf },
{"",			"_beginthreadex"  ,(FUNC_) th_beginthreadex },
{"",			"_errno"  			,(FUNC_) &_errno },

//{"",			"strlen"  	,(FUNC_) strlen },
{"",			"strlen"  	,(FUNC_) imp_strlen }, //safer strlen
{"",			"strpbrk"  	,(FUNC_) imp_strpbrk }, 

/////////////////////////////////////////////
/////////// DIRECT MAPPING //////////////////
/// *safe enough for a direct replacement* ///
/////////////////////////////////////////////
/////////////////////////////////////////////
#ifdef USE_Direct_Mapping

{"",			"vfprintf"  ,(FUNC_) vfprintf },
{"",			"scanf"  ,(FUNC_) scanf },

/////////// LOG ////////////////////
{"",			"printf"  	,(FUNC_) imp_printf },


{"",			"fflush"  	,(FUNC_) imp_fflush },
{"",			"fwrite"  	,(FUNC_) imp_fwrite },

{"",			"fprintf"  ,(FUNC_) imp_fprintf },
{"",			"sprintf"  ,(FUNC_) imp_sprintf },
{"",			"vsprintf"  ,(FUNC_) imp_vsprintf },


{"",			"putc"  	,(FUNC_) imp_putc },
{"",			"fputc"  	,(FUNC_) imp_fputc },
{"",			"puts"  	,(FUNC_) imp_puts },
{"",			"fputs"  	,(FUNC_) imp_fputs },
{"",			"putchar"  ,(FUNC_) imp_putchar },

////////////////////////////////////

/////////// MEM ////////////////////
{"",			"memcmp"  		,(FUNC_) memcmp },
{"",			"memmove"  		,(FUNC_) memmove },
{"",			"memcpy"  		,(FUNC_) memcpy },
{"",			"memset"  		,(FUNC_) memset },
////////////////////////////////////

/////////// STRING ///////////////
{"",			"wcslen"  	,(FUNC_) wcslen_ },
//{"",			"wcstombs"  ,(FUNC_) imp_wcstombs },
{"",			"wcstombs"  ,(FUNC_) imp_wcstombs },


{"",			"isalnum"  ,(FUNC_) isalnum},
{"",			"isdigit"  ,(FUNC_) isdigit },
{"",			"tolower"  ,(FUNC_) tolower },


{"",			"strcmp"  	,(FUNC_) strcmp },
{"",			"stricmp"	,(FUNC_) stricmp },

{"",			"strcat"  	,(FUNC_) strcat },
{"",			"strchr"  	,(FUNC_) strchr },
{"",			"strcpy"  	,(FUNC_) strcpy },
{"",			"strncmp"  ,(FUNC_) strncmp },
{"",			"strtok"  	,(FUNC_) strtok },
{"",			"strtol"  	,(FUNC_) strtol },
//{"",			"time"  	,(FUNC_) time },
{"",			"strrchr"  ,(FUNC_) strrchr },
{"",			"srand"  	,(FUNC_) srand },
{"",			"atoi"  	,(FUNC_) atoi },

{"",			"strstr"  	,(FUNC_) strstr },
{"",			"memchr"  	,(FUNC_) memchr },
{"",			"strtoul"  	,(FUNC_) strtoul },



////////////////////////////////

/////////// CHAR ////////////////
{"",			"getc"  	,(FUNC_) getc },
{"",			"fgetc"  	,(FUNC_) fgetc },
{"",			"getchar"  ,(FUNC_) getchar },
{"",			"getch"  	,(FUNC_) getch },
/////////////////////////////////

/////////// MATH ////////////////
{"",			"floor"  	,(FUNC_) floor },
{"",			"pow"  		,(FUNC_) pow },
{"",			"ceil"  	,(FUNC_) ceil },
{"",			"ceil"  	,(FUNC_) ceil },
{"",			"fabs"  	,(FUNC_) fabs  }, 
{"",			"qsort"  	,(FUNC_) qsort },
{"",			"tan"  		,(FUNC_) tan },
{"",			"rand"  	,(FUNC_) rand },
{"",			"abs"  		,(FUNC_) imp_abs }, 
/////////////////////////////////

/////////// FILE ////////////////
{"",			"fopen"  	,(FUNC_) imp_fopen },
{"",			"fread"  	,(FUNC_) fread },
{"",			"fclose"  	,(FUNC_) fclose },
{"",			"fseek"  	,(FUNC_) fseek },
{"",			"ftell"  	,(FUNC_) ftell },
{"",			"rewind"  	,(FUNC_) rewind },
#endif

{"",			"GetSystemMetrics"  		,(FUNC_) sys_GetSystemMetrics },
{"",			"SystemParametersInfoA"  	,(FUNC_) sys_SystemParametersInfoA },
{"",			"SystemParametersInfoW"  	,(FUNC_) sys_SystemParametersInfoW },
{"",			"GetCursorPos"  			,(FUNC_) sys_GetCursorPos },
{"",			"GetVersionExA"  			,(FUNC_) sys_GetVersionExA },
{"",			"GetVersionExW"  			,(FUNC_) sys_GetVersionExW },
{"",			"MonitorFromPoint"  		,(FUNC_) sys_MonitorFromPoint },
{"",			"SetConsoleTextAttribute"  	,(FUNC_) sys_SetConsoleTextAttribute },
{"",			"GetMonitorInfoA"  			,(FUNC_) sys_GetMonitorInfoA },
{"",			"GetMonitorInfoW"  			,(FUNC_) sys_GetMonitorInfoW },
{"",			"AdjustWindowRect"  		,(FUNC_) sys_AdjustWindowRect },
{"",			"MapWindowPoints"  			,(FUNC_) sys_MapWindowPoints },
{"",			"PtInRect"  				,(FUNC_) sys_PtInRect },
{"",			"SetForegroundWindow"  		,(FUNC_) sys_SetForegroundWindow },
{"",			"GetDeviceCaps"  			,(FUNC_) sys_GetDeviceCaps },
{"",			"CreatePalette"  			,(FUNC_) sys_CreatePalette },
{"",			"ReleaseDC"  				,(FUNC_) sys_ReleaseDC },
{"",			"SetEvent"  				,(FUNC_) sys_SetEvent },
{"",			"SetDIBitsToDevice"  		,(FUNC_) sys_SetDIBitsToDevice },
{"",			"GetKeyboardState"  		,(FUNC_) sys_GetKeyboardState},
{"",			"SetCursor"  				,(FUNC_) sys_SetCursor},
{"",			"BeginPaint"  				,(FUNC_) sys_BeginPaint},
{"",			"EndPaint"  				,(FUNC_) sys_EndPaint},
{"",			"SelectPalette"  			,(FUNC_) sys_SelectPalette},
{"",			"RealizePalette"  			,(FUNC_) sys_RealizePalette},
{"",			"InvalidateRect"  			,(FUNC_) sys_InvalidateRect},
{"",			"DestroyWindow"  			,(FUNC_) sys_DestroyWindow},
{"",			"DeleteObject"  			,(FUNC_) sys_DeleteObject},
{"",			"KillTimer"  				,(FUNC_) sys_KillTimer},
{"",			"ChangeDisplaySettingsExA"  ,(FUNC_) sys_ChangeDisplaySettingsExA},
{"",			"GetConsoleMode"  			,(FUNC_) sys_GetConsoleMode},
{"",			"SetConsoleMode"  			,(FUNC_) sys_SetConsoleMode},
{"",			"ReadConsoleInputA"  		,(FUNC_) sys_ReadConsoleInputA},
{"",			"ReadConsoleInputW"  		,(FUNC_) sys_ReadConsoleInputW},
{"",			"PeekConsoleInputA"  		,(FUNC_) sys_PeekConsoleInputA},
{"",			"PeekConsoleInputW"  		,(FUNC_) sys_PeekConsoleInputW},
{"",			"SetConsoleCtrlHandler"  	,(FUNC_) sys_SetConsoleCtrlHandler},

{"",			"GetFullPathNameA"  		,(FUNC_) sys_GetFullPathNameA},
{"",			"GetConsoleMode"  			,(FUNC_) sys_GetConsoleMode},
{"",			"_fileno"  					,(FUNC_) imp_fileno},
{"",			"_access"  					,(FUNC_) imp_access},
{"",			"signal"  					,(FUNC_) imp_signal},
{"",			"_open"  					,(FUNC_) imp_open},
/////////////////////////////////	


};

void func_who(int id){
err_print("Out of table: %s : %s(), %d", aDummyFunc[id].DLL,  aDummyFunc[id].Who, id );
}

void* 
	Module_GetFunction(const char* _sModule, const char*  _sFunc) 
{
	unsigned int _nSize = sizeof(aTableFunc) /  sizeof(sFunc);
	for (unsigned int i=0; i < _nSize; i++) {
		if (strcmp(_sFunc, aTableFunc[i].sFuncName) == 0) {
			if(aTableFunc[i].sLib[0] == 0){ 
				//Any Lib
				{
					_printl("Found %s: --> %s [LOADED]",  _sModule, _sFunc);
					return (FARPROC)aTableFunc[i].dFunc;
				}
			}else{ 
				//Lib is specified
				if (strcmp(_sModule, aTableFunc[i].sLib) == 0) {
					_printl("Found %s: --> %s [LOADED]",  _sModule, _sFunc);
					return (FARPROC)aTableFunc[i].dFunc;
				}
			}
		}
	}

	static unsigned int current = 0;
	current++;

	warn_print("Warning, %s:  ---------   %s ",  _sModule, _sFunc);
	
	aDummyFunc[current].Who = _sFunc;
	aDummyFunc[current].DLL = _sModule;

	if (current >=  sizeof(aDummyFunc) / sizeof( aDummyFunc[0] )) {current = 0;}

   return (void*)aDummyFunc[current].dFunc;
}



#endif //EXELOADER_FuncTable_H