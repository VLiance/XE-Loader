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
* FuncTable_Sys is an attempt to remake system functions, or redirect them, 
* this is a mix between FuncTable_Pipe & FuncTable_Imp
* 
* Warning: Windows WINAPI function are __stdcall instead of __cdecl. 
* __stdcall remapped function must have the EXACT same paramters and must be specified as __stdcall
*  If not, your app will likely crash when the function return.
*
*/


//!VOID WINAPI SetLastError (DWORD dwErrCode)
DWORD last_error = 0;
VOID WINAPI sys_SetLastError (DWORD dwErrCode){
	if(dwErrCode != 0){
		showfunc("SetLastError( dwErrCode: %d)", dwErrCode); 
	}
	#if defined(Func_Win) || defined(USE_Window_LastError) 
		SetLastError(dwErrCode);
	#else
	last_error = dwErrCode;
	#endif
}

//!DWORD WINAPI GetLastError (VOID)
DWORD WINAPI sys_GetLastError(VOID){
	showfunc_opt("GetLastError( )", ""); 
	#if defined(Func_Win) || defined(USE_Window_LastError) 
	DWORD error = GetLastError();
	if (error){
		LPVOID lpMsgBuf;
		DWORD bufLen = FormatMessage(	FORMAT_MESSAGE_ALLOCATE_BUFFER |
										FORMAT_MESSAGE_FROM_SYSTEM |
										FORMAT_MESSAGE_IGNORE_INSERTS,
										NULL,error,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR) &lpMsgBuf,0, NULL );
		if (bufLen){
		  LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
		//  std::string result(lpMsgStr, lpMsgStr+bufLen); //TODO
		  LocalFree(lpMsgBuf);
		//  showinf("GetLastError:%s", result.c_str());
		  showinf("TODO GetLastError:","");
		}

	}
	return error;
	#else
	 return last_error;
	#endif
}


//!WINBOOL WINAPI GetVersionExA (LPOSVERSIONINFOA lpVersionInformation)
//!WINBOOL WINAPI GetVersionExW (LPOSVERSIONINFOW lpVersionInformation)
	//DWORD dwOSVersionInfoSize;
	//DWORD dwMajorVersion;
	//DWORD dwMinorVersion;
	//DWORD dwBuildNumber;
	//DWORD dwPlatformId;
	//WCHAR szCSDVersion[128];	
WINBOOL WINAPI sys_GetVersionExA(LPOSVERSIONINFOA lpVersionInformation){
	showfunc("GetVersionExA( lpVersionInformation: %p )", lpVersionInformation);
	#ifdef Func_Win
		return GetVersionExA(lpVersionInformation);
	#else
		lpVersionInformation->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		lpVersionInformation->dwMajorVersion = 10;
		lpVersionInformation->dwMinorVersion = 0;
		lpVersionInformation->dwBuildNumber = 0;
		lpVersionInformation->dwPlatformId = 2;
		lpVersionInformation->szCSDVersion[128] = 0;
		return 1;
	#endif
}
WINBOOL WINAPI sys_GetVersionExW (LPOSVERSIONINFOW lpVersionInformation){
	showfunc("GetVersionExW( lpVersionInformation: %p)", lpVersionInformation); 
	#ifdef Func_Win
		return GetVersionExW(lpVersionInformation);
	#else
		lpVersionInformation->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		lpVersionInformation->dwMajorVersion = 10;
		lpVersionInformation->dwMinorVersion = 0;
		lpVersionInformation->dwBuildNumber = 0;
		lpVersionInformation->dwPlatformId = 2;
		lpVersionInformation->szCSDVersion[128] = 0;
		return 1;
	#endif
}

//!WINBOOL WINAPI TrackMouseEvent(LPTRACKMOUSEEVENT lpEventTrack)
WINBOOL WINAPI sys_TrackMouseEvent(LPTRACKMOUSEEVENT lpEventTrack){
	showfunc("TrackMouseEvent( lpEventTrack: %p)", lpEventTrack); 
	#ifdef Func_Win
		return TrackMouseEvent(lpEventTrack);
	#else
		return true;
	#endif
}


//!HDC GetDC(HWND hWnd)
inl HDC WINAPI sys_GetDC(HWND hWnd){
	showfunc("GetDC( lpModuleName: %p)", hWnd); 
	#ifdef Func_Win
		return GetDC(hWnd);
	#else
		return (HDC)hWnd; //HDC is same as HWND (not necessary to dissociate them)
	#endif
}

//!HWND WindowFromDC(HDC hDC)
inl WINAPI HWND pipe_WindowFromDC(HDC hDC){
	showfunc_opt("WindowFromDC( hDC:%p )",hDC);
	#ifdef Func_Win
	return WindowFromDC(hDC);
	#else
	return (HWND)hDC; //HDC is same as HWND (not necessary to dissociate them)
	#endif
}

//!HWND WINAPI CreateWindowExA(DWORD dwExStyle,LPCSTR lpClassName,LPCSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam)
HWND WINAPI sys_CreateWindowExA(DWORD dwExStyle,LPCSTR lpClassName,LPCSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam){
	showfunc("CreateWindowExA( dwExStyle: %d, lpClassName: %s, lpWindowName :%p, dwStyle: %d, X: %d, Y: %d, nWidth: %d, nHeight: %d, hWndParent: %p, hMenu: %p, hInstance: %d, lpParam: %d )",
								dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	#ifdef Func_Win
		return CreateWindowExA( dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam );
	#else
		int idx = Create_context((ContextInf){.width=nWidth, .height=nHeight});
		return (HWND)idx;
	#endif
}
//!HWND WINAPI CreateWindowExW(DWORD dwExStyle,LPCWSTR lpClassName,LPCWSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam)
HWND WINAPI pipe_CreateWindowExW(DWORD dwExStyle,LPCWSTR lpClassName,LPCWSTR lpWindowName,DWORD dwStyle,int X,int Y,int nWidth,int nHeight,HWND hWndParent,HMENU hMenu,HINSTANCE hInstance,LPVOID lpParam){
	showfunc("CreateWindowExW( dwExStyle: %d, lpClassName: %p, lpWindowName :%p, dwStyle: %d, X: %d, Y: %d, nWidth: %d, nHeight: %d, hWndParent: %p, hMenu: %p, hInstance: %d, lpParam: %d )",
								dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	#ifdef Func_Win
		return CreateWindowExW( dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam );
	#else
	
		int idx = Create_context((ContextInf){.width=nWidth, .height=nHeight});
		return (HWND)idx;
	#endif
}


//!int StretchDIBits(HDC hdc,int xDest,int yDest,int DestWidth,int DestHeight,int xSrc,int ySrc, int SrcWidth, int SrcHeight, const VOID *lpBits, const BITMAPINFO *lpbmi, UINT iUsage, DWORD rop)
int WINAPI pipe_StretchDIBits(HDC hdc,int xDest,int yDest,int DestWidth,int DestHeight,int xSrc,int ySrc, int SrcWidth, int SrcHeight, const VOID *lpBits, const BITMAPINFO *lpbmi, UINT iUsage, DWORD rop){
	showfunc("StretchDIBits( hdc: %p )", hdc);
	#ifdef Func_Win
		return StretchDIBits(hdc, xDest, yDest, DestWidth, DestHeight, xSrc, ySrc, SrcWidth, SrcHeight, lpBits, lpbmi, iUsage, rop);
	#else
		/*
		showinf("lpbmi.bmiHeader.biWidth: %d", lpbmi->bmiHeader.biWidth);
		showinf("lpbmi.bmiHeader.biHeight: %d", lpbmi->bmiHeader.biHeight);
		showinf("lpbmi.bmiHeader.biPlanes: %d", lpbmi->bmiHeader.biPlanes);
		showinf("lpbmi.bmiHeader.biBitCount: %d", lpbmi->bmiHeader.biBitCount);
		showinf("lpbmi.bmiHeader.biCompression: %d", lpbmi->bmiHeader.biCompression);
		showinf("lpbmi.bmiHeader.biSizeImage: %d", lpbmi->bmiHeader.biSizeImage);
		showinf("lpbmi.bmiHeader.biXPelsPerMeter: %d", lpbmi->bmiHeader.biXPelsPerMeter);
		showinf("lpbmi.bmiHeader.biYPelsPerMeter: %d", lpbmi->bmiHeader.biYPelsPerMeter);
		showinf("lpbmi.bmiHeader.biClrUsed: %d", lpbmi->bmiHeader.biClrUsed);
		showinf("lpbmi.bmiHeader.biClrImportant: %d", lpbmi->bmiHeader.biClrImportant);
		showinf("lpbmi.bmiColors[0].rgbBlue: %d", lpbmi->bmiColors[0].rgbBlue );
		showinf("lpbmi.bmiColors[0].rgbGreen: %d", lpbmi->bmiColors[0].rgbGreen );
		showinf("lpbmi.bmiColors[0].rgbRed: %d", lpbmi->bmiColors[0].rgbRed );
		showinf("lpbmi.bmiColors[0].rgbReserved: %d", lpbmi->bmiColors[0].rgbReserved );
		*/
		return Blit_context((size_t)hdc, lpBits, SrcWidth)->height; //->heighT: number of scan lines copied
	#endif
}


//!WINBOOL WINAPI GetClientRect(HWND hWnd,LPRECT lpRect)
//struct RECT {LONG left; LONG top;LONG right;LONG bottom;}
WINBOOL WINAPI sys_GetClientRect(HWND hWnd,LPRECT lpRect){
 	showfunc_opt("GetClientRect( hWnd: %p, lpRect: %p )", hWnd, lpRect);
	#ifdef Func_Win
		return GetClientRect(hWnd, lpRect);
	#else
		lpRect->left = 0;
		lpRect->top  = 0;
		lpRect->right  = aContext[(size_t)hWnd].width;
		lpRect->bottom = aContext[(size_t)hWnd].height;
		return true;
	#endif
}

//!WINBOOL WINAPI GetWindowRect(HWND hWnd,LPRECT lpRect)
WINBOOL WINAPI sys_GetWindowRect(HWND hWnd,LPRECT lpRect){
	showfunc_opt("GetWindowRect( hWnd: %p, lpRect: %p )", hWnd, lpRect);
	#ifdef Func_Win
		return GetWindowRect(hWnd, lpRect);
	#else
		lpRect->left = 0;
		lpRect->top  = 0;
		lpRect->right  = aContext[(size_t)hWnd].width;
		lpRect->bottom = aContext[(size_t)hWnd].height;
		return true;
	#endif
}

//!WINBOOL WINAPI TranslateMessage(CONST MSG *lpMsg)
WINBOOL WINAPI sys_TranslateMessage(CONST MSG *lpMsg){
 	showfunc_opt("TranslateMessage( lpMsg: %p )", lpMsg);
	#ifdef Func_Win
		return TranslateMessage(lpMsg);
	#else
		return true;
	#endif
}

//!LRESULT WINAPI DispatchMessageA(CONST MSG *lpMsg)
//!LRESULT WINAPI DispatchMessageW(CONST MSG *lpMsg)
WINBOOL WINAPI sys_DispatchMessageA(CONST MSG *lpMsg){
 	showfunc_opt("DispatchMessageA( lpMsg: %p )", lpMsg);
	#ifdef Func_Win
		return DispatchMessageA(lpMsg);
	#else
		return true;
	#endif
}
WINBOOL WINAPI sys_DispatchMessageW(CONST MSG *lpMsg){
 	showfunc_opt("DispatchMessageW( lpMsg: %p )", lpMsg);
	#ifdef Func_Win
		return DispatchMessageW(lpMsg);
	#else
		return 0;
	#endif
}


//!UINT WINAPI SetErrosrMode (UINT uMode)
UINT WINAPI sys_SetErrorMode(UINT uMode){
 	showfunc("SetErrorMode( uMode: %p )", uMode);
	#ifdef Func_Win
		return SetErrorMode(uMode);
	#else
		return 0;
	#endif
}



///////////////////// HERE OK
///////////////////// HERE OK
///////////////////// HERE OK
  


//!DWORD GetFileType(HANDLE hFile)
DWORD sys_GetFileType(HANDLE hFile){
	showfunc("GetFileType( hFile: %p )", hFile);
	#ifdef Func_Win
		return GetFileType(hFile);
	#else
	return 0;
	#endif
}

//!ULONGLONG NTAPI VerSetConditionMask (ULONGLONG ConditionMask, DWORD TypeMask, BYTE Condition);
ULONGLONG NTAPI sys_VerSetConditionMask (ULONGLONG ConditionMask, DWORD TypeMask, BYTE Condition){
	showfunc_opt("VerSetConditionMask( ConditionMask: %p, TypeMask: %d, Condition: %d )", ConditionMask, TypeMask, Condition);
	#ifdef Func_Win
		return VerSetConditionMask(ConditionMask, TypeMask, Condition);
	#else
		return 0;
	#endif

}

//!WINBOOL WINAPI VerifyVersionInfoW (LPOSVERSIONINFOEXW lpVersionInformation, DWORD dwTypeMask, DWORDLONG dwlConditionMask)
WINBOOL WINAPI sys_VerifyVersionInfoW (LPOSVERSIONINFOEXW lpVersionInformation, DWORD dwTypeMask, DWORDLONG dwlConditionMask){
	showfunc_opt("VerifyVersionInfoW( lpVersionInformation: %p, dwTypeMask: %d, dwlConditionMask: %d )", lpVersionInformation, dwTypeMask, dwlConditionMask);
	#ifdef Func_Win
		return VerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask);
	#else
		//If the currently running operating system satisfies the specified requirements, the return value is a nonzero value.
		return 1;
	#endif
}

//!BOOL IMAGEAPI EnumerateLoadedModules64(__in HANDLE hProcess,__in PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback,__in PVOID UserContext)
typedef BOOL (CALLBACK* PENUMLOADED_MODULES_CALLBACK64)( PCSTR ModuleName, ULONG ModuleBase, ULONG ModuleSize, PVOID UserContext);
BOOL WINAPI sys_EnumerateLoadedModules64( HANDLE hProcess, PENUMLOADED_MODULES_CALLBACK64 EnumLoadedModulesCallback, PVOID UserContext){
	showfunc_opt("EnumerateLoadedModules64( hProcess: %p, EnumLoadedModulesCallback: %p, UserContext: %p )", hProcess, EnumLoadedModulesCallback, UserContext);
	// static BOOL CALLBACK ELM_Callback(WIN32_ELMCB_PCSTR ModuleName, DWORD64 ModuleBase,ULONG ModuleSize, PVOID UserContext);
	//Just send a fake Module 
	EnumLoadedModulesCallback(0,0,0,0);

	return true;
}

//!DWORD WINAPI GetCurrentDirectoryA (DWORD nBufferLength, LPSTR lpBuffer)
//!DWORD WINAPI GetCurrentDirectoryW (DWORD nBufferLength, LPWSTR lpBuffer)
DWORD WINAPI sys_GetCurrentDirectoryA (DWORD nBufferLength, LPSTR lpBuffer){
	showfunc_opt("GetCurrentDirectoryA( nBufferLength: %d, lpBuffer: %p )", nBufferLength, lpBuffer);
	#ifdef Func_Win
		return GetCurrentDirectoryA( nBufferLength, lpBuffer);
	#else
		//If the currently running operating system satisfies the specified requirements, the return value is a nonzero value.
		return 1;
	#endif
}
DWORD WINAPI sys_GetCurrentDirectoryW (DWORD nBufferLength, LPWSTR lpBuffer){
	showfunc_opt("GetCurrentDirectoryW( nBufferLength: %d, lpBuffer: %p )", nBufferLength, lpBuffer);
	#ifdef Func_Win
		return GetCurrentDirectoryW( nBufferLength, lpBuffer);
	#else
		//return GetCurrentDirectoryW( nBufferLength, lpBuffer);//TODO
		//If the currently running operating system satisfies the specified requirements, the return value is a nonzero value.
		return 1;
	#endif
}

//!HRESULT GetDpiForMonitor(HMONITOR hmonitor, MONITOR_DPI_TYPE dpiType,UINT *dpiX,UINT *dpiY)
HRESULT sys_GetDpiForMonitor(HMONITOR hmonitor,int dpiType,UINT* dpiX,UINT* dpiY){
	showfunc("GetDpiForMonitor( hmonitor: %p, dpiType: %d, dpiX: %p,  dpiY: %p )", hmonitor, dpiType, dpiX, dpiY);
	*dpiX = 0;
	*dpiY = 0;
	return 0;
}

//!BOOL SetProcessDPIAware()
inl BOOL sys_SetProcessDPIAware(){
	showfunc("SetProcessDPIAware( )","");
	return true;
}

//!HRESULT SetProcessDpiAwareness(PROCESS_DPI_AWARENESS value)
inl HRESULT sys_SetProcessDpiAwareness(int value){
	showfunc("SetProcessDpiAwareness( value: %d )",value);
	return 0;
}

//!WINBOOL WINAPI QueryPerformanceCounter (LARGE_INTEGER *lpPerformanceCount)

WINBOOL WINAPI sys_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount){
   	showfunc_opt("QueryPerformanceCounter(lpPerformanceCount)", lpPerformanceCount);
	#ifdef Func_Win
		return QueryPerformanceCounter( lpPerformanceCount);
	#else
		static int i = 0; i++;
		if(lpPerformanceCount != 0){
			LARGE_INTEGER lpPerformanceCount_ = {(DWORD)521891041 + i};//Dummy value
			*lpPerformanceCount = lpPerformanceCount_;
		}
		return true;
	#endif
}

//!WINBOOL WINAPI QueryPerformanceFrequency (LARGE_INTEGER *lpFrequency)
WINBOOL WINAPI sys_QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency){
   	showfunc("QueryPerformanceFrequency( lpFrequency: %p )", lpFrequency);
	#ifdef Func_Win
		return QueryPerformanceFrequency( lpFrequency);
	#else
		static const LARGE_INTEGER lpFrequency_ = {8221038}; //Dummy value
		if(lpFrequency != 0){*lpFrequency = lpFrequency_;}
		return false;
	#endif
}

//!DWORD WINAPI GetTickCount (VOID)
DWORD WINAPI sys_GetTickCount(VOID){
 	showfunc("GetTickCount( )", "");
	#ifdef Func_Win
		return GetTickCount();
	#else
		return 1;//Fake
	#endif
}

//!DWORD WINAPI GetCurrentThreadId (VOID)
DWORD WINAPI sys_GetCurrentThreadId(VOID){
 	showfunc("GetCurrentThreadId( )", "");
	#ifdef Func_Win
		return GetCurrentThreadId();
	#else
		return 1;//Fake
	#endif
}

//!DWORD WINAPI GetCurrentThreadId (VOID)
DWORD WINAPI sys_GetCurrentProcessId(VOID){
 	showfunc("GetCurrentProcessId( )", "");
	#ifdef Func_Win
		return GetCurrentProcessId();
	#else
		return 1;//TODO
	#endif
}

 //!VOID WINAPI GetSystemTimeAsFileTime (LPFILETIME lpSystemTimeAsFileTime)
 VOID WINAPI sys_GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime){
	 showfunc("GetSystemTimeAsFileTime( lpSystemTimeAsFileTime: %p )", lpSystemTimeAsFileTime);
	#ifdef Func_Win
		GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
	#else
		//typedef struct _FILETIME {DWORD dwLowDateTime;DWORD dwHighDateTime;} FILETIME,*PFILETIME,*LPFILETIME;
		lpSystemTimeAsFileTime->dwLowDateTime = 1; //Fake time
		lpSystemTimeAsFileTime->dwHighDateTime = 1; //Fake time
	#endif
 }

//!LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter (LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI sys_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter){
 	showfunc("SetUnhandledExceptionFilter( lpTopLevelExceptionFilter: %p )", lpTopLevelExceptionFilter);
	#ifdef Func_Win
		return SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
	#else
		return 0;
	#endif
}


//!HANDLE WINAPI CreateEventA (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName)
//!HANDLE WINAPI CreateEventW (LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCWSTR lpName)
HANDLE WINAPI sys_CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCSTR lpName){
	showfunc("CreateEventA( lpEventAttributes: %p,  bManualReset: %d, bInitialState: %d, lpName: %s )", lpEventAttributes, bManualReset, bInitialState, lpName);
	#ifdef Func_Win
		return CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
	#else
		return 0;
	#endif
}
HANDLE WINAPI sys_CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, WINBOOL bManualReset, WINBOOL bInitialState, LPCWSTR lpName){
	showfunc("CreateEventW( lpEventAttributes: %p,  bManualReset: %d, bInitialState: %d, lpName: %p )", lpEventAttributes, bManualReset, bInitialState, lpName);
	#ifdef Func_Win
		return CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
	#else
		return 0;
	#endif
}

//!SHORT WINAPI GetKeyState(int nVirtKey)
SHORT WINAPI sys_GetKeyState(int nVirtKey){
	showfunc_opt("GetKeyState( nVirtKey: %d )", nVirtKey);
	#ifdef Func_Win
		return GetKeyState(nVirtKey);
	#else
		return 0;
	#endif
}


//!VOID WINAPI InitializeSListHead (PSLIST_HEADER ListHead)
VOID WINAPI sys_InitializeSListHead(PSLIST_HEADER ListHead){
	showfunc("InitializeSListHead( ListHead: %d )", ListHead);
	#ifdef Func_Win
		 InitializeSListHead(ListHead);
	#else
	//	 0;
	//TODO
	#endif
}
/*
  WINBASEAPI VOID WINAPI InitializeSListHead (PSLIST_HEADER ListHead);
  WINBASEAPI PSLIST_ENTRY WINAPI InterlockedPopEntrySList (PSLIST_HEADER ListHead);
  WINBASEAPI PSLIST_ENTRY WINAPI InterlockedPushEntrySList (PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry);
  WINBASEAPI PSLIST_ENTRY WINAPI InterlockedFlushSList (PSLIST_HEADER ListHead);
  WINBASEAPI USHORT WINAPI QueryDepthSList (PSLIST_HEADER ListHead);
*/

//!LPCH WINAPI GetEnvironmentStrings (VOID)
//!LPWCH WINAPI GetEnvironmentStringsW (VOID)
LPCH WINAPI sys_GetEnvironmentStrings (VOID){
	showfunc("GetEnvironmentStrings( )", "");
	#ifdef Func_Win
		return GetEnvironmentStrings();
	#else
		return 0;	//TODO (Not work!?)
	#endif
}
LPWCH WINAPI sys_GetEnvironmentStringsW (VOID){
	showfunc("GetEnvironmentStringsW( )", "");

	#ifdef Func_Win
		return GetEnvironmentStringsW();
	#else
		return 0;	//TODO (Not work!?)
	#endif
}
 //!WINBOOL WINAPI FreeEnvironmentStringsA (LPCH penv)
 //!WINBOOL WINAPI FreeEnvironmentStringsW (LPWCH penv)
 WINBOOL WINAPI sys_FreeEnvironmentStringsA (LPCH penv){
 	showfunc("FreeEnvironmentStringsA( penv: %p )", penv);
	#ifdef Func_Win
		return FreeEnvironmentStringsA(penv);
	#else
		return 0;	//TODO (Not work!?)
	#endif
 }
 WINBOOL WINAPI sys_FreeEnvironmentStringsW (LPWCH penv){
  	showfunc("FreeEnvironmentStringsW( penv: %p )", penv);
	#ifdef Func_Win
		return FreeEnvironmentStringsW(penv);
	#else
		return 0;	//TODO (Not work!?)
	#endif
 }
 
//!DWORD WINAPI GetModuleFileNameA (HMODULE hModule, LPSTR lpFilename, DWORD nSize)
//!DWORD WINAPI GetModuleFileNameW (HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
DWORD WINAPI sys_GetModuleFileNameA (HMODULE hModule, LPSTR lpFilename, DWORD nSize){
	showfunc("GetModuleFileNameA( hModule: %p, lpFilename: %s, nSize: %d )", hModule, lpFilename, nSize);
	#ifdef Func_Win
		return GetModuleFileNameA(hModule, lpFilename, nSize);
	#else
		return 0;
	#endif
}
DWORD WINAPI sys_GetModuleFileNameW (HMODULE hModule, LPWSTR lpFilename, DWORD nSize){
	showfunc("GetModuleFileNameW( hModule: %p, lpFilename: %p, nSize: %d )", hModule, lpFilename, nSize);
	#ifdef Func_Win
		return GetModuleFileNameW(hModule, lpFilename, nSize);
	#else
		return 0;
	#endif
}

//!int WINAPI GetSystemMetrics(int nIndex)
int WINAPI sys_GetSystemMetrics(int nIndex){
	showfunc("GetSystemMetrics( nIndex: %d )", nIndex);
	#ifdef Func_Win
		return GetSystemMetrics(nIndex);
	#else
		return 0;//Fail --> use custom implementation
	#endif
}

//!WINBOOL WINAPI SystemParametersInfoA(UINT uiAction,UINT uiParam,PVOID pvParam,UINT fWinIni)
//!WINBOOL WINAPI SystemParametersInfoW(UINT uiAction,UINT uiParam,PVOID pvParam,UINT fWinIni)
DWORD WINAPI sys_SystemParametersInfoA(UINT uiAction,UINT uiParam,PVOID pvParam,UINT fWinIni){
	showfunc("SystemParametersInfoA( uiAction: %p, uiParam: %s, pvParam: %d, fWinIni: %d )", uiAction, uiParam, pvParam, fWinIni);
	#ifdef Func_Win
		return SystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	#else
		return 0;
	#endif
}
DWORD WINAPI sys_SystemParametersInfoW(UINT uiAction,UINT uiParam,PVOID pvParam,UINT fWinIni){
	showfunc("SystemParametersInfoW( uiAction: %p, uiParam: %s, pvParam: %d, fWinIni: %d )", uiAction, uiParam, pvParam, fWinIni);
	#ifdef Func_Win
		return SystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	#else
		return 0;
	#endif
}

//!WINBOOL WINAPI GetCursorPos(LPPOINT lpPoint)
WINBOOL WINAPI sys_GetCursorPos(LPPOINT lpPoint){
	showfunc("GetCursorPos( lpPoint: %p )", lpPoint);
	#ifdef Func_Win
		return GetCursorPos(lpPoint);
	#else
		return false;//Fail
	#endif
}

//!HMONITOR WINAPI MonitorFromPoint(POINT pt,DWORD dwFlags)
HMONITOR WINAPI sys_MonitorFromPoint(POINT pt,DWORD dwFlags){
	showfunc("MonitorFromPoint( pt: %p, dwFlags: %d )", pt, dwFlags);
	#ifdef Func_Win
		return MonitorFromPoint(pt, dwFlags);
	#else
		return 0;//Fail
	#endif
}
//!WINBOOL WINAPI SetConsoleTextAttribute(HANDLE hConsoleOutput,WORD wAttributes)
WINBOOL WINAPI sys_SetConsoleTextAttribute(HANDLE hConsoleOutput,WORD wAttributes){
	showfunc("SetConsoleTextAttribute( hConsoleOutput: %p, wAttributes: %d )", hConsoleOutput, wAttributes);
	#ifdef Func_Win
		return SetConsoleTextAttribute(hConsoleOutput, wAttributes);
	#else
		return false;//Fail
	#endif
}

//!WINBOOL WINAPI GetMonitorInfoA(HMONITOR hMonitor,LPMONITORINFO lpmi)
//!WINBOOL WINAPI GetMonitorInfoW(HMONITOR hMonitor,LPMONITORINFO lpmi)
WINBOOL WINAPI sys_GetMonitorInfoA(HMONITOR hMonitor,LPMONITORINFO lpmi){
	showfunc("GetMonitorInfoA( hMonitor: %p, lpmi: %d )", hMonitor, lpmi);
	#ifdef Func_Win
		return GetMonitorInfoA(hMonitor, lpmi);
	#else
		return false;//Fail
	#endif
}
WINBOOL WINAPI sys_GetMonitorInfoW(HMONITOR hMonitor,LPMONITORINFO lpmi){
	showfunc("GetMonitorInfoW( hMonitor: %p, lpmi: %d )", hMonitor, lpmi);
	#ifdef Func_Win
		return GetMonitorInfoW(hMonitor, lpmi);
	#else
		return false;//Fail
	#endif
}

//!WINBOOL WINAPI AdjustWindowRect(LPRECT lpRect,DWORD dwStyle,WINBOOL bMenu)
WINBOOL WINAPI sys_AdjustWindowRect(LPRECT lpRect,DWORD dwStyle,WINBOOL bMenu){
		showfunc("AdjustWindowRect( lpRect: %p, dwStyle: %d, bMenu: %d )", lpRect, dwStyle, bMenu);
	#ifdef Func_Win
		return AdjustWindowRect(lpRect, dwStyle, bMenu);
	#else
		return false;//Fail
	#endif
}

//!int WINAPI MapWindowPoints(HWND hWndFrom,HWND hWndTo,LPPOINT lpPoints,UINT cPoints)
int WINAPI sys_MapWindowPoints(HWND hWndFrom,HWND hWndTo,LPPOINT lpPoints,UINT cPoints){
	showfunc("MapWindowPoints( hWndFrom: %p, hWndTo: %d, lpPoints: %d, cPoints: %d )", hWndFrom, hWndTo, lpPoints, cPoints);
	#ifdef Func_Win
		return MapWindowPoints(hWndFrom, hWndTo, lpPoints, cPoints);
	#else
		return 0;//Fail
	#endif
}

//!WINBOOL WINAPI PtInRect(CONST RECT *lprc,POINT pt)
WINBOOL WINAPI sys_PtInRect(CONST RECT *lprc,POINT pt){
	showfunc("PtInRect( lprc: %p, pt: %d )", lprc, pt);
	#ifdef Func_Win
		return PtInRect(lprc, pt);
	#else
		return 0;//If the specified point does not lie within the rectangle, the return value is zero.
	#endif
}

//!WINBOOL WINAPI SetForegroundWindow(HWND hWnd)
WINBOOL WINAPI sys_SetForegroundWindow(HWND hWnd){
	showfunc("SetForegroundWindow( hWnd: %p )", hWnd);
	#ifdef Func_Win
		return SetForegroundWindow(hWnd);
	#else
		return false;
	#endif
}

//!int WINAPI GetDeviceCaps(HDC hdc,int index)
int WINAPI sys_GetDeviceCaps(HDC hdc,int index){
	showfunc("GetDeviceCaps( hdc: %p, index: %d )", hdc, index);
	#ifdef Func_Win
		return GetDeviceCaps(hdc, index);
	#else
		return 0;
	#endif
}

//!HPALETTE WINAPI CreatePalette(CONST LOGPALETTE *plpal)
HPALETTE WINAPI sys_CreatePalette(CONST LOGPALETTE *plpal){
	showfunc("CreatePalette( plpal: %p )", plpal);
	#ifdef Func_Win
		return CreatePalette(plpal);
	#else
		return 0;//Fail
	#endif
}

//!WINUSERAPI int WINAPI ReleaseDC(HWND hWnd,HDC hDC)
int WINAPI sys_ReleaseDC(HWND hWnd,HDC hDC){
	showfunc("ReleaseDC( hWnd: %p, hDC: %p )", hWnd, hDC);
	#ifdef Func_Win
		return ReleaseDC(hWnd, hDC);
	#else
		return 0;//Not released
	#endif
}

//!WINBOOL WINAPI SetEvent (HANDLE hEvent)
WINBOOL WINAPI sys_SetEvent (HANDLE hEvent){
	showfunc("SetEvent( hEvent: %p )", hEvent);
	#ifdef Func_Win
		return SetEvent(hEvent);
	#else
		return false;
	#endif
}

//!int WINAPI SetDIBitsToDevice(HDC hdc,int xDest,int yDest,DWORD w,DWORD h,int xSrc,int ySrc,UINT StartScan,UINT cLines,CONST VOID *lpvBits,CONST BITMAPINFO *lpbmi,UINT ColorUse);
int WINAPI sys_SetDIBitsToDevice(HDC hdc,int xDest,int yDest,DWORD w,DWORD h,int xSrc,int ySrc,UINT StartScan,UINT cLines,CONST VOID *lpvBits,CONST BITMAPINFO *lpbmi,UINT ColorUse){
	showfunc("SetDIBitsToDevice( hdc: %p, xDest: %d, yDest %d, w: %d, h: %d, xSrc: %d, ySrc: %d, StartScan: %d, cLines: %d, lpvBits: %p, lpbmi: %p, ColorUse: %p )", hdc, xDest, yDest, w, h, xSrc, ySrc, StartScan, cLines, lpvBits, lpbmi, ColorUse);
	#ifdef Func_Win
		return SetDIBitsToDevice( hdc, xDest, yDest, w, h, xSrc, ySrc, StartScan, cLines, lpvBits, lpbmi, ColorUse);
	#else
		return false;
	#endif
}

//!WINBOOL WINAPI GetKeyboardState(PBYTE lpKeyState)
WINBOOL WINAPI sys_GetKeyboardState(PBYTE lpKeyState){
	showfunc("GetKeyboardState( lpKeyState: %p )", lpKeyState);
	#ifdef Func_Win
		return GetKeyboardState(lpKeyState);
	#else
		return false;
	#endif
}

//!HCURSOR WINAPI SetCursor(HCURSOR hCursor)
HCURSOR WINAPI sys_SetCursor(HCURSOR hCursor){
	showfunc("SetCursor( hCursor: %p )", hCursor);
	#ifdef Func_Win
		return SetCursor(hCursor);
	#else
		return false;
	#endif
}

//!HDC WINAPI BeginPaint(HWND hWnd,LPPAINTSTRUCT lpPaint)
HDC WINAPI sys_BeginPaint(HWND hWnd,LPPAINTSTRUCT lpPaint){
	showfunc("BeginPaint( hWnd: %p, lpPaint:%p )", hWnd, lpPaint);
	#ifdef Func_Win
		return BeginPaint(hWnd, lpPaint);
	#else
		return 0;
	#endif
}

//!HPALETTE WINAPI SelectPalette(HDC hdc,HPALETTE hPal,WINBOOL bForceBkgd)
HPALETTE WINAPI sys_SelectPalette(HDC hdc,HPALETTE hPal,WINBOOL bForceBkgd){
	showfunc("SelectPalette( hdc: %p, hPal:%p, bForceBkgd: %d )", hdc, hPal, bForceBkgd);
	#ifdef Func_Win
		return SelectPalette( hdc, hPal, bForceBkgd);
	#else
		return 0;
	#endif
}

//!WINGDIAPI UINT WINAPI RealizePalette(HDC hdc)
UINT WINAPI sys_RealizePalette(HDC hdc){
	showfunc("RealizePalette( hdc: %p )", hdc);
	#ifdef Func_Win
		return RealizePalette( hdc );
	#else
		return 0;
	#endif
}

//!WINBOOL WINAPI InvalidateRect(HWND hWnd,CONST RECT *lpRect,WINBOOL bErase)
WINBOOL WINAPI sys_InvalidateRect(HWND hWnd,CONST RECT *lpRect,WINBOOL bErase){
	showfunc("InvalidateRect( hWnd: %p, lpRec: %p, bErase: %d )", hWnd, lpRect, bErase );
	#ifdef Func_Win
		return InvalidateRect( hWnd, lpRect, bErase );
	#else
		return 0;
	#endif
}

//!WINBOOL WINAPI EndPaint(HWND hWnd,CONST PAINTSTRUCT *lpPaint)
WINBOOL WINAPI sys_EndPaint(HWND hWnd,CONST PAINTSTRUCT *lpPaint){
	showfunc("EndPaint( hWnd: %p, lpPaint: %p )", hWnd, lpPaint );
	#ifdef Func_Win
		return EndPaint( hWnd, lpPaint);
	#else
		return false;
	#endif
}

//!WINBOOL WINAPI DestroyWindow(HWND hWnd)
WINBOOL WINAPI sys_DestroyWindow(HWND hWnd){
	showfunc("DestroyWindow( hWnd: %p )", hWnd );
	#ifdef Func_Win
		return DestroyWindow( hWnd);
	#else
		return false;
	#endif
}

//!WINBOOL WINAPI DeleteObject(HGDIOBJ ho)
WINBOOL WINAPI sys_DeleteObject(HGDIOBJ ho){
	showfunc("DeleteObject( ho: %p )", ho );
	#ifdef Func_Win
		return DeleteObject( ho);
	#else
		return false;
	#endif
}

//!WINBOOL WINAPI KillTimer(HWND hWnd,UINT_PTR uIDEvent)
WINBOOL WINAPI sys_KillTimer(HWND hWnd,UINT_PTR uIDEvent){
	showfunc("KillTimer( hWnd: %p, uIDEvent: %p )", hWnd, uIDEvent );
	#ifdef Func_Win
		return KillTimer( hWnd, uIDEvent);
	#else
		return false;
	#endif
}

//!LONG WINAPI ChangeDisplaySettingsExA(LPCSTR lpszDeviceName,LPDEVMODEA lpDevMode,HWND hwnd,DWORD dwflags,LPVOID lParam)
LONG WINAPI sys_ChangeDisplaySettingsExA(LPCSTR lpszDeviceName,LPDEVMODEA lpDevMode,HWND hwnd,DWORD dwflags,LPVOID lParam){
	showfunc("ChangeDisplaySettingsExA( lpszDeviceName: %p, lpDevMode: %p,dwflags: %p, lParam: %p )", lpszDeviceName, lpDevMode, hwnd, dwflags, lParam);
	#ifdef Func_Win
		return ChangeDisplaySettingsExA( lpszDeviceName, lpDevMode, hwnd, dwflags, lParam);
	#else
		return 0;
	#endif
}
//!WINBASEAPI WINBOOL WINAPI GetConsoleMode(HANDLE hConsoleHandle,LPDWORD lpMode)
WINBOOL WINAPI sys_GetConsoleMode(HANDLE hConsoleHandle,LPDWORD lpMode){
	showfunc("GetConsoleMode( hConsoleHandle: %p, lpMode: %d )", hConsoleHandle, lpMode );
	#ifdef Func_Win
		return GetConsoleMode( hConsoleHandle, lpMode);
	#else
		return false;
	#endif
}
//!WINBASEAPI WINBOOL WINAPI SetConsoleMode(HANDLE hConsoleHandle,DWORD dwMode)
WINBOOL WINAPI sys_SetConsoleMode(HANDLE hConsoleHandle,DWORD dwMode){
	showfunc("SetConsoleMode( hConsoleHandle: %p, dwMode: %d )", hConsoleHandle, dwMode );
	#ifdef Func_Win
		return SetConsoleMode( hConsoleHandle, dwMode);
	#else
		return false;
	#endif
}

//!WINBASEAPI WINBOOL WINAPI PeekConsoleInputA(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead);
//!WINBASEAPI WINBOOL WINAPI PeekConsoleInputW(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead);
WINBOOL WINAPI sys_PeekConsoleInputA(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead){
	showfunc("PeekConsoleInputA( hConsoleInput: %p, lpBuffer: %d, nLength: %d, lpNumberOfEventsRead: %p )", hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	#ifdef Func_Win
		return PeekConsoleInputA( hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead );
	#else
		return false;
	#endif
}
WINBOOL WINAPI sys_PeekConsoleInputW(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead){
	showfunc("PeekConsoleInputA( PeekConsoleInputW: %p, lpBuffer: %d, nLength: %d, lpNumberOfEventsRead: %p )", hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	#ifdef Func_Win
		return PeekConsoleInputW( hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead );
	#else
		return false;
	#endif
}

//!WINBASEAPI WINBOOL WINAPI ReadConsoleInputA(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead)
//!WINBASEAPI WINBOOL WINAPI ReadConsoleInputW(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead)
WINBOOL WINAPI sys_ReadConsoleInputA(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead){
	showfunc("ReadConsoleInputA( hConsoleInput: %p, lpBuffer: %d, nLength: %d, lpNumberOfEventsRead: %p )", hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	#ifdef Func_Win
		return PeekConsoleInputA( hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead );
	#else
		return false;
	#endif
}
WINBOOL WINAPI sys_ReadConsoleInputW(HANDLE hConsoleInput,PINPUT_RECORD lpBuffer,DWORD nLength,LPDWORD lpNumberOfEventsRead){
	showfunc("sys_ReadConsoleInputW( hConsoleInput: %p, lpBuffer: %d, nLength: %d, lpNumberOfEventsRead: %p )", hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead);
	#ifdef Func_Win
		return sys_ReadConsoleInputW( hConsoleInput, lpBuffer, nLength, lpNumberOfEventsRead );
	#else
		return false;
	#endif
}

//!WINBASEAPI WINBOOL WINAPI SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine,WINBOOL Add)
WINBOOL WINAPI sys_SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine,WINBOOL Add){
	showfunc("SetConsoleCtrlHandler( HandlerRoutine: %p, Add: %d )", HandlerRoutine, Add );
	#ifdef Func_Win
		return SetConsoleCtrlHandler( HandlerRoutine, Add);
	#else
		return false;
	#endif
}

//!WINBASEAPI DWORD WINAPI GetFullPathNameA (LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart)
DWORD WINAPI sys_GetFullPathNameA (LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart){
	showfunc("GetFullPathNameA( lpFileName: %p, nBufferLength: %d, lpBuffer: %p, lpFilePart: %p )", lpFileName, nBufferLength, lpBuffer, lpFilePart );
	#ifdef Func_Win
		return GetFullPathNameA( lpFileName, nBufferLength, lpBuffer, lpFilePart );
	#else
		return 0;
	#endif
}

//!WINBASEAPI DWORD WINAPI GetTempPathA (DWORD nBufferLength, LPSTR lpBuffer)
//!WINBASEAPI DWORD WINAPI GetTempPathW (DWORD nBufferLength, LPWSTR lpBuffer)
DWORD WINAPI  sys_GetTempPathA (DWORD nBufferLength, LPSTR lpBuffer){
	showfunc("GetTempPathA( nBufferLength: %d, lpBuffer: %p )", nBufferLength, lpBuffer );
	#ifdef Func_Win
		return GetTempPathA( nBufferLength, lpBuffer);
	#else
		const char path_temp[] = "C:\\Windows\\TEMP\\";
		if(nBufferLength >= sizeof(path_temp)){
			_memcpy(lpBuffer, path_temp, sizeof(path_temp));
		}
		return sizeof(path_temp); //If the return value is greater than nBufferLength, the return value is the length, in TCHARs, of the buffer required to hold the path.
	#endif
}
DWORD WINAPI  sys_GetTempPathW (DWORD nBufferLength, LPWSTR lpBuffer){
	showfunc("GetTempPathW( nBufferLength: %d, lpBuffer: %d )", nBufferLength, lpBuffer );
	#ifdef Func_Win
		return GetTempPathW( nBufferLength, lpBuffer);
	#else
		const wchar_t* path_temp = L"C:\\TEMP\\";
		_memcpy(lpBuffer, path_temp, sizeof(path_temp));
		return sizeof(path_temp);
	#endif
}


//!WINBASEAPI HANDLE WINAPI CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
//!WINBASEAPI HANDLE WINAPI CreateFileW (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
HANDLE WINAPI sys_CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile){
 	showfunc("CreateFileA( lpFileName: %s, dwDesiredAccess: %d, dwShareMode: %d, lpSecurityAttributes: %p, dwCreationDisposition: %d, dwFlagsAndAttributes: %d, hTemplateFile: %p )", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );
	#ifdef Func_Win
		return CreateFileA(  lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );
	#else
		return 0;
	#endif
 }

//!WINBASEAPI WINBOOL WINAPI CreateProcessA (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
//!WINBASEAPI WINBOOL WINAPI CreateProcessW (LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
WINBOOL WINAPI sys_CreateProcessA (LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation){
	showfunc("CreateProcessA( lpApplicationName: %s, lpCommandLine: %s, lpProcessAttributes: %p, lpThreadAttributes: %p, bInheritHandles: %p, dwCreationFlags: %d, lpEnvironment: %p, lpCurrentDirectory: %p, lpStartupInfo: %p, lpProcessInformation: %p )", lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation );
	#ifdef Func_Win
		bool ret =  CreateProcessA( lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation );
	#else
		bool ret = false ;
	#endif
	showinf("ret: %d", ret);
	return ret;
}

//!WINBASEAPI WINBOOL WINAPI GetExitCodeProcess (HANDLE hProcess, LPDWORD lpExitCode)
WINBOOL WINAPI sys_GetExitCodeProcess (HANDLE hProcess, LPDWORD lpExitCode) {
 	showfunc("GetExitCodeProcess( hProcess: %p, lpExitCode: %p )", hProcess, lpExitCode);
	#ifdef Func_Win
		bool ret = GetExitCodeProcess( hProcess, lpExitCode );
	#else
		bool ret = false ;
	#endif
	showinf("ret: %d, *lpExitCode: %d", ret,  *lpExitCode);
	return ret;
}

//!WINBASEAPI WINBOOL WINAPI GlobalMemoryStatusEx (LPMEMORYSTATUSEX lpBuffer)
typedef struct _MEMORYSTATUSEX_ {
  DWORD     dwLength;
  DWORD     dwMemoryLoad;
  DWORDLONG ullTotalPhys;
  DWORDLONG ullAvailPhys;
  DWORDLONG ullTotalPageFile;
  DWORDLONG ullAvailPageFile;
  DWORDLONG ullTotalVirtual;
  DWORDLONG ullAvailVirtual;
  DWORDLONG ullAvailExtendedVirtual;
} _MEMORYSTATUSEX_, *LPMEMORYSTATUSEX_;
 WINBOOL WINAPI sys_GlobalMemoryStatusEx (LPMEMORYSTATUSEX_ lpBuffer){
	showfunc("GlobalMemoryStatusEx( lpBuffer: %p )", lpBuffer);
	#ifdef Func_Win
		return GlobalMemoryStatusEx((LPMEMORYSTATUSEX)lpBuffer );
	#else
	
		return true;
	#endif
}



