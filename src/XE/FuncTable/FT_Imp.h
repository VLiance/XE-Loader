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
 * FuncTable_Impl is the XE-Loader custom implementation. 
 * Main goal is to be portable which does not relying on system functions
 *
*/

//!HMODULE LoadLibraryW(LPCWSTR lpLibFileName)
inl HMODULE WINAPI imp_LoadLibraryW(LPCWSTR lpLibFileName){

	int len = wcslen_(lpLibFileName);
	byte_t aVLA[len + sizeof(fptr_t)];
	
	view_t view = {	.header=(fptr_t*)aVLA,	
					.data=(byte_t*)&aVLA[sizeof(fptr_t)] ,
					.size=len,
					};

	
	/*
	int len = wcslen_(lpLibFileName);
	char aVLA[len];
	W2CStr(aVLA, lpLibFileName,len);
	*/

	showinf("\n TODO: imp_LoadLibraryW" , "");

/*
	WStr _swFile(lpLibFileName);const char* _sFile = _swFile.ToCStr();
	showfunc("LoadLibraryW( lpLibFileName: %s )", _sFile);
	#ifdef USE_Windows_LoadLibrary
		HMODULE _ret = LoadLibraryW(lpLibFileName);
		if(!_ret){sys_GetLastError();}return _ret;
	#else
		if(strcmp(_sFile, "Dbghelp.dll") == 0){ //required for Mesa
			return (HMODULE)1; //Fake availability
		}
		return (HMODULE)AddLibrary(_sFile);
	#endif
	*/
}


//!HMODULE LoadLibraryA(LPCSTR lpLibFileName)
inl HMODULE WINAPI imp_LoadLibraryA(LPCSTR lpLibFileName){
	showfunc("LoadLibraryA( lpLibFileName: %s )", lpLibFileName);
	#ifdef USE_Windows_LoadLibrary
		HMODULE _ret = LoadLibraryA(lpLibFileName);
		if(!_ret){sys_GetLastError();}return _ret;
	#else
		return (HMODULE)Xe_AddLibrary(lpLibFileName);
		//return (HMODULE)AddLibrary("test");
	#endif
}


//!HMODULE WINAPI LoadLibraryExA (LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
//!HMODULE WINAPI LoadLibraryExW (LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
HMODULE WINAPI imp_LoadLibraryExA (LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){
	showfunc("LoadLibraryExA( lpLibFileName: %s, dwFlags: %d )", lpLibFileName, dwFlags);
	#ifdef USE_Windows_LoadLibrary
		HMODULE _ret = LoadLibraryExA(lpLibFileName, dwFlags);
		if(!_ret){sys_GetLastError();}return _ret;
	#else
		return (HMODULE)Xe_AddLibrary(lpLibFileName);
	#endif
}
HMODULE WINAPI imp_LoadLibraryExW (LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags){

	showinf("TODO imp_LoadLibraryExW", "");
/*
	WStr _swFile(lpLibFileName);const char* _sFile = _swFile.ToCStr();
	showfunc("LoadLibraryExW( lpLibFileName: %s, dwFlags: %d )", _sFile, dwFlags);
	#ifdef USE_Windows_LoadLibrary
		HMODULE _ret = LoadLibraryExW(lpLibFileName, dwFlags);
		if(!_ret){sys_GetLastError();}return _ret;
	#else
		return (HMODULE)AddLibrary(_sFile);
	#endif
	*/
	
}

//!WINBOOL WINAPI FreeLibrary (HMODULE hLibModule)
WINBOOL WINAPI imp_FreeLibrary(HMODULE hLibModule){
	#ifdef USE_Windows_LoadLibrary
		WINBOOL _ret = FreeLibrary(hLibModule);
		if(!_ret){sys_GetLastError();}return _ret;
	#else
		return true; //TODO free lib?
	#endif
}

//!FARPROC GetProcAddress(HMODULE hModule,LPCSTR  lpProcName)
FARPROC WINAPI  imp_GetProcAddress(  HMODULE hModule, LPCSTR  lpProcName){
	showfunc("GetProcAddress( hModule: %p, lpProcName: %s)",hModule, lpProcName);
	#ifdef USE_Windows_GetProcAddress
		return GetProcAddress(hModule, lpProcName);
	#else
		char* _sDllName = (char*)"unknow";
	//	bool bOurLib = is_in_aLibList((MEMORYMODULE*)hModule);
		bool bOurLib = aModule(contain, (XE_Module*)hModule);

		FARPROC _func = 0;
		if(bOurLib){
			info_print("Module: %s [%s]", ((XE_Module*)hModule)->file.path, lpProcName);
			MEMORYMODULE* handle = ((XE_Module*)hModule)->handle;
			
			PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(handle, IMAGE_DIRECTORY_ENTRY_EXPORT);
			if(directory != 0){
				if ( directory->Size == 0) {
					 err_print("no export table found" );
				}
				//PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) ( handle->codeBase + directory->VirtualAddress);
				//_sDllName =  (char*) ( handle->codeBase + exports->Name);
				_sDllName =  ((XE_Module*)hModule)->name;
			}
			_func =  MemGetProcAddress(handle, lpProcName);
		}
		if(_func != 0){
			_printl( "GetLibAddress[%s] --> %s() ...", _sDllName, lpProcName);
			return _func;
		}else{
			_printl("GetTableAddress[%s] --> %s() ...", _sDllName, lpProcName);
			// malloc name to keep track of it ///
			//TODO free it at end of Exeloading
			char* _newName = _mallocpy(lpProcName, strlen(lpProcName)+1, char);
			return MyMemoryDefaultGetProcAddress(0, _newName); //Look in our function table
		}
	#endif
}

void * imp_memset ( void * ptr, int value, size_t num ){
	printf("\n Memest!\n ");
	printf("\n -Memest!\n ");
	printf("\n -Memest!\n ");
	return 0;
}


/*
//!VOID imp_chkstk(DWORD size)
static void* ntdll = 0;
typedef ULONG  (*funcPtr_chkstk)();
static funcPtr_chkstk _func = 0;
//https://metricpanda.com/rival-fortress-update-45-dealing-with-__chkstk-__chkstk_ms-when-cross-compiling-for-windows/
//https://stackoverflow.com/questions/52406183/mingw-stack-size-reserved-or-committed
 //WINIWE: https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/signal_i386.c

//This issue was not only due to ntdll.dll. Potentially it could be on "large-address-aware" with JIT.I have missed to consider the case that JIT memory pool would not be within 2GB area.
ULONG imp_chkstk(){
	//Windows pages in extra stack for your thread as it is used. At the end of the stack, there is one guard page mapped as inaccessible memory -- if the program accesses it (because it is trying to use more stack than is currently mapped), there's an access violation. The OS catches the fault, maps in another page of stack at the same address as the old guard page, creates a new guard page just beyond the old one, and resumes from the instruction that caused the violation.
	//alloca is partially intrinsic function, implemented by compiler. but internally it call _alloca_probe_16 (for x86) or __chkstk(x64) for move guard page down on stack. implementation of this functions exist in alloca16.obj and chkstk.objwhich can be found in VC subfolder (where exacly depended from VC version) - you can add this obj for link process or even first convert it to lib. also in latest WDK libs - exist ntdllp.lib (not confuse with ntdll.lib) - it also containing all need for implementation ( ntdll.dll export _chkstk (for x86) and __chkstk (for x64))
	showfunc("chkstk( )", "");
	//showfunc("chkstk(size: %d)", size);
	if(ntdll == 0){
		//HMODULE _hmod = LoadLibraryA("ntdll.dll");
		HMODULE _hmod = LoadLibraryA("C:/Windows/System32/ntdll.dll");
		//HMODULE _hmod = LoadLibraryA("C:/Windows/SysWOW64/ntdll.dll");
		if(_hmod != 0){
			printf("\nLoaded");
			//_func = (funcPtr_chkstk)GetProcAddress(_hmod,"_chkstk");
			_func = (funcPtr_chkstk)GetProcAddress(_hmod,"_chkstk");
		}
	}
	if(_func != 0){
		showinf("Found chkstk: Call it %p", _func);
		return _func();
	}else{
		showinf("Error: No function 'chkstk'","");
	}
	return 0;
	//Load ntdll.dll: __chkstk
}
 */
 
 
 //!FILE * fopen ( const char * filename, const char * mode )
 FILE * imp_fopen ( const char * filename, const char * mode ){
	showfunc("fopen( filename: %p, mode: %s )", filename,mode);
	return fopen(filename, mode);
 }

 
 
 //!size_t wcstombs (char* dest, const wchar_t* src, size_t max);
 //Windows wchar_t is 16-bit & for Linux, wchar_t is 32 bit.
 size_t imp_wcstombs(char* dest, const wchar_t* src, size_t max){
// wprintf(L"\nTHE SOURCE! %c\n " ,src);
	showfunc("imp_wcstombs( dest: %p, src: %p , max: %d )", dest,src,max);
	if(!dest){ return 0;}
	
	// char* _res = W2CStr_(dest, src, max);
	 char* _res = W4CStr_(dest, (UTF32*)src, max);
	 showinf("_res: %s", dest);
	 return max;//TODO The number of bytes written to dest
	 
 }
 
//!void __cdecl _initterm(PVFV *,PVFV *);
typedef void (CDECL *__PVFV)();
inl void imp_initterm(__PVFV* ppfn,__PVFV* end){
	showfunc("_initterm( ppfn: %p, end: %p )", ppfn,end);
	do {
       __PVFV pfn =  *++ppfn;
        if (pfn){
            pfn();
        }
    } while (ppfn < end);
}

//!void __cdecl _initterm(PVFV *,PVFV *);
typedef int  (CDECL *__PIFV)();
inl int imp_initterm_e(__PIFV* ppfn,__PIFV* end){
	showfunc("_initterm_e( ppfn: %p, end: %p )", ppfn,end);
	do {
        __PIFV pfn = *++ppfn;
        if (pfn){
		int err;
            if ( err = pfn()) {
				showinf("fn error: %d", err);
				return err;
			}
        }
    } while (ppfn < end);
    return 0;
}


//!_CRTIMP char ***__cdecl __p__environ(void)
//static  char** _environ_ = 0;
char* _environ_[] = {"test1", "test2"};
inl char*** imp_p__environ(void){
	showfunc("__p__environ( )", "");
	//return &_environ; //Standard one
	return (char***)&_environ_; //Custom
}


//!void __cdecl _lock(int locknum)
inl void  imp_lock(int locknum){
	showfunc_opt("_lock( locknum: %d )", locknum);
	//_lock(locknum);
}

//!void __cdecl _unlock(int locknum)
inl void  imp_unlock(int locknum){
	showfunc_opt("_unlock( locknum: %d )", locknum);
	//_unlock(locknum);
}

//!void __set_app_type (int at)
#define _UNKNOWN_APP    0
#define _CONSOLE_APP    1
#define _GUI_APP        2
void imp_set_app_type (int at){
	switch(at){
		case _GUI_APP:showfunc("_set_app_type( at: %d [_GUI_APP] )",at);break;
		case _CONSOLE_APP:showfunc("_set_app_type( at: %d [_CONSOLE_APP] )",at);break;
		default :showfunc("_set_app_type( at: %d [_UNKNOWN_APP] )",at);break;
	}
}

// struct MSVCRT_lconv * CDECL MSVCRT_localeconv(void)
// __declspec(dllimport) int __cdecl __lconv_init (void);
//!int __lconv_init(void)
int imp_lconv_init(void){
	showfunc("__lconv_init( )", "");
	/* char Char = (char) UCHAR_MAX;
	  _lconv.int_frac_digits = Char;
	  _lconv.frac_digits = Char;
	  _lconv.p_sep_by_space = _lconv.n_sep_by_space = Char;
	  _lconv.p_cs_precedes = _lconv.n_cs_precedes = Char;
	  _lconv.p_sign_posn = _lconv.n_sign_posn = Char;*/
	return -1;
}

//!const char** __p__acmdln( void )
const char* __acmdln = "Test cmdLine";
char** imp_p__acmdln( void ){
	showfunc("p__acmdln( )","");
	//__acmdln = (char*)malloc(8192);
    return (char**)&__acmdln;
   // return &__acmdln;
}	

//!_onexit_t _onexit(_onexit_t function)
FUNC_ imp_onexit(FUNC_ _func){
	showfunc("_onexit( fn: %p )", _func);
	//TODO _onexit can have multiple functions, must be added to a list
	//https://github.com/shihyu/learn_c/blob/master/vc_lib_src/src/onexit.c
	return _func; //success?
}

//!int* __p__fmode()


#define	_O_TEXT_	0x4000	// CR-LF in file becomes LF in memory. 
#define	_O_BINARY_	0x8000	// Input and output is not translated. 
int _fmode_ = _O_TEXT_;
int* imp_p__fmode(){
	showfunc("__p__fmode( )", "");
	_fmode_ = _O_TEXT_;
	return &_fmode_;
}
#define _IOCOMMIT   0x4000
int _commode = _IOCOMMIT;
int * imp_p__commode(){
	return &_commode;
}
char *__initenv = NULL;     /* pointer to initial environment block */
int * imp_p__initenv(){
	return &_commode;
}


#ifndef _STARTUP_INFO_DEFINED
 #define _STARTUP_INFO_DEFINED
   typedef struct {
     int newmode;
   } _startupinfo;
 #endif
//!int __getmainargs(int * _Argc,char *** _Argv,char *** _Env,int _DoWildCard,_startupinfo * _StartInfo)
int imp_getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _DoWildCard, void* _StartInfo){ //_StartInfo :Other information to be passed to the CRT DLL.
	showfunc("__getmainargs( _Argc: %p, _Argv: %p, _Env: %p, _DoWildCard: %d, _StartInfo: %p )", _Argc, _Argv, _Env, _DoWildCard, _StartInfo);
	
	LPSTARTUPINFO lpStartupInfo = _StartInfo;
	lpStartupInfo->cb = sizeof(LPSTARTUPINFO);
	lpStartupInfo->lpDesktop = (LPTSTR)L"";
	lpStartupInfo->lpTitle = (LPTSTR)"";
	lpStartupInfo->dwX =0;
	lpStartupInfo->dwY =0;
	lpStartupInfo->dwXSize =0;
	lpStartupInfo->dwYSize =0;
	lpStartupInfo->dwXCountChars =0;
	lpStartupInfo->dwYCountChars =0;
	lpStartupInfo->dwFillAttribute =0;
	lpStartupInfo->dwFlags =0;
	lpStartupInfo->wShowWindow =0;
	lpStartupInfo->cbReserved2 =0;
	lpStartupInfo->lpReserved2 =0;

	lpStartupInfo->hStdInput =0;
	lpStartupInfo->hStdOutput =0;
	lpStartupInfo->hStdError =0;

	
	for(int i = 0; i < *_Argc; i++){
		showinf("arg[%d]: %s", i, (*_Argv)[i]);
	}

	*_Argc =0;
	char* envp[] = { "param0", "param1", "param2" };
	*_Env = (char**)&envp;
	//*_Env = 0;
	
	return 0;//successful
}

//!int _vscprintf(const char *format,va_list argptr)
inl int imp_vscprintf(const char *format,va_list argptr){
	showfunc_opt("_vscprintf( )", "");
    int retval = 0; 
    va_list argcopy;
    va_copy(argcopy, argptr); 
    retval = vsnprintf(NULL, 0, format, argcopy); 
    va_end(argcopy); 
    return retval;
 }


//!char *_strdup(const char *strSource)
inl char* imp_strdup(const char *strSource){
	showfunc_opt("_strdup( strSource: %s )", strSource);
	size_t size = strlen(strSource) + 1;
	char* str = (char*)malloc(size);
	if (str) {memcpy(str, strSource, size);}
	return str;
}


//!char * strncpy( char * destination, const char * source, size_t num )
inl char* imp_strncpy( char * destination, const char * source, size_t num ){
	showfunc_opt("strncpy( destination: %p, source: %p, num: %d )", destination, source, num);
	size_t i = 0;
	while(i++ != num && (*destination++ = *source++));
	return destination;
}

//!int isspace ( int c )
inl int imp_isspace( int c ){
	showfunc_opt("isspace( c %d )", c);
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'; // || whatever other char you consider space
}

//!int isupper ( int c )
inl int  imp_isupper( int c ){
	showfunc_opt("isupper( c %d )", c);
	return (c >= 'A' && c <= 'Z');
}

//!int islower ( int c )
inl int  imp_islower( int c ){
	showfunc_opt("islower( c %d )", c);
	return (c >= 'a' && c <= 'z');
}

//!int abs(int x)
inl int imp_abs(int x){
	showfunc_opt("abs( x %d )", x);
	if(x < 0){return x*-1;}return x;
}

//===== CommandLine ==== //

//!LPSTR GetCommandLineA(){
//!LPWSTR GetCommandLineW(){
LPSTR imp_GetCommandLineA(){
	showfunc("GetCommandLineA( )", "");
	#ifdef Func_Win
	return GetCommandLineA();
	#else
	//TODO Real Arg
	wchar_t* arg = (wchar_t*)L"Test ExeLoader winMain input arg";
	wchar_t* alloc = (wchar_t*)imp_LocalAlloc(0, sizeof(L"Test ExeLoader winMain input arg") ); //We must alloc with LocalAlloc because windows will call LocalFree later
	memcpy(alloc, arg, sizeof(L"Test ExeLoader winMain input arg"));
	showfunc_ret("GetCommandLineA[LPSTR: %p]", alloc);
	return (LPSTR)alloc; 
	#endif
}
LPWSTR WINAPI imp_GetCommandLineW(){
	showfunc("GetCommandLineW( )", "");
	#ifdef Func_Win
	return GetCommandLineW();
	#else
	//TODO Real Arg
	wchar_t* arg = (wchar_t*)L"Test ExeLoader winMain input arg";
	wchar_t* alloc = (wchar_t*)imp_LocalAlloc(0, sizeof(L"Test ExeLoader winMain input arg") ); //We must alloc with LocalAlloc because windows will call LocalFree later
	memcpy(alloc, arg, sizeof(L"Test ExeLoader winMain input arg"));
	showfunc_ret("GetCommandLineW[LPWSTR: %p]", alloc);
	return (LPWSTR)alloc; 
	#endif
}

//!LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine,int* pNumArgs)
inl LPWSTR* WINAPI imp_CommandLineToArgvW(LPCWSTR lpCmdLine,int* pNumArgs){
	showfunc("CommandLineToArgvW( lpCmdLine: %p, pNumArgs: %p )", lpCmdLine, pNumArgs);
	#ifdef Func_Win
	return CommandLineToArgvW(lpCmdLine, pNumArgs);
	#else
	*pNumArgs = xe_arg_nb;
	showfunc_ret("CommandLineToArgvW(pNumArgs: %d)[exe_arg:]", *pNumArgs, *xe_arg);
	//TODO convert to wide
	return (LPWSTR*)xe_arg;
	#endif
}

//============ //

//!int snprintf ( char * s, size_t n, const char * format, ... )
inl int  imp_snwprintf( wchar_t* s, size_t n, const wchar_t* format, ... ){
	showfunc_opt("snwprintf( s: %p, n: %d, format: %p, ... )", s,n,format); 
/*
	size_t len = wcslen(format);
	printf("\nlength: %d \n", len);
	printf("\nlsize_t: %d \n", n);
	
	/////////////// UTF16 to UTF8 ///////////////
	const UTF16* input = (const UTF16*)format;
	UTF8* output = (UTF8*)malloc(len+1);//+1 for null terminating char
	
	UTF8* outStart = (UTF8*)output;
	ConversionResult res =	ConvertUTF16toUTF8(&input, &input[len], &output, &output[n], ConversionFlags::lenientConversion);
	//Possible value of res: conversionOK || sourceExhausted || targetExhausted
	*output = 0; //Terminate string
	/////////////////////////////////////////////
	//free(output);

	vswprintf_ARG(format, s, n, ret);
	//wprintf(L"TEST: %s", s);
	return  ret;
	*/
	return 0;
}



//!int fwprintf (FILE* stream, const wchar_t* format, ...)
inl int imp_fwprintf (FILE* stream, const wchar_t* format, ...){
	showfunc("fwprintf( stream: %p, format: %p, ... )", stream, format); 
	
	wchar_t BUFFER[8192]; //TODO GLOBAL BUFF or malloc?
	vswprintf_ARG(format, BUFFER, 8192, ret);
	
	#ifndef No_wprintf
	//Convert to cstr?
	wprintf(BUFFER);
	#else
	showinf("[No wprintf]", "");
	#endif
	return ret;
}

//copy d:
//gdb cpcldr
//set arg nogui
//r
//sys /debug = 2
//sys /debug /cpinticore = p1
//exe/ /win32 blend2.exe


//!int vsnprintf (char * __restrict__ __stream, size_t __n, const char * __restrict__ __format, va_list __local_argv);
int imp_vsnprintf (char* s, size_t n, const char *  format, va_list __local_argv){
	/*
	showfunc("vsnprintf( s: %u, n: %d, format: %s, ... )", s,n,format); 
	
	static int count = 0;
	count++;
	if(n == 4048){
		printf("\nhere");
	}
	
	return vsnprintf(s, n, format, __local_argv);
	*/
	
	showfunc_opt("vsnprintf( s: %p, n: %u, format: %s, ... )  --  %u", s, n, format);
	#ifdef USE_limit_on_vsnprintf
	if(n > USE_limit_on_vsnprintf) n = USE_limit_on_vsnprintf;
	#endif
	/*
	if(strcmp(format, "#version %I64i%s%s") == 0)
	{
		format = "#version %llu%s%s";
		showfunc("CORRECTED : vsnprintf( s: %p, n: %u, format: %s, ... )", s, n, format);
	}
	*/
	return vsnprintf(s, n, format, __local_argv);
}

//!UINT ___lc_codepage_func(void)
UINT imp_lc_codepage_func(void){
	showfunc_opt("___lc_codepage_func( )", ""); 
	return 0; //TODO validate?
}

//!int _stricmp(const char *string1,const char *string2)
int imp_stricmp(const char *string1,const char *string2){
	showfunc_opt("_stricmp( string1: %p, string2: %p )", ""); 
	return stricmp(string1, string2);
}


//vswprintf_ARG(format, dest, max, ret)va_list _arg_;va_start (_arg_, format);int ret = vswprintf((wchar_t*)dest, max, format, _arg_);va_end (_arg_);

//!int fprintf ( FILE * stream, const char * format, ... )
//int imp_fprintf( FILE* stream, const char* format, va_list __local_argv){
int imp_fprintf( FILE* stream, const char* format, ...){
	showfunc_opt("fprintf( stream: %p, format: %s, ... )", stream,format); 
	va_list _arg_;va_start (_arg_, format);

	#ifdef USE_PRINTF
	int ret = vprintf(format, _arg_);
	#else
	
	//TODO optimise & size check
	char BUFFER[4096] = {0};
	int ret = 0;
	va_list arg;
	va_start (arg, format);
		 ret = vsprintf (BUFFER, format, arg);
	va_end (arg);
	showinf("O> %s", BUFFER);
	#endif
	
	va_end (_arg_);
	return ret;
}

//!int printf ( const char * format, ... )
//int imp_printf( const char* format, va_list __local_argv){
int imp_printf( const char* format, ...){
	showfunc_opt("printf( stream: %p, format: %s, ... )",format); 
	va_list _arg_;va_start (_arg_, format);
	#ifdef USE_PRINTF
	int ret = printf(_arg_);
	#else
	
	//TODO optimise & size check
	char BUFFER[4096] = {0};
	va_list arg;
	va_start (arg, format);
		int ret = vsprintf (BUFFER, format, arg);
	va_end (arg);
	showinf("O> %s", BUFFER);
	
	#endif
	va_end (_arg_);
	return ret;
}

//!size_t fwrite ( const void * ptr, size_t size, size_t count, FILE * stream )
size_t imp_fwrite( const void * ptr, size_t size, size_t count, FILE * stream ){
	showfunc_opt("fwrite( ptr: %p, size: %d, count: %d, stream: %p )", ptr,size, count, stream); 
	return fwrite(ptr,size, count, stdout);
	//printf("%s", _char);
}

//int fflush ( FILE * stream )
int imp_fflush( FILE * stream ){
	showfunc("fflush( stream: %p )", stream); 
	return 0;
}

//!int fputc(int char, FILE *stream)
int imp_fputc(int _char, FILE *stream){
	showfunc_opt("fputc( _char: %d, stream: %p, ... )", _char,stream); 
	printf("%c", _char);
	return _char;
}

//!int putc(int char, FILE *stream)
int imp_putc(int _char, FILE *stream){
	showfunc_opt("putc( _char: %d, stream: %p, ... )", _char,stream); 
	printf("%c", _char);
	return _char;
}
//!int putchar ( int character )
int imp_putchar( int _char ){
	showfunc_opt("putc( character: %c )", _char); 
	printf("%c", _char);
	return _char;
}

//!int puts ( const char * str )
int imp_puts( const char * str ){
	showfunc_opt("puts( _char: %s )", str); 
	return printf(str);
}

//!int fputs ( const char * str, FILE * stream )
int imp_fputs ( const char * str, FILE * stream ){
	showfunc_opt("puts( _char: %s, stream: %p)", str, stream); 
	return printf(str);
}

//!int sprintf ( char * str, const char * format, ... )
int imp_sprintf( char * str, const char * format, va_list __local_argv){
	showfunc_opt("sprintf( s: %p, format: %p, ... )", str,format); 
	return sprintf(str, format, __local_argv);
}

//!int sprintf ( char * str, const char * format, ... )
int imp_snprintf( char * str, size_t n, const char * format, va_list __local_argv){
	showfunc_opt("snprintf( s: %p, format: %p, ... )", str,format); 
	return snprintf(str, n, format, __local_argv);
}

//!int* CDECL _errno(void )
static int _errno_ = 0;
int* imp_errno(void ){
	showfunc_opt("errno()", ""); 
	//  return &(msvcrt_get_thread_data()->thread_errno);
	return &_errno_;
}
//!intptr_t _get_osfhandle(int fd)
#ifndef EBADF
#define EBADF            9      /* Bad file number */
#endif
intptr_t imp_get_osfhandle(int fd){
	showfunc("_get_osfhandle( fd: %d )", fd); 
	//File descriptor 0 stdint, 1 stdout, 2 strerr
	//If execution is allowed to continue, it returns INVALID_HANDLE_VALUE (-1). It also sets errno to EBADF, indicating an invalid file handle.
	return -1;
}

//!long _lseek(int fd,long offset,int origin)
long imp_lseek(int fd,long offset,int origin){
	showfunc_opt("_lseek( fd: %d, offset: %d, origin: %d )", fd, offset, origin); 
	//File descriptor 0 stdint, 1 stdout, 2 strerr
	//If execution is allowed to continue, these functions set errno to EBADF and return -1L.
	return ((long)-1);
}


//!int _write(int fd,const void *buffer, unsigned int count)
int imp_write(int fd,const void* buffer, unsigned int count){
	showfunc_opt("_write( fd: %d, buffer: %p, count: %d )", fd, buffer, count);
	int _bytes = printf ("%.*s\n",count, buffer)-1;
	if(_bytes > count){_bytes = count;}
	return _bytes;
	
}

//!int _isatty( int fd )
int imp_isatty( int fd ){
	showfunc_opt("isatty( fd: %d)", fd);
	//_isatty returns a nonzero value if the descriptor is associated with a character device. Otherwise, _isatty returns 0.
	return 1;
}


//!void __register_frame(void*)
void imp_register_frame(void* ptr){	//!__USING_SJLJ_EXCEPTIONS__
	// libgcc defines the __register_frame function to dynamically register new
	// dwarf frames for exception handling. This functionality is not portable
	// across compilers and is only provided by GCC. We use the __register_frame
	// function here so that code generated by the JIT cooperates with the unwinding
	// runtime of libgcc. When JITting with exception handling enable, LLVM
	// generates dwarf frames and registers it to libgcc with __register_frame.
	showfunc_opt("__register_frame( ptr: %p)", ptr);
}
//!void __deregister_frame(void*)	
void imp_deregister_frame(void* ptr){
	showfunc_opt("__deregister_frame( ptr: %p)", ptr);
}


//!int _open(const char *filename,int oflag [,int pmode])
int imp_open(const char *filename,int oflag,int pmode){
	showfunc("_open( filename: %s, oflag: d, pmode: %d)", filename,oflag,pmode);
	return -1;//error
}

//!void abort (void)
void imp_abort (void){
	showfunc("abort", "");
	fn void GDB_Func_Break();
	GDB_Func_Break();
	showfunc("Try Continuing...", "");
	return;
}

//! int __cdecl _isctype(int _C,int _Type)
int imp_isctype(int _C,int _Type){
	showfunc("_isctype( _C: %d, _Type: %d)", _C, _Type);
	//return _isctype(_C, _Type);
	return 1; //or 0?
}

//!size_t strlen ( const char * str )
int imp_strlen(const char * str ){
	showfunc("strlen( str: %s)", str);
	if(str == 0){ //Std will not check for null ptr!
		err_print("strlen on null ptr!");
		return 0;
	}
	return strlen(str);
}

/*
LPVOID WINAPI LocalLock (HLOCAL hMem);
SIZE_T WINAPI LocalShrink (HLOCAL hMem, UINT cbNewSize);
SIZE_T WINAPI LocalCompact (UINT uMinFree);
UINT WINAPI LocalFlags (HLOCAL hMem);
HLOCAL WINAPI LocalHandle (LPCVOID pMem);
WINBOOL WINAPI LocalUnlock (HLOCAL hMem);
*/