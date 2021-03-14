
typedef struct {
	HBITMAP hbmp;
	HWND hwnd_View;
	void* pixels;
	int idx;
	int width;
	int height;
	int id_context; // cpcdos
} ContextInf;
extern int aContext_count;
extern ContextInf aContext[50];

HWND pixView_createWindow( HINSTANCE hInstance, ContextInf* _context);
void pixView_update(ContextInf* _context);
void pixView_MakeSurface(ContextInf* _context);	


uint32_t Create_context(ContextInf _ctx){
	aContext_count++; //Important: Skip the zero index (NULL)
	int idx = aContext_count;
	
	aContext[idx] = _ctx;
	
	aContext[idx].idx = idx;
	//aContext[idx].width = nWidth;
	//aContext[idx].height = nHeight;
	
	#ifdef ShowPixView
	aContext[idx].hwnd_View = pixView_createWindow(xe_hInstance, &aContext[idx]);
	#endif
	
	/*
	#ifdef CpcDos
	if(nWidth > 10){
		// Get ID context from cpcdos
		aContext[idx].id_context = oCpc->Create_Context(nWidth, nHeight);
		showinf("Create_Context()= idx: %d, height: %d, width: %d", idx,  aContext[idx].height,  aContext[idx].width);
	}
	#endif
	*/
	showinf("PixView= idx: %d, height: %d, width: %d", idx,  aContext[idx].height,  aContext[idx].width);
	showinf("create hwnd_View( hwnd_View: %d, idx: %d, height: %d, width: %d )", aContext[idx].hwnd_View,  idx,  aContext[idx].height,  aContext[idx].width );
	return (uint32_t)idx;
}

ContextInf* Blit_context(uint32_t _idx, const void* _pixels, int _SrcWidth){ //TODO more flexible param
	
	_printl("!Blit_context ");

	#ifdef ShowPixView
		// aContext[idx].width & SrcWidth may differ (+32pix for depth buffer?)
		pixView_MakeSurface(&aContext[_idx]);
		uint32_t* pix_src = (uint32_t*)_pixels;
		uint32_t* pix_dest = (uint32_t*)aContext[_idx].pixels;
		
		for(int y = 0; y <  aContext[_idx].height; y++){
			memcpy(pix_dest + (y * aContext[_idx].width), pix_src + (y * _SrcWidth), aContext[_idx].width *4);
		}
		
		//( aContext[idx].width & SrcWidth may differ )
		//memcpy(aContext[idx].pixels, lpBits, aContext[idx].height * aContext[idx].width *4);
		
		pixView_update(&aContext[_idx]);
		//showinf("PixView= idx: %d, height: %d, width: %d", idx,  aContext[idx].height,  aContext[idx].width);
	#endif
		/*
		#ifdef CpcDos
		if(aContext[idx].width > 10){
			aContext[idx].pixels = oCpc->Init_Get_Context_PTR(aContext[1].id_context);

			uint32_t* pix_src = (uint32_t*)lpBits;
			uint32_t* pix_dest = (uint32_t*)aContext[idx].pixels;
			
			for(int y = 0; y <  aContext[idx].height; y++){
				memcpy(pix_dest + (y * aContext[idx].width), pix_src + (y * SrcWidth), aContext[idx].width *4);
			}

			oCpc->Blitting(aContext[1].id_context);
		}	
		#endif
		*/
	return &aContext[_idx]; //number of scan lines copied
	
}


#define _(_)XEGI_Msg_##_
#define XEGI_Msg_(_)(XEGI_Msg_){XEGI_Msg_##_}
_enum_{
	_(LBUTTONDOWN),
	_(LBUTTONUP),
	_(MOUSEMOVE),
}enum_
#undef _


typedef struct {
	uint32_t handle;
	XEGI_Msg_  type;
	ptrdiff_t x;
	ptrdiff_t y;
} XEGI_SysMsg;

ARRAY(XEGI_aSysMsg, XEGI_SysMsg, 512);
// -- Instance -- //
XEGI_aSysMsg aSysMsg;
#define aSysMsg(fn, ...) XEGI_aSysMsg_##fn(&aSysMsg, ##__VA_ARGS__)
//!-----------!//

//USED?
uint32_t Sys_ProcessMsg(XEGI_SysMsg _msg){
	switch (_msg.type.val)
	{
	_case XEGI_Msg_LBUTTONDOWN:
	{
		
	}
	_case XEGI_Msg_LBUTTONUP:
	{
		
	}
	}
	return 0;
}
//USED?
uint32_t Sys_ProcessMsg_ALL(){

	for(int i = 0; i < aSysMsg.size; i++){
		Sys_ProcessMsg(aSysMsg.data[i]);
	}
	aSysMsg(reset);
	return 0;
}



//IF have longjump
#include <setjmp.h> 
#include <signal.h>

bool bSetJumpMustReturn = false; 
jmp_buf jmp_thread_owner_return; 
////

typedef uint32_t (*XEGI_THREAD_START_ROUTINE) (void* threadParam);
typedef struct {
	XEGI_THREAD_START_ROUTINE mainfunc;
	bool executed;
	uint32_t id;
	uint32_t handle;
	void* param;
	jmp_buf jump; //IF have longjump
} XEGI_Thread;

ARRAY(XEGI_aThread, XEGI_Thread, 512);
uint32_t nCurrThread =0;
// -- Instance -- //
XEGI_aThread aThread={};
#define aThread(fn, ...) XEGI_aThread_##fn(&aThread, ##__VA_ARGS__)
//!-----------!//

void 
	XeGI_ExecuteThread(XEGI_Thread* th)
{
	if(!setjmp(jmp_thread_owner_return))
	{
		bSetJumpMustReturn = true;
		//_print("Lauch thread :%d", th->id);
		th->mainfunc( th->param );
		//TODO REMOVE THREAD if ended by itself
	}
	bSetJumpMustReturn = false;
}
void 
	XeGI_ExecuteNextThread()
{
	for(int i = 0; i< aThread.size; i++){
		nCurrThread++;
		if(nCurrThread>= aThread.size){nCurrThread = 0;}
		XeGI_ExecuteThread(&aThread.data[nCurrThread]);
	}
}
uintptr_t 
	XeGI_CreateThread(XEGI_THREAD_START_ROUTINE threadMain, uint32_t stackSize, void* threadParam)
{
	uintptr_t thdl =0;
	int err =0;

	#ifdef SIMULATE_MULTI_THREAD_TO_SINGLE_WORKER_TERMINATE_ON_SLEEP
	
		XEGI_Thread* th = aThread(add,(XEGI_Thread){.id=aThread.size, .mainfunc=threadMain, .param=threadParam }); //TODO deep copy param?
		XeGI_ExecuteThread(th);
		
	#else
		#if defined(Func_Win) || defined(USE_WinThread)
		//if ( (thdl = (uintptr_t)CreateThread( (LPSECURITY_ATTRIBUTES)security,stack_size,(LPTHREAD_START_ROUTINE)start_address,(LPVOID)arglist,initflag,(LPDWORD)thrdaddr)) == (uintptr_t)0 ){
		if ( (thdl = (uintptr_t)CreateThread(0,stackSize,(LPTHREAD_START_ROUTINE)threadMain,(LPVOID)threadParam,0,0))){
			err = GetLastError();
		}
		#endif
	#endif
	return thdl;
}
void 
	XeGI_Sleep(int32_t _ms)
{
	#ifdef SIMULATE_MULTI_THREAD_TO_SINGLE_WORKER_TERMINATE_ON_SLEEP
		
		if(bSetJumpMustReturn){
			longjmp(jmp_thread_owner_return,1); //Terminate current simulated thread, return to owner
		}else{
			//Call next thread
			XeGI_ExecuteNextThread();
		}
		_Sleep(1);//Minimal sleep
	#else
		_Sleep(_ms);
	#endif
}

#ifdef ShowPixView
#include "XE/Utils/PixView.h"
#endif

 //////// ////////
////// IMPL ////////
 //////// ////////
int aContext_count = 0;
ContextInf aContext[50] = {0};
