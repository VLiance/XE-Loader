
hdl_t Create_context(ContextInf _ctx){
	//aContext_count++; //Important: Skip the zero index (NULL)
	aContext_count++; //Important: Skip the zero index (NULL)
	hdl_t idx = aContext_count;
	
	aContext[idx] = _ctx;
	
	aContext[idx].idx = idx;
	//aContext[idx].width = nWidth;
	//aContext[idx].height = nHeight;
	
	#ifdef ShowPixView
	aContext[idx].hwnd_View = pixView_createWindow(&aContext[idx]);
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
	return (hdl_t)idx;
}

ContextInf* Blit_context(uint32_t _idx, const void* _pixels, int _SrcWidth){ //TODO more flexible param
	
	_printl("!Blit_context ");

	#ifdef ShowPixView
		// aContext[idx].width & SrcWidth may differ (+32pix for depth buffer?)
		pixView_MakeSurface(&aContext[_idx]);
		uint32_t* pix_src = (uint32_t*)_pixels;
		uint32_t* pix_dest = (uint32_t*)aContext[_idx].pixels;
		
		int off_x = aContext[_idx].off_x;
		int off_y = aContext[_idx].off_y;
		
		for(int y = 0; y <  aContext[_idx].height; y++){
			memcpy(pix_dest + off_x + ((y + off_y) * (aContext[_idx].mem_width)), pix_src + (y * _SrcWidth), aContext[_idx].width *4);
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

/*
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
*/

//////////////// MESSAGES /////////////////////

uint32_t XeGI_Get_ContextMsg(hdl_t _context){

	//aSysMsg(add,(XEGI_SysMsg){.handle=_context, .type=XEGI_Msg_(LBUTTONDOWN)});
	//aSysMsg(add,(XEGI_SysMsg){.handle=_context, .type=XEGI_Msg_(LBUTTONUP)});
	//aSysMsg(add,(XEGI_SysMsg){.handle=_context, .type=XEGI_Msg_(MOUSEMOVE), .x=MouseX, .y=MouseY });
	return 1;
}

//////////////////// THREAD //////////////

uintptr_t 
	XeGI_CreateThread(XEGI_THREAD_START_ROUTINE threadMain, uint32_t stackSize, void* threadParam)
{
    //if ( (thdl = (uintptr_t)YourFunc_CreateThread((void* (*) (void *))threadMain, stackSize,(LPVOID)threadParam))){
	//	return thdl;
	//}
  	///No thread
	_printl("Warning, no thread created");
	return 1;
}
hdl_t 
	XeGI_GetCurrentThread()
{
	return 0;
}
void 
	XeGI_EnterCriticalSection(hdl_t _handle)
{
}
void 
	XeGI_LeaveCriticalSection(hdl_t _handle)
{
}

////////////////////// FILE //////////////
//typedef struct {
//	hdl_t handle;
//	uint32_t  pos;
//	uint32_t  size;
//	char*  path;
//} XEGI_FileOp;
size_t 
	XeGI_GetFileSize(XEGI_FileOp* _file)
{
	return 0;
}
bool 
	XeGI_ReadFile(XEGI_FileOp* _file)
{
	// _file->size = XeGI_GetFileSize(_file->path)
	// _file->data = malloc _file->size
	return false;
}
bool 
	XeGI_WriteFile(XEGI_FileOp* _file)
{
	return false;
}
