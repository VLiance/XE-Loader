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
* Some utils function to view pixels from memory, 
* we need to create window to view visually the memory
*
*/

float pixView_mouse_x  = 0;  //FIXME: AtomicInt
float pixView_mouse_y  = 0;	 //FIXME: AtomicInt
bool bLButtonDown  = false;  //FIXME: AtomicBool
 
#ifdef USE_Transparent_PixView
	#define WIN_BORDER_T 20
	#define WIN_BORDER_L 5
	#define WIN_BORDER_R WIN_BORDER_L
	#define WIN_BORDER_B WIN_BORDER_L
	
#else
	#define WIN_BORDER_T 0
	#define WIN_BORDER_L 0
	#define WIN_BORDER_R WIN_BORDER_L
	#define WIN_BORDER_B WIN_BORDER_L
#endif 

#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp)    ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)    ((int)(short)HIWORD(lp))
#endif 

LRESULT CALLBACK WndProc( HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam){
	uint32_t h = (uint32_t)hwnd;

  switch ( msg ) {
    case WM_CREATE:
      {
       // MakeSurface( hwnd );
      }
      break;
	  
 case WM_SYSCOMMAND :
      {
			switch ( (int)wParam ) {
			case SC_RESTORE:{
				//TODO
			  }
			  break;
		}
      }
      break;
	  
  case WM_LBUTTONDOWN:
		aSysMsg(add,(XEGI_SysMsg){.handle=h, .type=XEGI_Msg_(LBUTTONDOWN)});
		bLButtonDown = true;
		break;
	case WM_LBUTTONUP:
		aSysMsg(add,(XEGI_SysMsg){.handle=h, .type=XEGI_Msg_(LBUTTONUP)});
		bLButtonDown = false;
		break;
				
	case WM_MOUSEMOVE:{
		aSysMsg(add,(XEGI_SysMsg){.handle=h, .type=XEGI_Msg_(MOUSEMOVE), .x=GET_X_LPARAM(lParam), .y=GET_Y_LPARAM(lParam) });
		pixView_mouse_x = (float)GET_X_LPARAM(lParam);
		pixView_mouse_y = (float)GET_Y_LPARAM(lParam);
	 }
			 
    case WM_PAINT:
      {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint( hwnd, &ps );
		//BitBlt( hdc, 0, 0, width, height, hdcMem, 0, 0, SRCCOPY );
        EndPaint( hwnd, &ps );
      }
      break;
    case WM_CLOSE:
      {
        DestroyWindow( hwnd );
      }
      break;
    case WM_DESTROY:
      {
        PostQuitMessage( 0 );
      }
      break;
  }
	return DefWindowProc( hwnd, msg, wParam, lParam );
}

ContextInf* upd_pixview = 0;
bool bTh_Surface_ready = false;

static void draw_square(uint32_t _color, uint32_t* _pix, int _lsize, int _posx, int _posy, int _width, int _height, int inc){
	int y = _height-1;
	for(int x = 0; x <  _width;  x+=inc)	{_pix[_posx+x+((_posy+0) *_lsize)]			= _color;}
	for(int x = 0; x <  _width;  x+=inc) 	{_pix[_posx+x+((_posy+y) * _lsize)] 		= _color;}
	for(y = 0; y 	 <  _height; y+=inc)	{_pix[_posx+0+((_posy+y) * _lsize)] 		= _color;}
	for(y = 0; y 	 <  _height; y+=inc)	{_pix[_posx+_width-1+((_posy+y) * _lsize)] 	= _color;}
}

void pixView_MakeSurface(ContextInf* _context){
	HWND _hwnd = (HWND)_context->hwnd_View;
	
	BITMAPINFO bmi;
	bmi.bmiHeader.biSize = sizeof(BITMAPINFO);
	bmi.bmiHeader.biWidth =		_context->mem_width;
	bmi.bmiHeader.biHeight =  -(_context->mem_height); //Order pixels from top to bottom
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32; //last byte not used, 32 bit for alignment
	bmi.bmiHeader.biCompression = BI_RGB;
	bmi.bmiHeader.biSizeImage = 0;
	bmi.bmiHeader.biXPelsPerMeter = 0;
	bmi.bmiHeader.biYPelsPerMeter = 0;
	bmi.bmiHeader.biClrUsed = 0;
	bmi.bmiHeader.biClrImportant = 0;
	bmi.bmiColors[0].rgbBlue = 0;
	bmi.bmiColors[0].rgbGreen = 0;
	bmi.bmiColors[0].rgbRed = 0;
	bmi.bmiColors[0].rgbReserved = 0;

	HDC hdc = GetDC( _hwnd );
	if(_context->hbmp != 0){
		DeleteObject(_context->hbmp );
	}
	_context->hbmp = CreateDIBSection( hdc, &bmi, DIB_RGB_COLORS, (void**)&_context->pixels, NULL, 0 );
	//DeleteDC( hdc );
///////////////
	ReleaseDC(_hwnd,  hdc );
	
	#ifndef USE_Transparent_PixView
	return;
	#endif
	
	//!Transparent!//
	//Clear
	_memset(_context->pixels, 0xFF, _context->mem_width*_context->mem_height*4 );

	//Border
	draw_square(0xFF555555,  _context->pixels,_context->mem_width, 0,0, _context->mem_width, _context->mem_height,1);
	draw_square(0xFFCCCCCC,  _context->pixels,_context->mem_width, 2,2, _context->mem_width-2, 1,3);
	draw_square(0xFFAAAAAA,  _context->pixels,_context->mem_width, _context->off_x-1,_context->off_y-1, _context->width+2, _context->height+2,1);
	
	//Minimise
	draw_square(0xFF444455,  _context->pixels,_context->mem_width, _context->mem_width-90,6, 12, 3,1);
	
	//Maximise
	draw_square(0xFFAAAAAA,  _context->pixels,_context->mem_width, _context->mem_width-55,2, 10, 10,2);
	draw_square(0xFF444455,  _context->pixels,_context->mem_width, _context->mem_width-60,5, 10, 10,1);
	
	//Close
	draw_square(0xFFAA0000,  _context->pixels,_context->mem_width, _context->mem_width-25,5, 10, 3,1);
	draw_square(0xFFAA0000,  _context->pixels,_context->mem_width, _context->mem_width-25,10, 10, 3,2);
}

void pixView_update_thread(ContextInf* _context){

	HWND _hwnd = (HWND)_context->hwnd_View;
	if(_hwnd == 0){
		return;
	}
	UpdateWindow( _hwnd );
	MSG _msg;
	ShowWindow( _hwnd, SW_SHOW );
	
	while ( PeekMessageA(&_msg, 0, 0, 0, PM_REMOVE) > 0 ) {
		TranslateMessage( &_msg );
		DispatchMessage( &_msg );
	}
	
	HDC hdc = GetDC( _hwnd );
	HDC hdcMem = CreateCompatibleDC( hdc );
	HBITMAP hbmOld = (HBITMAP)SelectObject( hdcMem, _context->hbmp );

	SIZE frameSize;
	frameSize.cx = _context->mem_width;
    frameSize.cy = _context->mem_height;
	POINT ptSrc = {0,0};
	int nWinAlpha = 255;
	BLENDFUNCTION bf = {AC_SRC_OVER, 0, nWinAlpha, AC_SRC_ALPHA};

	#ifdef USE_Transparent_PixView
		UpdateLayeredWindow(_hwnd, hdc, NULL, &frameSize, hdcMem, &ptSrc, 0, &bf, ULW_ALPHA);
	#else
		BitBlt( hdc, 0, 0, _context->width, _context->height, hdcMem, 0, 0, SRCCOPY );
	#endif
 
	SelectObject( hdcMem, hbmOld );
	DeleteObject(hdcMem);
	ReleaseDC( _hwnd, hdc );
}

void set_ContextRealSize(ContextInf* _context){
	_context->mem_width  = _context->width+ WIN_BORDER_L + WIN_BORDER_R;
	_context->mem_height = _context->height+ WIN_BORDER_T + WIN_BORDER_B;
	_context->off_y = WIN_BORDER_T;
	_context->off_x = WIN_BORDER_L;
}


DWORD WINAPI pixView_createWindow_thread(ContextInf* _context) {
	set_ContextRealSize(_context);

	HINSTANCE hInstance = GetModuleHandle(NULL);
	
	static bool class_registred = false;
	if(!class_registred){
		WNDCLASSEX wc;
		wc.cbClsExtra = 0;
		wc.cbWndExtra = 0;
		wc.cbSize = sizeof( WNDCLASSEX );
		wc.hbrBackground = CreateSolidBrush( 0 );
		wc.hCursor = LoadCursor( NULL, IDC_ARROW );
		wc.hIcon = LoadIcon( NULL, IDI_APPLICATION );
		wc.hIconSm = LoadIcon( NULL, IDI_APPLICATION );
		wc.hInstance = hInstance;
		wc.lpfnWndProc = WndProc;
		wc.lpszClassName = "pixview_class";
		wc.lpszMenuName = NULL;
		wc.style = 0;

		if ( !RegisterClassEx(&wc) ) {
			MessageBox( NULL, "Failed to register window class.", "Error", MB_OK );
			return 0;
		}
		class_registred = true;
	}

	HWND hwnd = CreateWindowEx(
		#ifdef USE_Transparent_PixView
			WS_EX_LAYERED  | WS_EX_NOPARENTNOTIFY, //WS_EX_LAYERED, // WS_EX_APPWINDOW,
		#else
			WS_EX_APPWINDOW  | WS_EX_NOPARENTNOTIFY, //WS_EX_LAYERED, // WS_EX_APPWINDOW,
		#endif

		"pixview_class",
		"pixview",
		WS_MINIMIZEBOX | WS_SYSMENU | WS_POPUP | WS_CAPTION,
		300, 200, _context->mem_width, _context->mem_height,
		NULL, NULL, hInstance, NULL 
	);

	if ( !hwnd ) {
		MessageBox( NULL, "Failed to create PixView", "Error", MB_OK );
		return 0;
	}

	RECT rcClient, rcWindow;
	POINT ptDiff;

	#ifndef USE_Transparent_PixView
		GetClientRect( hwnd, &rcClient );
		GetWindowRect( hwnd, &rcWindow );
		ptDiff.x = (rcWindow.right - rcWindow.left) - rcClient.right;
		ptDiff.y = (rcWindow.bottom - rcWindow.top) - rcClient.bottom;
		MoveWindow( hwnd, rcWindow.left, rcWindow.top, _context->mem_width + ptDiff.x, _context->mem_height + ptDiff.y, false);
	#endif
	
	_context->hwnd_View = hwnd;
	
	int last_width  = _context->width;
	int last_height = _context->height;
	pixView_MakeSurface(_context);
	
	bTh_Surface_ready = true;

	ShowWindow( hwnd, SW_SHOWDEFAULT );
	
	MSG _msg;
	while (1){
		if(upd_pixview == _context){
			if(last_width != _context->width || last_height != _context->height){
				last_width  = _context->width;
				last_height = _context->height;
				set_ContextRealSize(_context);
				pixView_MakeSurface(_context);
			}
			pixView_update_thread(upd_pixview);
			upd_pixview = 0;
		}
		
		while ( PeekMessageA(&_msg, 0, 0, 0, PM_REMOVE) > 0 ) {
			TranslateMessage( &_msg );
			DispatchMessage( &_msg );
		}
		Sleep(1);
	}
	return 0;
}

HWND pixView_createWindow( ContextInf* _context) {

  HANDLE thread = CreateThread(NULL, 0, (void*)pixView_createWindow_thread, _context, 0, NULL);
  if (thread) {
  
	static CRITICAL_SECTION _ct = {};
	if(!_ct.DebugInfo){InitializeCriticalSection(&_ct);}
	EnterCriticalSection(&_ct);
	{
		while(!bTh_Surface_ready){ //Wait for _context fill & creation (be sure to not modify *_context data while this thread as not finished is initialisation)
			Sleep(1);
		}
		bTh_Surface_ready = false;
	}
	LeaveCriticalSection(&_ct);
  }
  return _context->hwnd_View;
}

void pixView_update(ContextInf* _context){
	static CRITICAL_SECTION _ct = {};
	if(!_ct.DebugInfo){InitializeCriticalSection(&_ct);}
	EnterCriticalSection(&_ct);
	{
		upd_pixview = _context;
		while(upd_pixview){ //Wait for _context update (be sure to not modify *_context data while this thread as not finished is update)
			Sleep(1);
		}
	LeaveCriticalSection(&_ct);
  }
}