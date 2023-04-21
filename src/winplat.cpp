#ifdef _WIN32

#include "plat.h"

#include <windows.h>
#include <conio.h>

HCRYPTPROV hCryptProv;
HWND consoleHwnd;

u8 GetKey(){
	u8 c = _getch();
	if (c==224){
		_getch();
	}
	return c;
}

void PasswordEntry(SecretString& pass){
	u8 c = 0;
	pass = {};
	while (true){
		c = _getch();
		if (c=='\n'||c=='\r'||c==3){
			if (c==3) pass.clear();
			break;
		} else if (c==8){
			if (!pass.empty())
				pass.pop_back();
		} else if (c>=32 && c<=127){
			pass.push_back(c);
		} else if (c==224){
			// skip character
			_getch();
		}
	}
}

void WinCryptInit(){
	if (!CryptAcquireContext(&hCryptProv,NULL,NULL,PROV_RSA_FULL,0)){
		std::cout << "Could not aquire WinCryptContext!" << std::endl;
		exit(1);
	}
}

void EnableVT(){
	DWORD mode;
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleMode(h,&mode);
	SetConsoleMode(h,mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

void WindowsInit(){
	WinCryptInit();
	EnableVT();
	SetConsoleTitle(PROGRAM_NAME);
	Sleep(40);
	consoleHwnd = FindWindow(NULL,PROGRAM_NAME);
}

void SetClipboard(const SecretString& str){
	OpenClipboard(consoleHwnd);
	EmptyClipboard();
	
	HGLOBAL globalData = GlobalAlloc(GMEM_MOVEABLE,str.size()+1);
	if (globalData==NULL){
		CloseClipboard();
		return;
	}
	
	u8* copy = (u8*)GlobalLock(globalData);
	memcpy(copy,str.c_str(),str.size()+1);
	GlobalUnlock(globalData);
	
	SetClipboardData(CF_TEXT,globalData);
	CloseClipboard();
	
	memset(copy,0,str.size());
}

void ClearClipboard(){
	OpenClipboard(consoleHwnd);
	
	HANDLE hData = GetClipboardData(CF_TEXT);
	if (hData==NULL){
		EmptyClipboard();
		CloseClipboard();
		return;
	}
	
	u8* pszText = (u8*)GlobalLock(hData);
	if (pszText==NULL){
		EmptyClipboard();
		CloseClipboard();
		return;
	}
	
	size_t size = strnlen((const char*)pszText,65536);
	memset(pszText,0,size);
	GlobalUnlock(hData);
	
	EmptyClipboard();
	CloseClipboard();
}

bool GenerateRandomBytes(u8* b,u64 count){
	return CryptGenRandom(hCryptProv,count,b);
}

void PlatInit(){
	WindowsInit();
}

#endif
