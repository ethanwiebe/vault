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

void PasswordEntry(std::string& pass){
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
	SetConsoleTitle("wordager");
	Sleep(40);
	consoleHwnd = FindWindow(NULL,"wordager");
}

void SetClipboard(const std::string& str){
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
	EmptyClipboard();
	CloseClipboard();
}

bool GenerateSalt(u64& salt){
	return CryptGenRandom(hCryptProv,sizeof(u64),(u8*)&salt);
}

void PlatInit(){
	WinInit();
}

#endif
