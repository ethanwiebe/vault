#ifdef __linux__

#include "plat.h"
#include <fstream>
#include <sys/ioctl.h>
#include <termios.h>
#include <thread>
#include <chrono>

#include "xclip.h"

static struct termios old, current;

static XClip::Manager* clipManager;

void initTermios(bool echo){
	tcgetattr(0,&old);
	current = old;
	current.c_lflag &= ~ICANON;
	if (echo){
		current.c_lflag |= ECHO;
	} else {
		current.c_lflag &= ~ECHO;
	}
	tcsetattr(0,TCSANOW,&current);
}

void resetTermios(){
	tcsetattr(0,TCSANOW,&old);
}

u8 getch(bool echo){
	u8 c;
	initTermios(echo);
	c = getchar();
	resetTermios();
	return c;
}

u8 GetKey(){
	u8 c = getch(false);
	if (c==27){
		getch(false);
		getch(false);
		c = ' ';
	}
	return c;
}

void PasswordEntry(SecretString& pass){
	u8 c = 0;
	pass = {};
	while (true){
		c = getch(false);
		if (c=='\n'||c=='\r'||c==3){
			if (c==3) pass.clear();
			break;
		} else if (c==127){
			if (!pass.empty())
				pass.pop_back();
		} else if (c>=32 && c<=127){
			pass.push_back(c);
		} else if (c==27){
			// skip character
			getch(false);
			getch(false);
		}
	}
}

bool GenerateSalt(u64& salt){
	std::ifstream r{"/dev/random",std::ios::binary};
	r.read((char*)&salt,sizeof(u64));
	return true;
}

void SetClipboard(const SecretString& str){
	clipManager->set_data(str.data(),str.size());
}

void ClearClipboard(){
	clipManager->clear_data();
}

void PlatInit(){
	clipManager = XClip::get_manager();
}

#endif
