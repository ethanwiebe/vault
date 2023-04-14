#pragma once

#include <string>
#include <time.h>
#include <iostream>
#include <iomanip>

#include "types.h"

#define CSI "\x1B["

enum class YesNoAnswer : u8 {
	None = 0,
	Yes,
	No
};

bool GenerateSalt(u64& salt);
void SetClipboard(const std::string& str);
void ClearClipboard();
u8 GetKey();
void PlatInit();
void PasswordEntry(std::string& pass);

inline u64 GetTime(){
	return time(NULL);
}

inline bool ReadStdInNumber(u32& num){
	std::string line;
	std::getline(std::cin,line);
	
	const char* start = line.data();
	char* end;
	errno = 0;
	num = strtoul(start,&end,10);
	if (errno==ERANGE)
		return false;
	if (end!=start+line.size())
		return false;
	return true;
}

inline YesNoAnswer GetYesNoAnswer(){
	u8 c = 0;
	while (true){
		c = GetKey();
		if (c=='y'||c=='Y'){
			return YesNoAnswer::Yes;
		} else if (c=='n'||c=='N'){
			return YesNoAnswer::No;
		} else if (c==3||c==27){
			return YesNoAnswer::None;
		}
	}
}

inline void PrintDate(u64 time){
	struct tm* local = localtime((time_t*)&time);
	
	std::cout << std::setfill('0');
	std::cout << local->tm_year+1900 << '/' << std::setw(2) << local->tm_mon+1 << '/' << std::setw(2) << local->tm_mday;
}

inline void ResetBackground(){
	std::cout << CSI "0m";
}

inline void SetBackgroundRGB(u8 r,u8 g,u8 b){
	std::cout << CSI << "48;2;" << (int)r << ';' << (int)g << ';' << (int)b << 'm';
}

inline void MoveCursor(s16 x,s16 y){
	std::cout << CSI << y << ';' << x << 'H';
}

inline void ClearConsole(){
	// also sends cursor back to beginning
	std::cout << CSI "2J";
	MoveCursor(0,0);
}

