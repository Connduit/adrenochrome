#ifndef ADRENOCHROME_BUILDER_H
#define ADRENOCHROME_BUILDER_H


#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline


class AdrenochromeBuilder
{
public:
	//AdrenochromeBuilder();
	//~AdrenochromeBuilder();

	//static void loadFile(std::string& path);
	static void loadFile(char* path);
private:
	ULONG_PTR baseAddress_;

};


#endif
