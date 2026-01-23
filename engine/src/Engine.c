//#pragma comment(linker, "/ENTRY:AxeEntry")


#include "Engine.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>


// TODO: function to initialize stuff so 
// that everyone else can use stuff defined in 
// engine.axe
//void initialize() { }

//#define DLLEXPORT __declspec(dllexport)
//DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) // TODO: remove WINAPI and replace with __cdecl to prevent name mangling
__declspec(dllexport)
void AxeEntry(void)
{
	MessageBoxA(NULL, "Engine AXE loaded", "AXE", MB_OK);
}

/*
__declspec(noinline)
void AxeEntry(void* ctx)
{
	MessageBoxA(NULL, "Engine.axe/Payload.axe", "Debug", MB_OK);
}*/
