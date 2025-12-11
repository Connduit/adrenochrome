/* Loader.h */

#ifndef ADRENOCHROME_LOADER_H
#define ADRENOCHROME_LOADER_H

#include "ReflectiveLoader.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved);
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpReserved);

#endif
