/* Loader.h */

#ifndef ADRENOCHROME_REFLECTIVE_LOADER_H
#define ADRENOCHROME_REFLECTIVE_LOADER_H


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DLL_QUERY_HMODULE 6

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT __declspec(dllexport)

typedef HMODULE (WINAPI* LOADLIBRARYA)
(LPCSTR lpLibFileName);

typedef FARPROC (WINAPI* GETPROCADDRESS)
(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI* VIRTUALALLOC)
(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef DWORD (NTAPI* NTFLUSHINSTRUCTIONCACHE)
(HANDLE hProcess, PVOID lpBaseAddress, ULONG dwSize);

//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved);
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpReserved);

#endif
