/* ReflectiveLoader.h */
// This files is JUST for loading the reflective dll

#ifndef ADRENOCHROME_REFLECTIVE_LOADER_H
#define ADRENOCHROME_REFLECTIVE_LOADER_H


#include <minwindef.h>
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

//////////////////////////////////////////////////////////////
// TODO: CONTEXTS
typedef struct // TODO: needs a constructor to zero everything out?
{
	ULONG_PTR rawImageBase;
	ULONG_PTR baseAddress;
	PIMAGE_NT_HEADERS pNtHeaders;
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	VIRTUALALLOC pVirtualAlloc;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache;
	//PVOID pNtdllBase; // TODO: 
} LOADER_CONTEXT, *PLOADER_CONTEXT;

//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved);
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpReserved);

// TODO: 
void loadModule(void); // load module into memory
//ULONG_PTR getImageBase(void); // TODO: rename to initalizeLoader/initalizeLoaderContext? populate context...
BOOL initializeContext(PLOADER_CONTEXT ctx); 
DWORD resolveDependencies(PLOADER_CONTEXT ctx);
BOOL copyImageIntoMemory(PLOADER_CONTEXT ctx); // TODO: rename to loadImageIntoMemory() ?
BOOL applyRelocations(PLOADER_CONTEXT ctx); 
BOOL resolveImports(PLOADER_CONTEXT ctx);
// void handleTLS(void); // void handleTLSCallbacks(void);
// void setProtections(void); // ?
// void callEntryPoint(void);
////////////////////////////////////////
// getImports();
// getExports();
// parse();



#endif
