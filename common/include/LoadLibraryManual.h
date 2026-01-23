/* LoadLibraryManual.h */

#ifndef LOAD_LIBRARY_MANUAL_H
#define LOAD_LIBRARY_MANUAL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// #ifdef __cplusplus
// extern "C" {
// #endif

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress  );
DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer  );
HANDLE WINAPI LoadLibraryManual(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);

// #ifdef __cplusplus
//
// }
// #endif

// TODO: move these into a more "common" header area
#define DEREF( name  )*(UINT_PTR *)(name)
#define DEREF_64( name  )*(DWORD64 *)(name)
#define DEREF_32( name  )*(DWORD *)(name)
#define DEREF_16( name  )*(WORD *)(name)
#define DEREF_8( name  )*(BYTE *)(name)


// TODO: rename to ManualMapper or something?
//HANDLE LoadLibraryManual(); // fewer's return type
// HMODULE LoadLibraryManual(LPCSTR lpLibFileName); // more correct
//LPVOID LoadLibraryManual(LPCSTR lpLibFileName); // TODO: this is technically the MOST correct return type

#endif
