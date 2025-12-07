/* GetModuleHandleManual.h */
#ifndef GET_MODULE_HANDLE_MANUAL_H
#define GET_MODULE_HANDLE_MANUAL_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// GetModuleHandle by literal name
HMODULE GetModuleHandleManual(LPCWSTR lpModuleName);

// GetModuleHandle by hash
// TODO: rename, function overloading is not allowed in c
// HMODULE GetModuleHandleManual(DWORD moduleHash);


#endif
