#ifndef GET_PROC_ADDRESS_MANUAL_H
#define GET_PROC_ADDRESS_MANUAL_H

// GetProcAddress by literal name
// FARPROC GetProcAddressManual(PVOID pModule, LPCSTR lpProcName);
// GetProcAddress by hash
FARPROC GetProcAddressManual(HMODULE hModule, DWORD procHash);

#endif
