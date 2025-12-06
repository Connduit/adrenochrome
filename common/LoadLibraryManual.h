/* LoadLibraryManual.h */

#ifndef LOAD_LIBRARY_MANUAL_H
#define LOAD_LIBRARY_MANUAL_H

HANDLE WINAPI LoadLibraryManual(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);

// TODO: rename to ManualMapper or something?
HANDLE LoadLibraryManual(LPCSTR lpLibFileName); // fewer's return type
// HMODULE LoadLibraryManual(LPCSTR lpLibFileName); // more correct
//LPVOID LoadLibraryManual(LPCSTR lpLibFileName); // TODO: this is technically the MOST correct return type

#endif
