#include "builder.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>



//void AdrenochromeBuilder::loadFile(std::string& path)
void AdrenochromeBuilder::loadFile(char* path)
{
	//HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwLength = GetFileSize(hFile, NULL);

	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		MessageBoxA(NULL, "HeapAlloc fails", "Debug", MB_OK);
	}

	DWORD dwBytesRead = 0;
	// reads the entire dll into memory
	// NOTE: here is where we're actually writing the contents of the targetDll
	// from the disk into the memory we just allocated for it on the Heap 

	if (!ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL))
	{
		MessageBoxA(NULL, "ReadFile fails", "Debug", MB_OK);
	}

}
/*
pe = read_file(pe_path)

dos = parse_dos_header(pe)
nt  = parse_nt_headers(pe)
sections = parse_section_headers(pe)
*/
