#include "Loader.h"
#include "AXEStructs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>



// NOTE: this is the function that would be called by a netsvcs svchost.exe process.
// For testing purposes, we will just call it through LoaderDll's DllMain function using CreateThread
//int startEngine()
DWORD WINAPI startEngine(LPVOID lpParam)
{
	loadAxeFromDisk();
	return 0;
}

//int loadAXE(char* /path/to/targetAxe)
//int loadAXE()
int loadAxeFromDisk()
{
	//char* targetAxe = "/path/to/targetAxe";
	char* targetAxe = "loader.axe";
	HANDLE hFile = CreateFileA(targetAxe, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// TODO: throw helpful error
		return 1;
	}

	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
	{
		// TODO: throw helpful error
		return 1;
	}

	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		// TODO: throw helpful error
		return 1;
	}

	DWORD dwBytesRead = 0;
	// reads the entire dll into memory
	// NOTE: here is where we're actually writing the contents of the targetDll
	// from the disk into the memory we just allocated for it on the Heap 

	if (!ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL))
	{
		// TODO: throw helpful error
		return 1;
	}

	PAXE_HEADER aHeader = (PAXE_HEADER)lpBuffer;
	loadAxe(lpBuffer, dwLength);

}

void loadAxe(LPVOID lpBuffer, DWORD dwLength)
{
	//ULONG_PTR baseAddress = VirtualAlloc(preferred base addr, num bytes to  allocate, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ULONG_PTR baseAddress = VirtualAlloc(NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// TODO: manually map here

}

void loadDLL()
{}

void loadPIC()
{}

void ManualMapDLL()
{}

void ManualMapAXE()
{}

void ManualMapPIC()
{}

void loadFromSection()
{}

void loadFromDisk()
{
	char* filename = "path/to/file";
	// decrypt(filename);
	// decompress(filename);
}