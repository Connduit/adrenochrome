#include "Loader.h"
#include "AXEStructs.h"

int loadAXE()
{
	char* targetAxe = "/path/to/targetAxe";
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