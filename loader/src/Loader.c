#include "Loader.h"
#include "AxeLoaderContext.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>


// NOTE: this is the function that would be called by a netsvcs svchost.exe process.
// For testing purposes, we will just call it through LoaderDll's DllMain function using CreateThread
//int startEngine()
DWORD WINAPI startEngine(LPVOID lpParam)
{
	MessageBoxA(NULL, "inside startEngine", "Debug", MB_OK);
	loadAxeFromDisk();
	return 0;
}

//int loadAXE(char* /path/to/targetAxe)
//int loadAXE()
int loadAxeFromDisk()
{
	MessageBoxA(NULL, "inside loadaxefromdisk", "Debug", MB_OK);
	//char* targetAxe = "/path/to/targetAxe";
	char* targetAxe = "C:\\Users\\Connor\\Documents\\Code\\C++\\adrenochrome\\x64\\Release\\engine.axe"; 
	HANDLE hFile = CreateFileA(targetAxe, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "invalid handle value", "Debug", MB_OK);
		// TODO: throw helpful error
		return 1;
	}

	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
	{
		// TODO: throw helpful error
		MessageBoxA(NULL, "invalid filesize", "Debug", MB_OK);
		return 1;
	}

	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		// TODO: throw helpful error
		MessageBoxA(NULL, "invalid heapalloc", "Debug", MB_OK);
		return 1;
	}

	DWORD dwBytesRead = 0;
	// reads the entire dll into memory
	// NOTE: here is where we're actually writing the contents of the targetDll
	// from the disk into the memory we just allocated for it on the Heap 

	// NOTE: ReadFile() copies heap into ram but that doesn't mean the image 
	// is mapped/loaded yet
	if (!ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL)) 
	{
		// TODO: throw helpful error
		MessageBoxA(NULL, "invalid readfile", "Debug", MB_OK);
		return 1;
	}

	PAXE_HEADER aHeader = (PAXE_HEADER)lpBuffer;
	loadAxe(lpBuffer, dwLength);

}

// NOTE: lpBuffer should be the rawImageBase of the .axe file on disk
void loadAxe(LPVOID lpBuffer, DWORD dwLength) // TODO: dwLength not needed?
{
	//ULONG_PTR baseAddress = VirtualAlloc(preferred base addr, num bytes to  allocate, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// ULONG_PTR baseAddress = VirtualAlloc(NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// TODO: manually map here

	MessageBoxA(NULL, "inside loadAxe", "Debug", MB_OK);

	AXE_LOADER_CONTEXT ctxStruct;   
	PAXE_LOADER_CONTEXT ctx = &ctxStruct; 


	PAXE_HEADER header = (PAXE_HEADER)lpBuffer;
	ctx->axeHeader = *header;

	ctx->axeSections = (PAXE_SECTION)((ULONG_PTR)lpBuffer + sizeof(AXE_HEADER));

	// ctx->axeImports = (AXE_IMPORT*)(ctx->axeSections + ctx->axeHeader.NumberOfSections);

	AXE_SECTION* relocSection = &ctx->axeSections[ctx->axeHeader.NumberOfSections - 1];
	ctx->axeRelocations = (AXE_RELOCATION*)((ULONG_PTR)lpBuffer + relocSection->Offset);

	// BYTE* textData = lpBuffer + ctx->axeSections[0].Offset;
	// BYTE* rdataData = lpBuffer + ctx->axeSections[1].Offset;
	// BYTE* dataData = lpBuffer + ctx->axeSections[2].Offset;


	// or do this:
	PAXE_SECTION pSection = (PAXE_SECTION)((ULONG_PTR)lpBuffer + sizeof(AXE_HEADER));

	size_t totalSize = 0; // sum of section sizes
	totalSize += sizeof(AXE_HEADER);

	for (int i = 0; i < header->NumberOfSections; ++i, ++pSection)
	{
		//totalSize += sections[i].Size;
		//ctx.axeSections = pSection;
		totalSize += pSection->Size;
	}

	char dbuf[128];
	wsprintfA(dbuf, "totalSize = %lu, SizeOfImage = %lu", totalSize, header->SizeOfImage); // these should match? 
	MessageBoxA(NULL, dbuf, "Debug", MB_OK);

	//BYTE* baseAddress = (BYTE*)VirtualAlloc(NULL, header->SizeOfSections, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//BYTE* baseAddress = (BYTE*)VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	ULONG_PTR baseAddress = (ULONG_PTR)VirtualAlloc(NULL, header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (baseAddress == NULL)
	{
		MessageBoxA(NULL, "bad virtualalloc", "Debug", MB_OK);
		// TODO: throw error? 
		return;
	}


	pSection = (PAXE_SECTION)((ULONG_PTR)lpBuffer + sizeof(AXE_HEADER));
	for (int i = 0; i < header->NumberOfSections; ++i, ++pSection)
	{
		PBYTE srcPtr = (PBYTE)lpBuffer + pSection->Offset;
		// memoryAddress = the RVA within the AXE image
		// NOTE: what's stopping us from just using the Offset field as an RVA instead?
		//PBYTE dstPtr = (PBYTE)(baseAddress + pSection->memoryAddress); 
		PBYTE dstPtr = (PBYTE)(baseAddress + pSection->Offset); 
		memcpy(dstPtr, srcPtr, pSection->Size);
		dstPtr += pSection->Size;
	}

	// TODO: relocations are required... unless we provide a baseaddress in the VirtualAlloc function


	// TODO: bad entry address
	ULONG_PTR entryAddress = (ULONG_PTR)(baseAddress + header->AddressOfEntryPoint);
	
	/*
	void (*AxeEntry)(void) = (void (*)(void))(baseAddress + axeHeader.AddressOfEntryPoint);
	AxeEntry();
	*/

	typedef void (*EntryFn)(void);
	EntryFn ep = (EntryFn)(baseAddress + header->AddressOfEntryPoint);
	MessageBoxA(NULL, "Jumping now", "Debug", MB_OK);
	ep();
	MessageBoxA(NULL, "Returned from entry", "Debug", MB_OK);

	MessageBoxA(NULL, "calling entry address", "Debug", MB_OK);
	char buf[128];
	wsprintfA(buf, "base=%p entry=%d", baseAddress, header->AddressOfEntryPoint);
	MessageBoxA(NULL, buf, "Debug", MB_OK);

	// Jump to entry point (first section start)
	((void(*)(void))entryAddress)(); // TODO: typedef this 

	return;

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
