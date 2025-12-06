/* LoadLibraryManual.c */

#include "LoadLibraryManual.h"



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



/* NOTES:
 * PEB-
 *
 *
 * - e_lfanew is the offset from DOS header to NT headers
 * - MZ Header == DOS Header
 *   NT Header == PE Header
 * */

DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	UINT_PTR dllBaseAddress   = 0;
	UINT_PTR uiBaseAddress   = 0;
	UINT_PTR uiExportDir     = 0; // PIMAGE_EXPORT_DIRECTORY
	UINT_PTR uiNameArray     = 0;
	UINT_PTR uiAddressArray  = 0;
	UINT_PTR uiNameOrdinals  = 0;
	DWORD dwCounter          = 0;
#ifdef WIN_X64
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


	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(dllBaseAddress + ((PIMAGE_DOS_HEADER)dllBaseAddress)->e_lfanew);
	DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)dllBaseAddress + dwExportDirRVA);


	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;


	// currenlty we can only process a PE file which is the same type as the one this fuction has
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	// NOTE: there's no work around for this, it is absolute
	if(pNTHeader->OptionalHeader.Magic == 0x010B) // PE32
	{
		if( dwCompiledArch != 1  )
			return 0;
	}
	else if(pNTHeader->OptionalHeader.Magic == 0x020B) // PE64
	{
		if( dwCompiledArch != 2  )
			return 0;
	}
	else
	{
		return 0;
	}

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT  ];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress  );

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress  );

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress  );

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress  );

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while( dwCounter--  )
	{
		// char* prodName = (char*)((ULONG_PTR)pModule + arrayOfNamesRVAs[i]); // dll loaded equivalent
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray  ), uiBaseAddress  ));

		if( strstr( cpExportedFunctionName, "ReflectiveLoader"  ) != NULL  )
		{
			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress  );

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += ( DEREF_16( uiNameOrdinals  ) * sizeof(DWORD)  );

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset( DEREF_32( uiAddressArray  ), uiBaseAddress  );
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}



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

	__try
	{
		do
		{
			if( !hProcess  || !lpBuffer || !dwLength  )
				break;

			// check if the library has a ReflectiveLoader...
			dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if( !dwReflectiveLoaderOffset  )
				break;

			// alloc memory (RWX) in the host process for the image...
			lpRemoteLibraryBuffer = VirtualAllocEx( hProcess, NULL, dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE  );
			if( !lpRemoteLibraryBuffer  )
				break;

			// write the image into the host process...
			if( !WriteProcessMemory( hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL  )  )
				break;

			// add the offset to ReflectiveLoader() to the remote library address...
			lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset  );

			// create a remote thread in the host process to call the ReflectiveLoader!
			hThread = CreateRemoteThread( hProcess, NULL, 1024*1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId  );


		} while( 0  );


	}
	__except( EXCEPTION_EXECUTE_HANDLER  )
	{
		hThread = NULL;

	}

	return hThread;

}
