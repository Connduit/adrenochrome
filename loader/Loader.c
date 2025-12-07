/*
1. Locate the PE headers
2. allocate memory for the image
3. map sections into the new memory
4. apply relocations
5. resolve imports
6. fix protections
7. run TLS callbacks
8. call the module's entry point (DllMain)
*/

// TODO: this file should be a "bootstrapper" .dll that loads the rawbytes that exist in its .data section. These rawbytes should be the payload.dll

#include "ReflectiveLoader.h"
#include "GetModuleHandleManual.h"
#include "GetProcAddressManual.h"



#pragma intrinsic( _ReturnAddress ) // MSVC only
// __builtin_return_address(0); // GCC/MinGW equivalent?

// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }


// ReflectiveLoader() function that external stager calls
// DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved)
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{

	ULONG_PTR uiLibraryAddress = caller(); // TODO: figure out a better name for this

	//PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader;

	// loop through memory backwards searching for our image's base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE) // NOTE: checks if uiLibraryAddress points to the start of the DOS Header
		{
			// this is just the offset
			pNTHeader = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew; // NOTE: here, pNTHeader isn't a PIMAGE_NT_HEADERS but just an offset to it
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (pNTHeader >= sizeof(IMAGE_DOS_HEADER) && pNTHeader < 1024)
			{
				pNTHeader += uiLibraryAddress; // NOTE: now pNTHeader actually becomes a PIMAGE_NT_HEADERS
				// break if we have found a valid MZ/PE header
				if (((PIMAGE_NT_HEADERS)pNTHeader)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		uiLibraryAddress--;
	}



	// TODO: my code is a lot cleaner but by using a massive while loop like 
	// here: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c#L125-L262
	// we can resolve everything in one pass through  

	// TODO: i don't think i can use stuff like GetModuleHandleManual because i don't have 
	// access yet to the rest of the dll
	HMODULE kernel32_module = GetModuleHandleManual(L"kernel32.dll");
	HMODULE ntdll_module = GetModuleHandleManual(L"ntdll.dll");

	LOADLIBRARYA pLoadLibraryA = GetProcAddressManual(kernel32_module, "LoadLibraryA");

	// TODO: is this one needed or can i just use GetProcAddressManual? i think i can just use manual
	GETPROCADDRESS pGetProcAddress = GetProcAddressManual(kernel32_module, "GetProcAddress");
	VIRTUALALLOC pVirtualAlloc = GetProcAddressManual(kernel32_module, "VirtualAlloc");
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = GetProcAddressManual(kernel32_module, "NtFlushInstructionCache");

	////////////////////////////////////////////////


	pNTHeader = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;



	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	// NOTE: the base address of the dll we are manually mapping.
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR baseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);


	// copy over dos header, dos stub, and pe header into baseAddress?
	
	// NOTE: SizeOfHeaders is the size of all the headers (from DosHeader to SectionHeaders)
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders; // TODO: rename uiValueA variable
	uiValueB = uiLibraryAddress; // store off address... libraryaddress is the address of where the target dll exist on the disk
	uiValueC = uiBaseAddress; // store off address... baseAddress is where we are trying to write our dll into the process we are injecting it into

	// we get the number of sections in the pe file, so we can write each section into memory 
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;


	// uiValueA = the VA of the first section
	// NOTE: OptionalHeader is the last field in PIMAGE_NT_HEADERS, so when we do 
	// OptionalHeader + SizeOfOptionalHeader we get the address to the first section 
	// header (these section headers point us to where its data lives).
	// NOTE: the SectionHeader "block" in the PE file structure is a table of 
	// every section's (of the pe file) header 
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader  );

	// NOTE: loop through all the sections in the pe file
	while(uiValueE--)
	{

		// uiValueC if the VA for this sections data
		// NOTE: gets the address of the section's data we want to copy (this is the src)
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData); 

		// uiValueB is the VA for this section
		// NOTE: gets the address of where we want to copy the section's data into (this is the destination)
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// copy the section over
		// NOTE: how many bytes we need to copy over (this is the section's size)
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		// NOTE: copy over the data for the section 1 byte at a time
		while(uiValueD--)
		{
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;
		}

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER  );
	}

	//uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT  ];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress  );

	// TODO: 
	// TODO: 
	// TODO: 
	// TODO: 


	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;
	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;
	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;
	case DLL_PROCESS_DETACH:
		if (lpReserved != NULL)
		{
			break; // do not do cleanup if process termination scenario
		}
		// Perform any necessary cleanup.
		break;
	}
    return TRUE;
}


/*

TODO: load data that exists 
LoadEngineThread();
    - locates the engine dll bytes inside host.dll's memory storeage

MapModuleFromMemory();

EngineEntry() optional export inide engine dllpoint 


*/
