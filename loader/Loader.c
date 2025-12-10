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

// TODO: lots of "extra" variables i added just for better readability that might make code slightly less
// optimized. should probs revert back to fewer's code if i want optimize it in that way again

#include "ReflectiveLoader.h"
#include "GetModuleHandleManual.h"
#include "GetProcAddressManual.h"

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;


#if defined(_MSC_VER)

#pragma intrinsic( _ReturnAddress ) // MSVC only
// __builtin_return_address(0); // GCC/MinGW equivalent?

// This function can not be inlined by the compiler or we will not get the address we expect. Ideally 
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of 
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics 
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller(VOID) { return (ULONG_PTR)_ReturnAddress(); }

#elif defined(__GNUC__) || defined(__clang__)

// MinGW/GCC Version for caller()
__attribute__((noinline)) ULONG_PTR caller(void)
{
	    return (ULONG_PTR)__builtin_return_address(0);
}

#else
	#error Unsupported Compiler
#endif



// ReflectiveLoader() function that external stager calls
// DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved)
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
{

	// NOTE: caller() gives the return address of the instruction that called caller()
	// which basically means it gives us the address to the next line of code in this function?
	// Therefore, this address is going to be somewhere within our injected dll buffer (the dll being the reflective dll)
	// NOTE: unmapped location of the dll 
	ULONG_PTR rawImageBase = caller(); // TODO: rename to rawImageBase or pRawImageBase

	//PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader;
	LONG ntHeaderOffset;


	// loop through memory backwards searching for our image's base address (image meaning our reflective dll)
	// NOTE: it is called an image because an image is just a PE file loaded/living in memory?
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)rawImageBase)->e_magic == IMAGE_DOS_SIGNATURE) // NOTE: checks if rawImageBase points to the start of the DOS Header
		{
			// this is just the offset
			ntHeaderOffset = ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew; // NOTE: here, pNTHeader isn't a PIMAGE_NT_HEADERS but just an offset to it
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (ntHeaderOffset >= sizeof(IMAGE_DOS_HEADER) && ntHeaderOffset < 1024)
			{
				//pNTHeader += rawImageBase; // NOTE: now pNTHeader actually becomes a PIMAGE_NT_HEADERS
				pNTHeader = (PIMAGE_NT_HEADERS)(rawImageBase + ntHeaderOffset);
				// break if we have found a valid MZ/PE header
				if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
				{
					break;
				}
			}
		}
		rawImageBase--;
	}

	// NOTE: at this point rawImageBase should be where our target.dll (the dll we injected into the process)
	// starts in memory



	// TODO: my code is a lot cleaner but by using a massive while loop like 
	// here: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c#L125-L262
	// we can resolve everything in one pass through  

	// TODO: i don't think i can use stuff like GetModuleHandleManual/GetProcAddressManual? because i don't have 
	// access yet to the rest of the dll
	HMODULE kernel32_module = GetModuleHandleManual(L"kernel32.dll");
	HMODULE ntdll_module = GetModuleHandleManual(L"ntdll.dll");

	LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)GetProcAddressManual(kernel32_module, "LoadLibraryA");

	// TODO: is this one needed or can i just use GetProcAddressManual? i think i can just use manual
	GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)GetProcAddressManual(kernel32_module, "GetProcAddress");
	VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)GetProcAddressManual(kernel32_module, "VirtualAlloc");
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GetProcAddressManual(kernel32_module, "NtFlushInstructionCache");

	////////////////////////////////////////////////


	pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew);



	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	// NOTE: the base address of the dll we are manually mapping.
	// the kernels base address and later this images newly loaded base address
	// NOTE: this newly allocated memory also lives in the process we injected our reflective dll into
	ULONG_PTR baseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);


	// copy over dos header, dos stub, and pe header into baseAddress?
	
	// NOTE: SizeOfHeaders is the size of all the headers (from DosHeader to SectionHeaders)
	//DWORD uiValueA = ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfHeaders; // TODO: rename uiValueA variable
	DWORD sizeOfHeaders = ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfHeaders; // TODO: rename uiValueA variable

	//ULONG_PTR uiValueB = rawImageBase; // store off address... libraryaddress is the address of where the target dll exist on the disk
	// TODO: rename to srcPtr or srcHeaderPtr
	ULONG_PTR srcPtr = rawImageBase; // store off address... libraryaddress is the address of where the target dll exist on the disk

	//ULONG_PTR uiValueC = baseAddress; // store off address... baseAddress is where we are trying to write our dll into the process we are injecting it into
	// TODO: rename to dstPtr or dstHeaderPtr
	ULONG_PTR dstPtr = baseAddress;

	while(sizeOfHeaders--)
	{
		*(BYTE *)dstPtr++ = *(BYTE *)srcPtr++;
	}

	// we get the number of sections in the pe file, so we can write each section into memory 
	WORD nSections = pNTHeader->FileHeader.NumberOfSections;


	// uiValueA = the VA of the first section
	// NOTE: OptionalHeader is the last field in PIMAGE_NT_HEADERS, so when we do 
	// OptionalHeader + SizeOfOptionalHeader we get the address to the first section 
	// header (these section headers point us to where its data lives).
	// NOTE: the SectionHeader "block" in the PE file structure is a table of 
	// every section's (of the pe file) header 
	sizeOfHeaders = ( (ULONG_PTR)&(pNTHeader)->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);
	//DWORD uiValueD;
	DWORD sizeofRawData;
	// NOTE: loop through all the sections in the pe file
	while (nSections--)
	{

		// baseAddressBuffer if the VA for this sections data
		// NOTE: gets the address of the section's data we want to copy (this is the src)
		// TODO: rename to srcPtr?
		srcPtr = (rawImageBase + ((PIMAGE_SECTION_HEADER)sizeOfHeaders)->PointerToRawData); 

		// uiValueB is the VA for this section
		// NOTE: gets the address of where we want to copy the section's data into (this is the destination)
		// TODO: rename to dstPtr?
		dstPtr = (baseAddress + ((PIMAGE_SECTION_HEADER)sizeOfHeaders)->VirtualAddress);

		// copy the section over
		// NOTE: how many bytes we need to copy over (this is the section's size)
		sizeofRawData = ((PIMAGE_SECTION_HEADER)sizeOfHeaders)->SizeOfRawData; // TODO: declare this variable outside the loop

		// NOTE: copy over the data for the section 1 byte at a time
		while(sizeofRawData--)
		{
			// TODO: rename both to match above
			*(BYTE *)dstPtr++ = *(BYTE *)srcPtr++;
		}

		// get the VA of the next section
		sizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);
	}

	// TODO: DELETE
	ULONG_PTR rawImageBaseBuffer;
	ULONG_PTR baseAddressBuffer;

	//uiValueB = the address of the import directory
	// NOTE: at this point, uiValueB is gonna look like this: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	// TODO: rename var to pImportDir
	PIMAGE_DATA_DIRECTORY pImportDir = &(pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// rawImageBaseBuffer = (ULONG_PTR)&(pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// NOTE: uiValueC should now point to PIMAGE_IMPORT_DESCRIPTOR
	// TODO: rename to PIMAGE_IMPORT_DESCRIPTOR importDesc
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + ((PIMAGE_DATA_DIRECTORY)pImportDir)->VirtualAddress); // TODO: use different variable here
	//baseAddressBuffer = ( baseAddress + ((PIMAGE_DATA_DIRECTORY)rawImageBaseBuffer)->VirtualAddress); // TODO: use different variable here

	ULONG_PTR importModuleBase;
	DWORD iatAddress;
	// itterate through all imports
	// NOTE: Name is an RVA to the name as a string
	// NOTE: we can do this because the import table is NULL-terminated by an array of IMAGE_IMPORT_DESCRIPTOR
	// NOTE: we're looping through all the imports because we're resolving all the imports/dlls that our 
	// reflective dll depends on. (we're resolving by calling getprocaddress)
	while (((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		// NOTE: at this point, rawImageBase is no longer for the address where our reflective dll exists in memory
		// in the process we injected into. now, rawImageBase will represent the the address of the dll's whos 
		// functions we are trying to resolve 
		importModuleBase = (ULONG_PTR)pLoadLibraryA((LPCSTR)(baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->Name)); // NOTE: this variable was called rawImageBase (that's what the comments above are referring to)

		// uiValueD = VA of the OriginalFirstThunk
		// TODO: should be a ULONG_PTR? using a DWORD would break this when the dll is greater than 4gb (this should never happen tho)
		DWORD sizeofRawData = (baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		iatAddress = (baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(iatAddress))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// NOTE: i can remove this if block if ik for certain my compiler isn't only importing by first thunk
			if (sizeofRawData && ((PIMAGE_THUNK_DATA)sizeofRawData)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				// TODO: type should be PIMAGE_NT_HEADERS, right? and variable name should be changed
				//uiExportDir = rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew;
				PIMAGE_NT_HEADERS importedNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)importModuleBase + ((PIMAGE_DOS_HEADER)importModuleBase)->e_lfanew);

				// uiNameArray = the address of the modules export directory entry
				//uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				DWORD dwExportDirRVA = importedNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; // TODO: cast to ULONG_PTR instead? 

				// get the VA of the export directory
				//uiExportDir = (rawImageBase + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
				PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)importModuleBase + dwExportDirRVA); // TODO: cast to correct types

				// get the VA for the array of addresses
				//uiAddressArray = (rawImageBase + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);
				// DWORD* uiAddressArray = rawImageBase + pExportDir->AddressOfFunctions; // TODO: cast to a ulong_ptr instead? NOTE: from my apimanager code
				// TODO: rename maybe?
				ULONG_PTR uiAddressArray = importModuleBase + pExportDir->AddressOfFunctions; // TODO: cast to a ulong_ptr instead? 

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				//uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)sizeofRawData)->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(iatAddress) = (importModuleBase + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + DEREF(iatAddress)); // TODO: rename to importFuncAddress?
				// rawImageBaseBuffer = (baseAddress + DEREF(iatAddress)); // TODO: rename to importFuncAddress?

				// use GetProcAddress and patch in the address for this imported function
				DEREF(iatAddress) = (ULONG_PTR)pGetProcAddress((HMODULE)importModuleBase, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)importByName)->Name);
			}
			// get the next imported function
			iatAddress += sizeof(ULONG_PTR);
			if (sizeofRawData)
				sizeofRawData += sizeof(ULONG_PTR);
		}

		// get the next import
		importDesc += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	///////////////////////////////////////////////////////////
	// NOTE: we don't need to check if the preferred image base is available because since
	// we are using VirtualAlloc to allocate a new memory block, we perform relocations everytime.
	// Using VirtualAlloc means that we will always have memory avaiable to us; however, we wont know 
	// where VirtualAlloc will place the DLL. And most of the time the memory region chosen by Windows
	// (when we call VirtualAlloc) will not match the preferred base in the PE header.

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// TODO: should rename rawImageBase or use a different variable name. the variable should be called 
	// maybe something like "relocationOffset" or something
	//rawImageBase = baseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	ULONG_PTR relocationDelta;
	relocationDelta = baseAddress - pNTHeader->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	// NOTE: get IMAGE_DATA_DIRECTORY for relocation table. uiValueB is type _IMAGE_DATA_DIRECTORY
	// which has a field called VirtualAddress which gives a relative address to the relocation table
	// relative to the image base
	// TODO: rename to baseRelocDir or pRelocDir
	PIMAGE_DATA_DIRECTORY pRelocDir = &pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	// rawImageBaseBuffer = (ULONG_PTR) & pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// NOTE: relocations are stored in relocation "blocks" IMAGE_BASE_RELOCATION. each
	// relocation block contains a number of different relocations (which can be obtained from SizeOfBlock). 
	// IMAGE_BASE_RELOCATION blocks are a thing so windows doesn't have to store every single relocation
	// needed one after another in a continguous block of memory

	// TODO:

	// check if their are any relocation blocks (IMAGE_BASE_RELOCATION) present
	if (((PIMAGE_DATA_DIRECTORY)pRelocDir)->Size) // TODO: castings are no longer needed?
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);
		// baseAddressBuffer = (baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);

		// and we itterate through all entries...
		// NOTE: we can do this because windows api says the IMAGE_BASE_RELOCATION blocks are terminated
		// by a NULL relocation block, meaning SizeOfBlock will be 0 when we want to stop looking/relocating
		while (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			iatAddress = (baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			// TODO:
			DWORD numRelocs = (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			// rawImageBaseBuffer = (((PIMAGE_BASE_RELOCATION)baseAddressBuffer)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			sizeofRawData = (ULONG_PTR)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

			// we itterate through all the entries in the current block...
			while (numRelocs--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)sizeofRawData)->type == IMAGE_REL_BASED_DIR64) // relocations for 64bit only
				{
					*(ULONG_PTR*)(iatAddress + ((PIMAGE_RELOC)sizeofRawData)->offset) += relocationDelta;
				}
				else if (((PIMAGE_RELOC)sizeofRawData)->type == IMAGE_REL_BASED_HIGHLOW) // relocations for 32bit only (if the dll is compiled in 32bit)
				{
					*(DWORD*)(iatAddress + ((PIMAGE_RELOC)sizeofRawData)->offset) += (DWORD)relocationDelta;
				}
				else if (((PIMAGE_RELOC)sizeofRawData)->type == IMAGE_REL_BASED_HIGH) // TODO: remove this? this is only needed in very old legacy 32bit relocations
				{
					*(WORD*)(iatAddress + ((PIMAGE_RELOC)sizeofRawData)->offset) += HIWORD(relocationDelta);
				}
				else if (((PIMAGE_RELOC)sizeofRawData)->type == IMAGE_REL_BASED_LOW) // TODO: remove this? this is only needed in very old legacy 32bit relocations
				{
					*(WORD*)(iatAddress + ((PIMAGE_RELOC)sizeofRawData)->offset) += LOWORD(relocationDelta);
				}

				// get the next entry in the current relocation block
				sizeofRawData += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			relocBlock = relocBlock + ((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock;
		}
	}
	////////////////////////////////////
	// 
	// 
	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	//iatAddress = (baseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint); // TODO: rename variable
	DWORD entryAddress = (baseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint); // TODO: rename variable

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)entryAddress)((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, lpParameter);

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return entryAddress; 

}

// TODO: HMODULE and HINSTANCE are the same... so choose one to use and change the rest for consitency
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE*)lpReserved = hAppInstance;
		}
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;
	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;
	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		// hAppInstance = hModule;
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
