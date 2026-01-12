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
#include "LoaderHashes.h"
#include "PEStructs.h"
#include "StatusCodes.h" 

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

// TODO:
// TODO:
// TODO:
// split up the steps in reflective loader into separate functions so i can reuse 
// them in the custom loader (Loader.c/h) when trying to manually map .axe files

//BOOL initializeContext(PLOADER_CONTEXT ctx)
BOOL initializeReflectiveContext(PLOADER_CONTEXT ctx)
{
	// NOTE: caller() gives the return address of the instruction that called caller()
	// which basically means it gives us the address to the next line of code in this function?
	// Therefore, this address is going to be somewhere within our injected dll buffer (the dll being the reflective dll)
	// NOTE: unmapped location of the dll 
	ULONG_PTR rawImageBase = caller(); // TODO: rename to rawImageBase or pRawImageBase

	//PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders;
	LONG ntHeaderOffset;


	// Loop backwards until we find the base address of our reflective dll
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
				pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase + ntHeaderOffset);
				// break if we have found a valid MZ/PE header
				if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
				{
					// TODO: return true immeditaly here? otherwise return false?
					break;
				}
			}
		}
		rawImageBase--;
	}

	ctx->rawImageBase = rawImageBase;
	ctx->pNtHeaders = pNtHeaders;

	return TRUE;
}
 
// TODO: parameter should be the modules we want to resolve?
// should i make a struct to hold all the modules?
DWORD resolveReflectiveDependencies(PLOADER_CONTEXT ctx) 
{

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

	ctx->pGetProcAddress = pGetProcAddress;
	ctx->pVirtualAlloc = pVirtualAlloc;
	ctx->pLoadLibraryA = pLoadLibraryA;
	ctx->pNtFlushInstructionCache = pNtFlushInstructionCache;

	return RDI_SUCCESS;
}

// TODO: rename to loadImageIntoMemory() or maybe just loadImage()?
BOOL copyImageIntoMemoryReflective(PLOADER_CONTEXT ctx)
{
	//pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew);
	// TODO: this should already be the same as ctx->pNtHeaders?
	//pNtHeader = (PIMAGE_NT_HEADERS)(rawImageBase + ((PIMAGE_DOS_HEADER)rawImageBase)->e_lfanew); // TODO: this should be fine? 


	// Allocate memory for the reflective dll to be loaded into (this memory is inside our target process)
	ULONG_PTR baseAddress = (ULONG_PTR)ctx->pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)ctx->pNtHeaders)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ctx->baseAddress = baseAddress;


	// copy over dos header, dos stub, and pe header into baseAddress?
	
	DWORD SizeOfHeaders = ((PIMAGE_NT_HEADERS)ctx->pNtHeaders)->OptionalHeader.SizeOfHeaders;
	PBYTE srcPtr = (PBYTE)ctx->rawImageBase;
	PBYTE dstPtr = (PBYTE)ctx->baseAddress;

	// Copy the headers into our newly allocated memory
	while (SizeOfHeaders--)
	{
		*dstPtr++ = *srcPtr++;
	}

	// we get the number of sections in the pe file, so we can write each section into memory 
	WORD nSections = (ctx->pNtHeaders)->FileHeader.NumberOfSections;

	// uiValueA = the VA of the first section
	// NOTE: OptionalHeader is the last field in PIMAGE_NT_HEADERS, so when we do 
	// OptionalHeader + SizeOfOptionalHeader we get the address to the first section 
	// header (these section headers point us to where its data lives).
	// NOTE: the SectionHeader "block" in the PE file structure is a table of 
	// every section's (of the pe file) header 
	//sizeOfHeaders = ( (ULONG_PTR)&(pNtHeader)->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader); // TODO: ?


	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ctx->pNtHeaders);


	// Copy the contents of each section 
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		srcPtr = (PBYTE)(ctx->rawImageBase + pSectionHeader->PointerToRawData); 
		dstPtr = (PBYTE)(ctx->baseAddress + pSectionHeader->VirtualAddress);
		//dstPtr = (PBYTE)(baseAddress + pSectionHeader->VirtualAddress);

		// copy the section over
		// NOTE: how many bytes we need to copy over (this is the section's size)
		DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;

		// Copy the contents of the current section
		while (SizeOfRawData--)
		{
			*dstPtr++ = *srcPtr++;
		}
	}

	return TRUE;
}



BOOL applyReflectiveRelocations(PLOADER_CONTEXT ctx)
{
	///////////////////////////////////////////////////////////
	// NOTE: we don't need to check if the preferred image base is available because since
	// we are using VirtualAlloc to allocate a new memory block, we perform relocations everytime.
	// Using VirtualAlloc means that we will always have memory avaiable to us; however, we wont know 
	// where VirtualAlloc will place the DLL. And most of the time the memory region chosen by Windows
	// (when we call VirtualAlloc) will not match the preferred base in the PE header.

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// TODO: should rename rawImageBase or use a different variable name. the variable should be called 
	// maybe something like "relocationOffset" or something

	ULONG_PTR relocationDelta = ctx->baseAddress - ctx->pNtHeaders->OptionalHeader.ImageBase; 
	// TODO: skip relocation logic if relocationDelta returns 0  
	// if (relocationDelta == 0) then skip next part


	// NOTE: get IMAGE_DATA_DIRECTORY for relocation table. uiValueB is type _IMAGE_DATA_DIRECTORY
	// which has a field called VirtualAddress which gives a relative address to the relocation table
	// relative to the image base
	// TODO: rename to baseRelocDir or pRelocDir
	PIMAGE_DATA_DIRECTORY pRelocDir = &ctx->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; 
	//PIMAGE_DATA_DIRECTORY pRelocDir = &(ctx->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]); 

	// NOTE: relocations are stored in relocation "blocks" IMAGE_BASE_RELOCATION. each
	// relocation block contains a number of different relocations (which can be obtained from SizeOfBlock). 
	// IMAGE_BASE_RELOCATION blocks are a thing so windows doesn't have to store every single relocation
	// needed one after another in a continguous block of memory

	// PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(baseAddress + pRelocDir->VirtualAddress); NOTE: equivalent to relocBlock
	// TODO:

	// check if their are any relocation blocks (IMAGE_BASE_RELOCATION) present
	// TODO: add better comment
	if (pRelocDir->Size)
	{
		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(ctx->baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress); // TODO: this might cause future problems? 
		// baseAddressBuffer = (baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);

		// and we itterate through all entries...
		// NOTE: we can do this because windows api says the IMAGE_BASE_RELOCATION blocks are terminated
		// by a NULL relocation block, meaning SizeOfBlock will be 0 when we want to stop looking/relocating
		//while (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock)
		for (; relocBlock->SizeOfBlock; relocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)relocBlock + relocBlock->SizeOfBlock))
		{
			// uiValueA = the VA for this relocation block
			//iatAddress = (baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress);
			ULONG_PTR relocBlockBase = (ULONG_PTR)(ctx->baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress); // relocBlockBaseAddress

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
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!

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

			}
		}
	}

	return TRUE;
}

BOOL resolveReflectiveImports(PLOADER_CONTEXT ctx)
{
	// TODO: should check if pImportDir->Size != 0 ? 
	PIMAGE_DATA_DIRECTORY pImportDir = &(ctx->pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; 

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	// NOTE: uiValueC should now point to PIMAGE_IMPORT_DESCRIPTOR
	// TODO: rename to PIMAGE_IMPORT_DESCRIPTOR importDesc
	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ctx->baseAddress + ((PIMAGE_DATA_DIRECTORY)pImportDir)->VirtualAddress);

	ULONG_PTR importModuleBase;
	//DWORD iatAddress; // TODO: change to type PIMAGE_THUNK_DATA?

	// itterate through all imports
	// NOTE: Name is an RVA to the name as a string
	// NOTE: we can do this because the import table is NULL-terminated by an array of IMAGE_IMPORT_DESCRIPTOR
	// NOTE: we're looping through all the imports because we're resolving all the imports/dlls that our 
	// reflective dll depends on. (we're resolving by calling getprocaddress)


	// TODO: Resolve imports (fix this comment) 
	for (; importDesc->Name; ++importDesc) // TODO: how does this for loop know when to stop? 
	{
		// use LoadLibraryA to load the imported module into memory
		importModuleBase = (ULONG_PTR)ctx->pLoadLibraryA((LPCSTR)(ctx->baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->Name));

		// TODO: remove? i don't think case will evere happen
		if (!importModuleBase) 
		{
			continue;
		}

		PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(ctx->baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		PIMAGE_THUNK_DATA iatAddress = (PIMAGE_THUNK_DATA)(ctx->baseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)importDesc)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		for (; iatAddress->u1.AddressOfData; ++iatAddress, ++originalThunk) // TODO: how does this for loop know when to stop? 
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// NOTE: i can remove this if block if ik for certain my compiler isn't only importing by first thunk
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
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(ctx->baseAddress + iatAddress->u1.AddressOfData);
				// rawImageBaseBuffer = (baseAddress + DEREF(iatAddress)); // TODO: rename to importFuncAddress?

				// use GetProcAddress and patch in the address for this imported function
				// TODO: use GetProcAddressManual() instead?
				iatAddress->u1.Function = (ULONG_PTR)ctx->pGetProcAddress((HMODULE)importModuleBase, (LPCSTR)importByName->Name);
			}
		}
	}
	return TRUE;
}


//BOOL callEntryPoint(PLOADER_CONTEXT ctx)
ULONG_PTR callReflectiveEntryPoint(PLOADER_CONTEXT ctx)
{
	// Call our images entry point

	ULONG_PTR entryAddress = (ctx->baseAddress + ctx->pNtHeaders->OptionalHeader.AddressOfEntryPoint); // TODO: rename variable

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	ctx->pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	//((DLLMAIN)entryAddress)((HINSTANCE)ctx->baseAddress, DLL_PROCESS_ATTACH, lpParameter); // TODO: breaking here? 
	((DLLMAIN)entryAddress)((HINSTANCE)ctx->baseAddress, DLL_PROCESS_ATTACH, NULL);

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
	return entryAddress; 

}



// TODO: this needs extern "C" if i ever plan to use c++
// ReflectiveLoader() function that external stager calls
// DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved)
//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
// TODO: rename function? 
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) // TODO: remove WINAPI and replace with __cdecl to prevent name mangling
{
	// TODO: 
	LOADER_CONTEXT ctx = {0};
	//initializeContext(&ctx);
	initializeReflectiveContext(&ctx);
	//resolveReflectiveDependencies(&ctx);
	resolveDependencies(&ctx);
	copyImageIntoMemoryReflective(&ctx);
	applyReflectiveRelocations(&ctx);
	resolveReflectiveImports(&ctx);
	return callReflectiveEntryPoint(&ctx);

}



/*

TODO: load data that exists 
LoadEngineThread();
    - locates the engine dll bytes inside host.dll's memory storeage

MapModuleFromMemory();

EngineEntry() optional export inide engine dllpoint 


*/
