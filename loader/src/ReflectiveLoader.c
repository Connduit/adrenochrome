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


// TODO: this needs extern "C" if i ever plan to use c++
// ReflectiveLoader() function that external stager calls
// DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpReserved)
//DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
// TODO: rename function? 
DLLEXPORT DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) // TODO: remove WINAPI and replace with __cdecl to prevent name mangling
{
	// ULONG_PTR baseAddress = // TODO: calculate
	// ManualMap((LPVOID)baseAddress);
	// TODO: 
	/*
	LOADER_CONTEXT ctx = {0};
	//initializeContext(&ctx);
	initializeReflectiveContext(&ctx);
	resolveDependencies(&ctx);
	copyImageIntoMemory(&ctx);
	applyRelocations(&ctx);
	resolveImports(&ctx);
	return callEntryPoint(&ctx);
	*/
	LOADER_CONTEXT ctx = { 0 };

	// Use lpParameter as the raw image base instead of caller()
	ctx.rawImageBase = (ULONG_PTR)lpParameter;

	// Find NT headers
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ctx.rawImageBase;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
		return 10;

	ctx.pNtHeaders = (PIMAGE_NT_HEADERS)(ctx.rawImageBase + pDos->e_lfanew);
	if (ctx.pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 11;

	// Now continue with the rest
	DWORD status = resolveDependencies(&ctx);
	if ((status & 0xF0000000) == 0xE0000000)
		return 20;

	if (!copyImageIntoMemory(&ctx))
		return 30;

	if (!applyRelocations(&ctx))
		return 40;

	if (!resolveImports(&ctx))
		return 50;

	return callEntryPoint(&ctx);

}



/*

TODO: load data that exists 
LoadEngineThread();
    - locates the engine dll bytes inside host.dll's memory storeage

MapModuleFromMemory();

EngineEntry() optional export inide engine dllpoint 


*/
