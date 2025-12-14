#include "GetProcAddressManual.h"
#include "ReflectiveLoader.h"


// TODO: rename pModule to hModule?
//FARPROC GetProcAddressManual(PVOID pModule, LPCSTR lpProcName)
DWORD GetProcAddressManual(PVOID pModule, DWORD procHash, FARPROC* prod)
{
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModule + ((PIMAGE_DOS_HEADER)pModule)->e_lfanew);
	DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModule + dwExportDirRVA);

	DWORD* arrayOfFunctionRVAs = (DWORD*)((ULONG_PTR)pModule + pExportDir->AddressOfFunctions);
	DWORD* arrayOfNamesRVAs = (DWORD*)((ULONG_PTR)pModule + pExportDir->AddressOfNames);
	WORD* arrayOfNameOrdinals = (WORD*)((ULONG_PTR)pModule + pExportDir->AddressOfNameOrdinals);

	DWORD numNames = pExportDir->NumberOfNames;
	//for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
	for (DWORD i = 0; i < numNames; ++i)
	{
		char* prodName = (char*)((ULONG_PTR)pModule + arrayOfNamesRVAs[i]);
		//WORD ordinalIndex = arrayOfNameOrdinals[i];
		//FARPROC functionAddress = (FARPROC)((ULONG_PTR)pModule + arrayOfFunctionRVAs[ordinalIndex]);

		// TODO: replace with better hasing algorithm
        if ((DWORD)hash(prodName) == procHash)
		{
			*prod = (FARPROC)((ULONG_PTR)pModule + arrayOfFunctionRVAs[arrayOfNameOrdinals[i]]);
			return RDI_SUCCESS;
		}
	}
	return RDI_ERR_RESOLVE_DEPS;
}
