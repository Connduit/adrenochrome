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

		// TODO: idk if case-insensitive strcmp is needed on here
		// printf("prodName = %s\n", prodName);
		//if (_stricmp(lpProcName, prodName) == 0)
        if ((DWORD)hash(prodName) == procHash)
		{
			*prod = (FARPROC)((ULONG_PTR)pModule + arrayOfFunctionRVAs[arrayOfNameOrdinals[i]]);
			return RDI_SUCCESS;
			//return (FARPROC)((ULONG_PTR)pModule + arrayOfFunctionRVAs[ordinalIndex]);
			//return functionAddress;
		}


        /*
        if (prodName[0] == 'L' && prodName[1] == 'o' && prodName[2] == 'a' && prodName[3] == 'd' &&
            prodName[4] == 'L' && prodName[5] == 'i' && prodName[6] == 'b' && prodName[7] == 'r' &&
            prodName[8] == 'a' && prodName[9] == 'r' && prodName[10] == 'y' && prodName[11] == 'A' && prodName[12] == '\0')
        {
            pContext->pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
        }
        //else if (dwHashValue == GETPROCADDRESS_HASH)
        //else if (strcmp(prodName, "GetProcAddress") == 0)
        else if (prodName[0] == 'G' && prodName[1] == 'e' && prodName[2] == 't' && prodName[3] == 'P' &&
            prodName[4] == 'r' && prodName[5] == 'o' && prodName[6] == 'c' && prodName[7] == 'A' &&
            prodName[8] == 'd' && prodName[9] == 'd' && prodName[10] == 'r' && prodName[11] == 'e' &&
            prodName[12] == 's' && prodName[13] == 's' && prodName[14] == '\0')
                return (HMODULE)pDataTableEntry->DllBase;
        {*/
	}
	return RDI_ERR_RESOLVE_DEPS; // TODO: 
	return NULL;
}
