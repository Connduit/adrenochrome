#include "GetModuleHandleManual.h"
#include "ReflectiveLoader.h"


//HMODULE GetModuleHandleManual(LPCWSTR lpModuleName)
//DWORD GetModuleHandleManual(LPCWSTR lpModuleName, HMODULE* hModule)
DWORD GetModuleHandleManual(DWORD moduleHash, HMODULE* hModule)
{
    //PPEB PebAddress = getPeb();
#if defined(_WIN64)
		PPEB PebAddress = (PPEB)__readgsqword(0x60);
		//PPEB PebAddress = reinterpret_cast<PPEB>(__readgsqword(0x60)); // c++ only
#else 
		PPEB PebAddress = (PPEB)__readgsqword(0x30);
		//PPEB PebAddress = reinterpret_cast<PPEB>(__readgsqword(0x30)); // c++ only
#endif

    //PVOID pModule = nullptr;

    PLIST_ENTRY pListHead = &PebAddress->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pList = PebAddress->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pDataTableEntry = NULL; // TODO: does this need to be initialized to nullptr?

    while (pList != pListHead)
    {
        pDataTableEntry = CONTAINING_RECORD(pList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        ULONG_PTR buffer = (ULONG_PTR)(pDataTableEntry->BaseDllName.Buffer);
        USHORT usCounter = pDataTableEntry->BaseDllName.Length;
        ULONG_PTR hashResult = 0;

		// TODO: create/use better hashing alg
        do
        {
            hashResult = ror((DWORD)hashResult);
            // normalize to uppercase if the madule name is in lowercase
            if (*((BYTE*)buffer) >= 'a')
                hashResult += *((BYTE*)buffer) - 0x20;
            else
                hashResult += *((BYTE*)buffer);
            buffer++;
        } while (--usCounter);


        if ((DWORD)hashResult == moduleHash)
        {
			*hModule = (HMODULE)pDataTableEntry->DllBase;
            return RDI_SUCCESS;
        }

		pList = pList->Flink;
    }

    return RDI_ERR_GET_MODULE_FAILS;
}
