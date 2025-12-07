#include "GetModuleHandleManual.h"
#include "ReflectiveLoader.h"

HMODULE GetModuleHandleManual(LPCWSTR lpModuleName)
{
    //PPEB PebAddress = getPeb();
#if defined(_WIN64)
		PPEB PebAddress = (PPEB)__readgsqword(0x60);
		//PPEB PebAddress = reinterpret_cast<PPEB>(__readgsqword(0x60)); // c++ only
#else 
		PPEB PebAddress = (PPEB)__readgsqword(0x30);
		//PPEB PebAddress = reinterpret_cast<PPEB>(__readgsqword(0x30)); // c++ only
#endif

    CHAR ModuleName[MAX_PATH] = { 0 }; // TODO: is this = {0} needed?


    //PVOID pModule = nullptr;

    PLIST_ENTRY pListHead = &PebAddress->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY pList = PebAddress->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pDataTableEntry; // TODO: does this need to be initialized to nullptr?

    while (pList != pListHead)
    {
        pDataTableEntry = CONTAINING_RECORD(pList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        //if (pDataTableEntry->BaseDllName.Buffer == lpModuleName)
        if (_wcsicmp(pDataTableEntry->BaseDllName.Buffer, lpModuleName) == 0)
        {
            return (HMODULE)pDataTableEntry->DllBase;
        }
        pList = pList->Flink;
    }

    return NULL;
    //return pModule;
}

/*
HMODULE GetModuleHandleManual(DWORD moduleHash)
{
    return NULL;
}
*/
