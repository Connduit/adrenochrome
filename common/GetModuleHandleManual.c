#include "GetModuleHandleManual.h"
#include "ReflectiveLoader.h"

char chrtoupper_i(char c)
{
    if (c >= 'a' && c <= 'z')
        c -= 'a' - 'A';
    return c;
}

int strcmp_i(const char* a, const char* b, size_t n)
{
    char ca, cb;
    for (;;)
    {
        ca = *a;
        cb = *b;
        if (ca != cb || (n > 0 && --n == 0))
            return ca - cb;

        if (ca == 0)
            return 0;

        a++;
        b++;
    }
}

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

        // TODO: fix this string comparison... don't have access to it in a reflective loader
        //if (pDataTableEntry->BaseDllName.Buffer == lpModuleName)
        //if (_wcsicmp(pDataTableEntry->BaseDllName.Buffer, lpModuleName) == 0)
        // TODO: function isn't comparing properly
        if (strcmp_i(pDataTableEntry->BaseDllName.Buffer, lpModuleName, pDataTableEntry->BaseDllName.Length) == 0)
        {
	        return RDI_ERR_MY_CUSTOM_ERROR;
            //return (HMODULE)pDataTableEntry->DllBase;
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
