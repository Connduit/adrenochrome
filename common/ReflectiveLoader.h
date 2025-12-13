/* ReflectiveLoader.h */
// TODO: defined all the structs/types needed 

#ifndef REFLECTIVE_LOADER_H
#define REFLECTIVE_LOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // TODO: eventually remove



#define DLL_QUERY_HMODULE 6

#define DEREF( name  )*(UINT_PTR *)(name)
#define DEREF_64( name  )*(DWORD64 *)(name)
#define DEREF_32( name  )*(DWORD *)(name)
#define DEREF_16( name  )*(WORD *)(name)
#define DEREF_8( name  )*(BYTE *)(name)

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT __declspec(dllexport)

typedef HMODULE (WINAPI* LOADLIBRARYA)
(LPCSTR lpLibFileName);

typedef FARPROC (WINAPI* GETPROCADDRESS)
(HMODULE hModule, LPCSTR lpProcName);

typedef LPVOID (WINAPI* VIRTUALALLOC)
(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

typedef DWORD (NTAPI* NTFLUSHINSTRUCTIONCACHE)
(HANDLE hProcess, PVOID lpBaseAddress, ULONG dwSize);



///////////////////////////////////////////////////
// Custom sRDI
#ifdef CUSTOM_SRDI
// TODO: declare custom srdi functions here
// ULONG_PTR LoadDLL(PBYTE pbModule, DWORD dwFunctionHash, LPVOID lpUserData, DWORD dwUserdataLen, PVOID pvShellcodeBase, DWORD dwFlags);
#endif
///////////////////////////////////////////////////
///////////////////////////////////////////////////
#define RDI_ERR_BASE 0xE0000000
#define RDI_SUCCESS (0x00000001)
#define RDI_ERR_FIND_IMAGE_BASE (RDI_ERR_BASE | 0x1000)
#define RDI_ERR_RESOLVE_DEPS (RDI_ERR_BASE | 0x2000) // Generic dependency failure
#define RDI_ERR_ALLOC_MEM (RDI_ERR_BASE | 0x3000)
// Granular codes for dependency resolution:
#define RDI_ERR_NO_KERNEL32 (RDI_ERR_BASE | 0x2100)		 // Failed to find kernel32.dll by hash
#define RDI_ERR_NO_NTDLL (RDI_ERR_BASE | 0x2200)		 // Failed to find ntdll.dll by hash
#define RDI_ERR_NO_EXPORTS (RDI_ERR_BASE | 0x2300)		 // Found kernel32, but couldn't find required exports
#define RDI_ERR_GETSYSCALLS_FAIL (RDI_ERR_BASE | 0x2400) // getSyscalls() failed
// My Custom Codes
#define RDI_ERR_MY_CUSTOM_ERROR (RDI_ERR_BASE | 0x4000) // 
///////////////////////////////////////////////////

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

// TODO: move all pe struct related info into its own header file called "PEStructs.h"

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks; // PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks; // PVOID Reserved2[2];
    PVOID DllBase; // pointer to the base address of where the DLL/module is loaded
    PVOID EntryPoint;
	ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID Reserved5[3];
    union
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    //PVOID EntryInProgress;
	//#if (NTDDI_VERSION >= NTDDI_WIN7)
    //UCHAR ShutdownInProgress;
    //PVOID ShutdownThreadId;
} PEB_LDR_DATA,*PPEB_LDR_DATA;

// TODO: this struct isn't needed? we only need Ldr anyways... might have to uncomment to avoid using certain #includes tho
// If it matters: https://github.com/HavocFramework/Havoc/blob/main/payloads/DllLdr/Include/Native.h#L41
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2]; // TODO: ImageBaseAddress?
	PPEB_LDR_DATA Ldr;
    /*
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
    */
} PEB,*PPEB;

/* 64bit
typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[520];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
} PEB;
*/

typedef struct
{
    WORD	offset : 12; // lower 12 bits
    WORD	type : 4; // upper 4 bits
} IMAGE_RELOC, *PIMAGE_RELOC;

#endif
