#ifndef AXE_STRUCTS_H
#define AXE_STRUCTS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline


// TODO: need to add #pragma pack(push, 1) and #pragma pack(pop) ? 

typedef struct _AXE_HEADER {
    // TODO: add default constructor for this? 


    WORD Magic;             // e.g., 0x58454121 = "AXE!" (NOT MZ) // TODO: rename to e_magic
    //WORD Version;           // Format version
    // WORD  ModuleType;        // Engine = 0, Module = 1, etc.

    // DWORD SizeOfImage;       // How much memory to allocate
    //DWORD SizeOfAxe;       // How much memory to allocate for the axe // optional? this would only be used by the loader
    //DWORD EntryPointRVA;     // Offset to the entry function inside the image // TODO: rename for consistency. this would only be used by the loader? 

    WORD NumberOfSections;      // Number of sections
    // DWORD SectionTableOffset; // Offset to custom section descriptors (sizeof(AXE_HEADER)) // NOTE: only used by loader

    //DWORD RelocOffset;       // Offset to relocations (AXE-specific format) // NOTE: only used by loader
    WORD NumberOfRelocations;        

   //  DWORD ImportOffset;      // Offset to hashed imports // NOTE: only used by loader
    WORD NumberOfImports;      // Number of imports

    // DWORD Flags;             // encryption flags, compression, etc.
    // DWORD Reserved;          // padding / future use 
} AXE_HEADER, *PAXE_HEADER;

typedef struct _AXE_SECTION {
    char Name[8];           // name of section (null-padded). technically optional if i decide to hard code section order logic in loader. (hash/obufuscate name)
    // DWORD RVA;               // where to map it (optional)? 
    DWORD Size;              // virtual size
    DWORD Offset;            // offset in AXE file
    ULONG_PTR memoryAddress; // ULONG_PTR? // needed by the custom loader 
    // DWORD Characteristics;   // RWX flags (technically optional)
} AXE_SECTION, *PAXE_SECTION;

typedef struct _AXE_IMPORT {
    const char* moduleName;     // original module name // TODO: change to hash
    const char* functionName;   // original function name (can be ordinal too?) // TODO: change to hash
    void** patchAddress;        // where to write resolved address
    const char* forwarderName;  // optional, "OtherModule.Func" if forwarded // TODO: change to hash
} AXE_IMPORT, *PAXE_IMPORT;

// TODO: (not implemented, optional) 
typedef struct _AXE_RELOCATION
{
    DWORD sectionIndex;  // which section this relocation applies to
    DWORD offset;        // offset inside section to patch
    DWORD type;          // e.g., 32-bit or 64-bit relocation
} AXE_RELOCATION, *PAXE_RELOCATION;

typedef struct _AXE_CONTEXT {
    AXE_HEADER axeHeader;
    AXE_SECTION axeSection;
    AXE_IMPORT axeImport;
    AXE_RELOCATION axeRelocation;
    // Section Data Blobs
} AXE_CONTEXT, *PAXE_CONTEXT;


#endif
