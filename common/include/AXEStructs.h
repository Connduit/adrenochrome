#ifndef AXE_STRUCTS_H
#define AXE_STRUCTS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline

typedef struct _AXE_HEADER {
    DWORD Magic;             // e.g., 0x58454121 = "AXE!" (NOT MZ) // TODO: rename to e_magic?
    //DWORD Magic;           // tells us if pe is 32 or 64 
    WORD  Version;           // Format version
    WORD  ModuleType;        // Engine = 0, Module = 1, etc.

    DWORD SizeOfImage;       // How much memory to allocate
    DWORD SizeOfAxe;       // How much memory to allocate for the axe // TODO: use this instead of sizeofimage
    DWORD EntryPointRVA;     // Offset to the entry function inside the image // TODO: rename for consistency

    DWORD SectionCount;      // Number of sections
    DWORD SectionTableOffset;// Offset to custom section descriptors // NOTE: should just be at the end of this struct right? 

    DWORD RelocOffset;       // Offset to relocations (AXE-specific format)
    DWORD RelocCount;        

    DWORD ImportOffset;      // Offset to hashed imports
    DWORD ImportCount;

    DWORD Flags;             // encryption flags, compression, etc.
    DWORD Reserved;          // padding / future use
} AXE_HEADER, *PAXE_HEADER;

typedef struct _AXE_SECTION {
    DWORD RVA;               // where to map it
    DWORD Size;              // virtual size
    DWORD Offset;            // offset in AXE file
    DWORD Characteristics;   // RWX flags
} AXE_SECTION, *PAXE_SECTION;

typedef struct _AXE_IMPORT {
    DWORD Hash;          // Adler32 hash of function name
    DWORD Offset;        // Where to write the resolved address
    DWORD DllHash;       // Hash of DLL name (optional)
} AXE_IMPORT, *PAXE_IMPORT;

typedef struct _AXE_CONTEXT {
    AXE_HEADER axeHeader;
    AXE_SECTION axeSection;
    AXE_IMPORT axeImport;
} AXE_CONTEXT, *PAXE_CONTEXT;


#endif
