#ifndef AXE_STRUCTS_H
#define AXE_STRUCTS_H

typedef struct _AXE_HEADER {
    DWORD Magic;             // e.g., 0x58454121 = "AXE!" (NOT MZ)
    WORD  Version;           // Format version
    WORD  ModuleType;        // Engine = 0, Module = 1, etc.

    DWORD ImageSize;         // How much memory to allocate
    DWORD EntryPointRVA;     // Offset to the entry function inside the image

    DWORD SectionCount;      // Number of sections
    DWORD SectionTableOffset;// Offset to custom section descriptors

    DWORD RelocOffset;       // Offset to relocations (AXE-specific format)
    DWORD RelocCount;        

    DWORD ImportOffset;      // Offset to hashed imports
    DWORD ImportCount;

    DWORD Flags;             // encryption flags, compression, etc.
    DWORD Reserved;          // padding / future use
} AXE_HEADER;

typedef struct _AXE_SECTION {
    DWORD RVA;               // where to map it
    DWORD Size;              // virtual size
    DWORD Offset;            // offset in AXE file
    DWORD Characteristics;   // RWX flags
} AXE_SECTION;

typedef struct _AXE_IMPORT {
    DWORD Hash;          // Adler32 hash of function name
    DWORD Offset;        // Where to write the resolved address
    DWORD DllHash;       // Hash of DLL name (optional)
} AXE_IMPORT;


#endif
