#ifndef AXE_LOADER_CONTEXT_H
#define AXE_LOADER_CONTEXT_H

#include "AXEStructs.h"

#define BASE_ADDRESS 0x180000000 // TODO: remove? we always address returned from VirtualAlloc?

// TODO: maybe turn this into just an "in-memory" version? 
typedef struct _AXE_LOADER_CONTEXT {
    AXE_HEADER axeHeader;
    AXE_SECTION* axeSections;
    AXE_IMPORT* axeImports;
    AXE_RELOCATION* axeRelocations;
    // Section Data Blobs
    // void* ImageBase? or should this be in AXE_HEADER? 
} AXE_LOADER_CONTEXT, *PAXE_LOADER_CONTEXT;

/*
AXE_HEADER
AXE_SECTION.text
AXE_SECTION.rdata
AXE_SECTION.data
AXE_SECTION.reloc
AXE_IMPORT // NULL
.text Data
.rdata Data
.data Data
.reloc AXE_RELOCATION
*/

#endif
