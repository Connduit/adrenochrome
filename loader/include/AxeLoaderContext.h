#ifndef AXE_LOADER_CONTEXT_H
#define AXE_LOADER_CONTEXT_H

#include "AXEStructs.h"

// TODO: maybe turn this into just an "in-memory" version? 
typedef struct _AXE_LOADER_CONTEXT {
    AXE_HEADER axeHeader;
    AXE_SECTION* axeSections;
    AXE_IMPORT* axeImports;
    AXE_RELOCATION* axeRelocations;
    // Section Data Blobs
    // void* ImageBase? or should this be in AXE_HEADER? 
} AXE_LOADER_CONTEXT, *PAXE_LOADER_CONTEXT;


#endif
