#ifndef AXE_BUILDER_CONTEXT_H
#define AXE_BUILDER_CONTEXT_H

#include "AXEStructs.h"

#include <vector>


// TODO: Position Independent AXE File Structure

// TODO: maybe turn this into just an "in-memory" version? 
typedef struct _AXE_BUILDER_CONTEXT {
    AXE_HEADER axeHeader;
    std::vector<AXE_SECTION> axeSections; // Section Header
    std::vector<AXE_IMPORT> axeImports;
    std::vector<AXE_RELOCATION> axeRelocations;
    // Section Data Blobs
} AXE_BUILDER_CONTEXT, *PAXE_BUILDER_CONTEXT;

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
