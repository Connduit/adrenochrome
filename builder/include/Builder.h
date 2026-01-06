#ifndef ADRENOCHROME_BUILDER_H
#define ADRENOCHROME_BUILDER_H

#include "AxeBuilderContext.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline

#include <cstdint> 
#include <string>
#include <vector>

#include <fstream>
#include <iostream>

/*
TODO: remove: 
- dos header and stub (IMAGE_DOS_HEADER)
- nt headers (IMAGE_NT_HEADERS)
- section headers (IMAGE_SECTION_HEADER)
	- not entirely tho, should be "flattened?" and maybe re-encoded?
- import address table 
- export table? (engine.axe would need to be exported to other modules?)
- relocation table? they might be needed?
- tls directory and callbacks
- debug directory and symbols
- resource section (.rsrc)
- manifest

TODO: keep:
- .text... maybe encrypt this?
- .rdata
- .data
- entry point related info
- minimal metadata 
- custom features (other needed stuff?)
*/

// TODO: make subclasses, one for .axe files and one for .dll files?
// or just add both functionality here?
// NOTE: the .dll file builder makes small obfuscation adjustments but 
// maintains the .dll structure unlike a .axe file 
class AdrenochromeBuilder
{
public:

	// TODO: add enums to see what type of dll we're loading?


	AdrenochromeBuilder(); // : baseAddress_() {}
	~AdrenochromeBuilder();

	//static void loadFile(std::string& path);
	//static void loadFile(LPCWSTR path);
	void loadFile(LPCWSTR path); // TODO: change return type
	void loadFile(std::string& path); // TODO: change return type
	
	// TODO: should be the only public function?
	void build();
private:
	void initializeContext();
	void populateContext();
	//void createContextInMemory(); // TODO: ??? virtuallloc is done here?

	//void createHeader();
	void updateHeader();
	void updateSectionHeaders();
	void updateSectionsData();
	void updateRelocations();

	// 
	//BOOL keepSection(ULONG_PTR addr);
	// return the name of section that corresponds with the addr
	std::string keepSection(ULONG_PTR addr);

	//
	DWORD Rva2Offset(DWORD dwRva);
	DWORD Offset2Rva(DWORD dwOffset);

	//DWORD findFunctionAddress(VOID* buffer);
	DWORD findFunctionAddress(void);

	PIMAGE_SECTION_HEADER getPESection(DWORD dwRva);
	//PAXE_SECTION getAXESection(DWORD dwRva);
	PAXE_SECTION getAXESection(PIMAGE_SECTION_HEADER pSectionHeader);

	BOOL SectionNamesEqual(const IMAGE_SECTION_HEADER& peSection, const AXE_SECTION& axeSection);

	//ULONG_PTR calculateEntryPoint(); // TODO: rename to calculateAddressOfEntryPoint() ? 
	void calculateEntryPoint(); // TODO: rename to calculateAddressOfEntryPoint() ? 

	void encrypt();
	void compress();
	void pack(); // pack struct into raw bytes (serializer function) // remove? 

	// TODO: rename function?
	bool createAXE();

	// NOTE: since we're using MapViewOfFile to get this var
	// we must treat it as the same layout as when the pe is on 
	// the disk (and not virtualalloc'd in memory)
	ULONG_PTR rawImageBase_; 
	//ULONG_PTR baseAddress_;  // TODO: ? 
	//ULONG_PTR currentAddress_; // NOTE: the current address ("location") we're writing to (within the baseaddress)
	AXE_BUILDER_CONTEXT ctx_;

	std::ofstream outfileStream_;

	//std::string inputFilename;
	std::string outputFilename_;

	// Pointer to where we're writing to in our outfileStream
	uint32_t cursor_;


	//
	HANDLE hFile_;
	HANDLE hMap_;
	LPVOID lpView_;
	
	//

	// TODO:
	DWORD SectionAlignment;
	DWORD FileAlignment;
	//

	// TODO: add offsets to start of headers, sections, data, etc... to this class 
	// so i don't have to store them inside the AXE_STRUCTS


	// std::vector<AXE_SECTION> axeSections_; // TODO: maybe add this? 

	// const fileAlignment = 0x200
	// const sectionAlignment = 0x1000 (not needed for builder... just remeber that this is what windows will use)

	// TODO: add some config struct that keeps track of the following (or maybe just add it to argv parameters
	// but could still use a config file? just had argv parameters populate the config file if params are provided,
	// otherwise use default config):
	// - names of the sections we want to keep
	// - output path and name of output file ()
	// - type of encryption, compression, and hashing
	// - choose what information we want to keep/strip from originally pe
	// BUILD_CONFIG config_;

};


#endif