#ifndef ADRENOCHROME_BUILDER_H
#define ADRENOCHROME_BUILDER_H

#include "AXEStructs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h> // NOTE: needed for __forceinline

#include <cstdint> 
#include <string>
#include <vector>

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

class AdrenochromeBuilder
{
public:
	AdrenochromeBuilder(); // : baseAddress_() {}
	//~AdrenochromeBuilder();

	//static void loadFile(std::string& path);
	//static void loadFile(LPCWSTR path);
	void loadFile(LPCWSTR path); // TODO: change return type
	
	// TODO: should be the only public function?
	void build();
private:
	void populateContext();
	//void createContextInMemory(); // TODO: ??? virtuallloc is done here?
	void encrypt();
	void compress();
	void pack(); // pack struct into raw bytes (serializer function)

	// TODO: rename function?
	bool createAXE(std::string path);
	bool createAXE(std::string path, std::vector<uint8_t>& buffer); // TODO: typedef vector<uint8_t>

	ULONG_PTR rawImageBase_; // TODO: rename to 
	//ULONG_PTR baseAddress_;  // TODO: ? 
	//ULONG_PTR currentAddress_; // NOTE: the current address ("location") we're writing to (within the baseaddress)
	PAXE_CONTEXT ctx_;

	//std::string inputFilename;
	std::string outputFilename_;

	std::vector<uint8_t> outBuffer_;


};


#endif
