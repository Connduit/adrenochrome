#ifndef ADRENOCHROME_BUILDER_H
#define ADRENOCHROME_BUILDER_H

#include "AXEStructs.h"

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

	void writeToStream(AXE_HEADER header); // update header 
	void writeToStream(AXE_SECTION section); // update section
	void writeToStream(std::vector<AXE_SECTION> sections); // update sections
	// void writeToStream( TODO ); // update/write section contents


	void encrypt();
	void compress();
	void pack(); // pack struct into raw bytes (serializer function)

	// TODO: rename function?
	bool createAXE(std::string path="./loader.axe");
	bool createAXE(std::string path, std::vector<uint8_t>& buffer); // TODO: typedef vector<uint8_t>

	ULONG_PTR rawImageBase_; // TODO: rename to 
	//ULONG_PTR baseAddress_;  // TODO: ? 
	//ULONG_PTR currentAddress_; // NOTE: the current address ("location") we're writing to (within the baseaddress)
	PAXE_CONTEXT ctx_;

	std::ofstream outfileStream_;

	//std::string inputFilename;
	std::string outputFilename_;

	std::vector<uint8_t> outBuffer_;


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
