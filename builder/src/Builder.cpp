#include "Builder.h"
#include "AxeConfig.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>

AdrenochromeBuilder::AdrenochromeBuilder()
	: rawImageBase_(0)
	  // baseAddress_(0),
	  //ctx_(nullptr)
{
	// LOGGING STUFF?
}

void AdrenochromeBuilder::build()
{
	// TODO: main function
	createAXE(); // check return type
	populateContext(); // change function type from void so i can check return type
}

// void AdrenochromeBuilder::loadFile(std::string& path)
// void AdrenochromeBuilder::loadFile(const std::wstring& path)
//  TODO: change return type?
void AdrenochromeBuilder::loadFile(LPCWSTR path)
{
	HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		// TODO: throw helpful error
		return;
	}

	HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap == NULL)
	{
		// TODO: throw helpful error
		return;
	}

	// NOTE: lpView is the baseAddress... TODO: rename var?
	// TODO: store this var as a class variable?
	LPVOID lpView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

	if (lpView != NULL)
	{
		rawImageBase_ = (ULONG_PTR)lpView;
	}
	else
	{
		// TODO: throw helpful error
	}
}

// TODO: do i even need a axe_struct? will def help with organizing and future
// proofing but what if i just did a virtualalloc using the SizeOfImage and just
// wrote everything i want to keep into that buffer. And then kept track of how
// many bytes i wrote to that buffer. and then just wrote all the bytes from
// virtualalloc_baseAddress to virtualalloc_baseAddress + nBytes to some file on
// disk that would be my .axe file
void AdrenochromeBuilder::populateContext()
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	// TODO: need to do sizeofimage - sizeofheaders? (if we plan on removing
	// headers)
	// ctx_->axeHeader.SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	// TODO: im pretty sure this will be wrong since im stripping a bunch of parts
	// of the dll. the entry point will have to be manually calculated
	// ctx_->axeHeader.EntryPointRVA =
	// pNtHeaders->OptionalHeader.AddressOfEntryPoint; // TODO: for should i just
	// return absolute?

	//////////////////////////////////////////////////
	// AXE_HEADER
	ctx_.axeHeader.Magic = 0xBEEF;
	// ctx_->axeHeader.NumberOfSections = 3; // TODO: should start o
	ctx_.axeHeader.NumberOfSections = 0;
	ctx_.axeHeader.NumberOfRelocations = 0;
	ctx_.axeHeader.NumberOfImports = 0;

	// NOTE: assume outfileStream_ is not null
	outfileStream_.write(reinterpret_cast<const char *>(&ctx_.axeHeader), sizeof(ctx_.axeHeader));
	// outfileStream_.write(reinterpret_cast<const char*>(&(ctx_->axeHeader)),
	// sizeof(ctx_->axeHeader));

	// TODO: create a function to generate an axe_section vector
	std::vector<AXE_SECTION> axeSections;
	AXE_SECTION text{};
	memcpy(text.Name, ".text", 5);
	text.memoryAddress = 0x1000; // starting addr? (this is an RVA?)
	text.Offset = 0;			 // raw offset (we will fill this later)
	text.Size = 0;				 // raw size (we will fill this later)
	axeSections.push_back(text);

	ctx_.axeHeader.NumberOfSections++;
	// TODO: make a write function to handle moving the outfilestream ptr around
	outfileStream_.seekp(0, std::ios::beg);															 // move outfilestream ptr to beginning on file
	outfileStream_.write(reinterpret_cast<const char *>(&ctx_.axeHeader), sizeof(ctx_.axeHeader)); // overwrite with updated header

	// outfileStream_.seekp(ctx_->axeHeader.SectionTableOffset, std::ios::beg); // TODO: uncomment if we end up adding a helpful offset
	outfileStream_.write(reinterpret_cast<const char *>(&text), sizeof(text));

	// uint32_t dataStart = SectionTableOffset + SectionCount * sizeof(AXE_SECTION)
	uint32_t dataStart = sizeof(ctx_.axeHeader) + ctx_.axeHeader.NumberOfSections * sizeof(AXE_SECTION);
	uint32_t cursor = dataStart;

	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
		//std::vector<AXE_SECTION>::const_iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		// Check the current section's name to see if we want to keep it
		std::vector<AXE_SECTION>::iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		if (iter != axeSections.end())
		{
			DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
			iter->Offset = cursor;
			iter->Size = SizeOfRawData;
			cursor += iter->Size;
		}
	}
	
	// Update SectionHeaders... TODO: make this its own func
	outfileStream_.seekp(sizeof(ctx_.axeHeader), std::ios::beg);
	for (unsigned int i = 0; i < axeSections.size(); ++i)
	{
		outfileStream_.write(reinterpret_cast<const char *>(&axeSections[i]), sizeof(AXE_SECTION));
	}

	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	// Write section data
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader) // TODO: change to while loop? i var is un-used?
	{
		std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
		//std::vector<AXE_SECTION>::const_iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		// Check the current section's name to see if we want to keep it
		std::vector<AXE_SECTION>::iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		if (iter != axeSections.end())
		{

			PBYTE srcPtr = (PBYTE)(rawImageBase_ + pSectionHeader->PointerToRawData);
			//DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;

			//outfileStream_.seekp(cursor, std::ios::beg);
			//outfileStream_.write(reinterpret_cast<const char *>(srcPtr), SizeOfRawData);
			//cursor += pSectionHeader->SizeOfRawData;
			outfileStream_.seekp(iter->Offset, std::ios::beg);
			outfileStream_.write(reinterpret_cast<const char *>(srcPtr), iter->Size);
			cursor += iter->Size;
		}
	}
	outfileStream_.close();

	// TODO:
	// ctx_->axeSection = axeSections;

	/*
	// TODO: relocs
	for (IMAGE_BASE_RELOCATION* relBlock = firstRelBlock; relBlock->VirtualAddress != 0; relBlock = nextRelBlock) {

	DWORD pageRVA = relBlock->VirtualAddress;
	WORD* entries = (WORD*)(relBlock + 1);
	int numEntries = (relBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

	for (int j = 0; j < numEntries; j++) {
		WORD entry = entries[j];
		DWORD type = entry >> 12;
		DWORD offset = entry & 0xFFF;

		axeRelocs[relocCounter].sectionIndex = findSectionForRVA(pageRVA + offset); 
		axeRelocs[relocCounter].offset = (pageRVA + offset) - sectionRVA;
		axeRelocs[relocCounter].type = type;
		relocCounter++;
	}
  }

	*/

	/*
	// TODO: imports
	for (int i = 0; importDescriptors[i].Name != 0; i++)
	{
		PIMAGE_IMPORT_DESCRIPTOR desc = &importDescriptors[i];
		char* dllName = (char*)(baseAddress + desc->Name);

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(baseAddress + desc->OriginalFirstThunk); int funcIndex = 0;

		while (thunk->u1.AddressOfData != 0)
		{
			AXE_IMPORT* imp = &axeImports[importCounter++];

			imp->moduleName = dllName;

			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				imp->functionName = NULL;          // you can store ordinal if needed
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunk->u1.AddressOfData);
				imp->functionName = (char*)ibn->Name;
			}

			if (thunk->u1.ForwarderString != 0)
			{
				imp->forwarderName = (char*)(baseAddress + thunk->u1.ForwarderString);
			}
			else
			{
				imp->forwarderName = NULL;
			}

			imp->patchAddress = NULL;  // set later when loader maps
			thunk++;
		}
	}
	*/

	// ctx_->pAxeImports = axeImports;
	//
}

bool AdrenochromeBuilder::createAXE(std::string path)
{

	outfileStream_.open(path, std::ios::binary | std::ios::trunc);
	if (!outfileStream_)
	{
		return false;
	}
	// TODO: do i ever need to "close" the stream
	return outfileStream_.good();
}

bool AdrenochromeBuilder::createAXE(std::string path,
									std::vector<uint8_t> &buffer)
{
	// TODO: this var should be a class variable so i can write to it from any
	// function in this class?
	std::ofstream outfile(path, std::ios::binary | std::ios::trunc);

	if (!outfile)
	{
		return false;
	}
	outfile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
	return outfile.good();
}
