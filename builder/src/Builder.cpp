#include "Builder.h"
#include "AxeConfig.h"
#include "PEStructs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <filesystem> // NOTE: just for replace_extension()
#include <cstring> // NOTE: needed for memcpy apparently (only on linux vscode)

AdrenochromeBuilder::AdrenochromeBuilder()
	: 
	rawImageBase_(0),
	ctx_(),
	cursor_(0)
	// baseAddress_(0),
{
	// LOGGING STUFF?
}

void AdrenochromeBuilder::build()
{
	// TODO: main function
	createAXE(); // check return type
	initializeContext();
	populateContext(); // change function type from void so i can check return type

	outfileStream_.close();
}

// void AdrenochromeBuilder::loadFile(std::string& path)
// void AdrenochromeBuilder::loadFile(const std::wstring& path)
//  TODO: change return type?
//void AdrenochromeBuilder::loadFile(LPCWSTR path)
void AdrenochromeBuilder::loadFile(std::string& path)
{
	std::filesystem::path p(path);
	outputFilename_ = p.replace_extension("axe").string();

	//HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

	// TODO: put in deconstructor (need to make below member vars) 
	//UnmapViewOfFile(lpView);
	//CloseHandle(hMap);
	//CloseHandle(hFile);


}

void AdrenochromeBuilder::initializeContext() // TODO: rename to initializeHeader? 
{

	BUILD_CONFIG buildConfig;

	//////////////////////////////////////////////////
	// AXE_HEADER
	ctx_.axeHeader.Magic = 0xBEEF;
	ctx_.axeHeader.SizeOfImage = 0;
	ctx_.axeHeader.AddressOfEntryPoint = 0;
	ctx_.axeHeader.NumberOfSections = 0; // TODO: just set to buildConfig.sectionNames.size() ? 
	ctx_.axeHeader.NumberOfRelocations = 0;
	ctx_.axeHeader.NumberOfImports = 0;

	// TODO: delete? pointless? 
	// outfileStream_.write(reinterpret_cast<const char *>(&ctx_.axeHeader), sizeof(ctx_.axeHeader));

	for (std::string& name : buildConfig.sectionNames)
	{
		AXE_SECTION section{};
		size_t copySize = (name.size() < sizeof(section.Name)) ? name.size() : sizeof(section.Name);
		std::memcpy(section.Name, name.data(), copySize);
		section.memoryAddress = 0; // starting addr for the specific section? (this is an RVA?) (fill later?)
		section.Offset = 0;			 // raw offset (we will fill this later)
		section.Size = 0;				 // raw size (we will fill this later)
		ctx_.axeSections.push_back(section);

		//ctx_.axeHeader.NumberOfSections++;
	}
	ctx_.axeHeader.NumberOfSections = ctx_.axeSections.size(); // TODO: this is better? 
	//updateHeader();


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

	// uint32_t dataStart = SectionTableOffset + SectionCount * sizeof(AXE_SECTION)
	uint32_t dataStart = sizeof(AXE_HEADER) + ctx_.axeHeader.NumberOfSections * sizeof(AXE_SECTION);
	cursor_ = dataStart;
	//uint32_t cursor = dataStart;

	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// Populate AXE SectionHeader
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
		//std::vector<AXE_SECTION>::const_iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		// Check the current section's name to see if we want to keep it
		std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(), 
			[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

		if (iter != ctx_.axeSections.end())
		{
			// TODO: this should be changed to VirtualSize? SizeOfRawData gets the VirtualSize rounded up to the nearest page (4kb)
			// or maybe keep at SizeOfRawData to give us a little bit of a buffer? (probs not needed tho)
			//DWORD VirtualSize = pSectionHeader->Misc.VirtualSize;
			// TODO: "trim" off alignment bytes from the SizeOfRawData/VirtualSize
			DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
			iter->Offset = cursor_;
			iter->Size = SizeOfRawData; // TODO: is size of raw data correct here? 
			cursor_ += iter->Size;
		}
	}

	//updateSectionHeaders();
	//calculateEntryPoint();
	//updateHeader(); // TODO: move this into the calculateEntryPoint() function? 
	
	//updateSectionsData();

	//updateHeader();

	// TODO: relocs

	// relocRVA = block.VirtualAddress + entry.Offset;
	// section.VirtualAddress = IMAGE_SECTION_HEADER.VirtualAddress
	// sectionOffsetInAXE = fileoffset in axe file where corresponding section is
	// axeOffset = absolute offset relative to the axe image base? // NOTE: this is the "relocationDelta?"

	//axeOffset = sectionOffsetInAXE + (relocRVA - section.VirtualAddress);


	
	//
	ULONG_PTR relocationDelta = rawImageBase_ - pNtHeaders->OptionalHeader.ImageBase; 
	DWORD offsetIntoSection = 0; 

	PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	if (pRelocDir->Size)
	{
		// TODO: add this to be 100% sure we've gone through all the blocks
		// BYTE* relocEnd = rawImageBase_ + relocSection.PointerToRawData + relocSection.SizeOfRawData;
		// for (; (BYTE*)relocBlock < relocEnd; relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock))



		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(rawImageBase_+ Rva2Offset(pRelocDir->VirtualAddress));
		// baseAddressBuffer = (baseAddress + ((PIMAGE_DATA_DIRECTORY)pRelocDir)->VirtualAddress);
		// and we itterate through all entries...
		// NOTE: we can do this because windows api says the IMAGE_BASE_RELOCATION blocks are terminated
		// by a NULL relocation block, meaning SizeOfBlock will be 0 when we want to stop looking/relocating... 
		// apparently this isn't always 100% true? 
		for (; relocBlock->SizeOfBlock; relocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)relocBlock + relocBlock->SizeOfBlock))
		{
			// if (relocBlock->SizeOfBlock == 0) break; // optional safety

			// uiValueA = the VA for this relocation block
			//iatAddress = (baseAddress + ((PIMAGE_BASE_RELOCATION)relocBlock)->VirtualAddress);
			ULONG_PTR relocBlockBase = (ULONG_PTR)(rawImageBase_ + Rva2Offset(relocBlock->VirtualAddress)); 

			// uiValueB = number of entries in this relocation block
			// TODO:
			ULONG numRelocs = (((PIMAGE_BASE_RELOCATION)relocBlock)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC); // TODO: should this be DWORD?
			// rawImageBaseBuffer = (((PIMAGE_BASE_RELOCATION)baseAddressBuffer)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			//sizeofRawData = (ULONG_PTR)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
			PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION)); // NOTE: this is the specific relocation entry

			// we itterate through all the entries in the current block...
			for (ULONG i = 0; i < numRelocs; ++i, ++pReloc)
			{
				// TODO: 
				//BOOL keepSec = keepSection(relocBlockBase + pReloc->offset);
				std::string sectionName = keepSection(relocBlockBase + pReloc->offset);
				if (sectionName.size() > 0)
				{
					// apply/store relocs

					std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
						[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

					if (iter != ctx_.axeSections.end())
					{
						DWORD index = static_cast<DWORD>(std::distance(ctx_.axeSections.begin(), iter));
						AXE_RELOCATION relocAxe{};
						relocAxe.sectionIndex = index;
						relocAxe.offset = pReloc->offset; // offset within the section
						relocAxe.type = pReloc->type;
						ctx_.axeRelocations.push_back(relocAxe);
					}

				}
				else
				{
					std::cout << "relocation found inside non idea section" << std::endl;
				}
			}
		}

		//updateRelocations();
	}

	AXE_SECTION& relocSection = *(ctx_.axeSections.end() - 1);
	AXE_SECTION& sectionBeforeReloc = *(ctx_.axeSections.end() - 2);
	// TODO: use .back() instead?
	//AXE_SECTION& relocSection = ctx_.axeSections.back();
	//AXE_SECTION& sectionBeforeReloc = ctx_.axeSections[ctx_.axeSections.size() - 2];

	relocSection.Offset = sectionBeforeReloc.Offset + sectionBeforeReloc.Size;
	//relocSection.Offset = sizeof(AXE_HEADER) + ctx_.axeSections.size() * sizeof(AXE_SECTION) + sectionBeforeReloc.Offset + sectionBeforeReloc.Size;
	relocSection.Size = ctx_.axeRelocations.size() * sizeof(AXE_RELOCATION); // TODO: this is wrong? 



	// if relocations exist, add a relocation section to ctx_.axeSections
	// if (ctx_.axeRelocations.size()) { }




	// TODO: imports


	cursor_ = 0;
	updateHeader();
	cursor_ += sizeof(AXE_HEADER);
	updateSectionHeaders();
	cursor_ +=  ctx_.axeSections.size() * sizeof(AXE_SECTION);
	updateSectionsData();

	updateRelocations();
	ctx_.axeHeader.SizeOfImage = cursor_;
	updateHeader();
}

void AdrenochromeBuilder::updateHeader()
{
	if (outfileStream_) 
	{
		outfileStream_.seekp(0, std::ios::beg);
		outfileStream_.write(reinterpret_cast<const char*>(&ctx_.axeHeader), sizeof(AXE_HEADER));
	}

}

void AdrenochromeBuilder::updateSectionHeaders() 
{

	// TODO: do this check: if (!outfileStream_) 

	//outfileStream_.seekp(sizeof(ctx_.axeHeader), std::ios::beg);
	//cursor_ = sizeof(AXE_HEADER);
	outfileStream_.seekp(sizeof(AXE_HEADER), std::ios::beg);
	for (unsigned int i = 0; i < ctx_.axeSections.size(); ++i)
	{
		outfileStream_.write(reinterpret_cast<const char*>(&ctx_.axeSections[i]), sizeof(AXE_SECTION));
		//cursor_ += sizeof(AXE_SECTION); // TODO: uncomment?
	}
}

void AdrenochromeBuilder::updateSectionsData()
{
	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	// Write section data
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader) // TODO: change to while loop? i var is un-used?
	{
		std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
		//std::vector<AXE_SECTION>::const_iterator iter = std::find_if(axeSections.begin(), axeSections.end(), [&sectionName](const AXE_SECTION& s) { return s.Name == sectionName; });
		// Check the current section's name to see if we want to keep it
		std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(), 
			[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

		// NOTE: we don't want to write the exact reloc data from the pe,
		// we want to use our own structure for the data
		if (iter != ctx_.axeSections.end() && sectionName != ".reloc")
		{

			PBYTE srcPtr = (PBYTE)(rawImageBase_ + pSectionHeader->PointerToRawData);
			//DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;

			//outfileStream_.seekp(cursor, std::ios::beg);
			//outfileStream_.write(reinterpret_cast<const char *>(srcPtr), SizeOfRawData);
			//cursor += pSectionHeader->SizeOfRawData;
			outfileStream_.seekp(iter->Offset, std::ios::beg);
			outfileStream_.write(reinterpret_cast<const char *>(srcPtr), iter->Size);
			cursor_ += iter->Size;
		}
	}

	//ctx_.axeHeader.SizeOfImage = cursor_;
}

void AdrenochromeBuilder::updateRelocations()
{
	if (outfileStream_)
	{
		for (size_t i = 0; i < ctx_.axeRelocations.size(); ++i)
		{
			outfileStream_.seekp(cursor_, std::ios::beg);
			outfileStream_.write(reinterpret_cast<const char*>(&ctx_.axeRelocations[i]), sizeof(AXE_RELOCATION));
			cursor_ += sizeof(AXE_RELOCATION);
		}
	}
}

//BOOL AdrenochromeBuilder::keepSection(ULONG_PTR addr)
std::string AdrenochromeBuilder::keepSection(ULONG_PTR addr)
{	

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	DWORD dwRva = (DWORD)(addr - rawImageBase_);

	// find what section the entry point is in 
	for (WORD i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		if (dwRva >= pSectionHeader->PointerToRawData && 
			dwRva < pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize)
		{

			std::string sectionName(reinterpret_cast<const char*>(pSectionHeader->Name), strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8)); // TODO: don't hard code length? 
			//std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);

			std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
				[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });
			// axeSection = ctx_.axeSections[TODO_INDEX]; // TODO_INDEX gets us 

			if (iter != ctx_.axeSections.end())
			{
				// TODO: 
				// or just apply/save off AXE_RELOCATION here?  
				return sectionName;
				//return TRUE;
			}
		}
	}

	return std::string();
	//return FALSE;
}

DWORD AdrenochromeBuilder::Rva2Offset(DWORD dwRva)
{
	WORD wIndex = 0; // TODO: rename to something like sIndex or sectionIndex maybe?

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);

	// pointer to the first section header
	// address of first section header = (address to the OptionalHeader) + SizeOfOptionalHeader
	// TODO: use IMAGE_FIRST_SECTION to get start address based on the PE header?
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);


	// Check if RVA points to somewhere before the first section
	//if (dwRva < pSectionHeader[0].PointerToRawData)
	if (dwRva < pSectionHeader->PointerToRawData)
	{
		return dwRva;
	}

	//for (wIndex = 0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections; ++wIndex, ++pSectionHeader)
	for (wIndex = 0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections; ++wIndex)
	{   
		// if the RVA is within the current SectionHeader structure (VirtualAddress to VirtualAddress + SizeOfRawData) 
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && 
			dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))           
		{
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
		}
	}
	return 0;

}

//ULONG_PTR AdrenochromeBuilder::calculateEntryPoint()
void AdrenochromeBuilder::calculateEntryPoint()
{
	DWORD offsetIntoSection = 0; 

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	DWORD AddressOfEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// find what section the entry point is in 
	for (WORD i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		// TODO: this needs to be using pSectionHeader->PointerToRawData since rawImageBase_ is based off of on disk alignment 
		if (AddressOfEntryPoint >= pSectionHeader->VirtualAddress && 
			AddressOfEntryPoint < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{
			offsetIntoSection = AddressOfEntryPoint - pSectionHeader->VirtualAddress; // NOTE: this is the RVA to the entry point relative to the section it's in

			std::string sectionName(reinterpret_cast<const char*>(pSectionHeader->Name), strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8)); // TODO: don't hard code length? 
			//std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);

			std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
				[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });
			// axeSection = ctx_.axeSections[TODO_INDEX]; // TODO_INDEX gets us 

			if (iter != ctx_.axeSections.end())
			{
				ctx_.axeHeader.AddressOfEntryPoint = iter->Offset + offsetIntoSection;
				return;
			}
		}
	}
	// TOD: 
	// updateHeader()
}



bool AdrenochromeBuilder::createAXE()
{

	outfileStream_.open(outputFilename_, std::ios::binary | std::ios::trunc);
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
