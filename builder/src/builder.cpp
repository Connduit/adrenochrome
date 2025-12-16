#include "builder.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <fstream>
#include <iostream>
#include <string>
#include <vector>



AdrenochromeBuilder::AdrenochromeBuilder() :
	rawImageBase_(0),
	//baseAddress_(0),
	ctx_(nullptr)
{
	// LOGGING STUFF?
}

void AdrenochromeBuilder::build()
{
	// TODO: main function
}

//void AdrenochromeBuilder::loadFile(std::string& path)
//void AdrenochromeBuilder::loadFile(const std::wstring& path)
// TODO: change return type?
void AdrenochromeBuilder::loadFile(LPCWSTR path)
{
	HANDLE hFile = CreateFileW(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// TODO: check hFile is valid... !INVALID_HANDLE_VALUE

	HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	// TODO: check hMap is valid... !NULL

	// NOTE: lpView is the baseAddress... TODO: rename var?
	// TODO: store this var as a class variable?
	LPVOID lpView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	// TODO: check lpView is valid... !NULL

	if (lpView != NULL)
	{
		rawImageBase_ = (ULONG_PTR)lpView;
	}

}

// TODO: do i even need a axe_struct? will def help with organizing and future proofing
// but what if i just did a virtualalloc using the SizeOfImage and just wrote everything 
// i want to keep into that buffer. And then kept track of how many bytes i wrote to that 
// buffer. and then just wrote all the bytes from virtualalloc_baseAddress to 
// virtualalloc_baseAddress + nBytes to some file on disk that would be my .axe file
void AdrenochromeBuilder::populateContext()
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	// TODO: need to do sizeofimage - sizeofheaders? (if we plan on removing headers)
	ctx_->axeHeader.SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	// TODO: im pretty sure this will be wrong since im stripping a bunch of parts of the dll.
	// the entry point will have to be manually calculated 
	ctx_->axeHeader.EntryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint; // TODO: for should i just return absolute?


	// TODO: pNtHeaders->FileHeader ? 
	// TODO: pNtHeaders->OptionalHeader ? 




	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	// TODO: for copying contents in each section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	// NOTE: pSectionHeader->PointerToRawData = pointer to data stored on disk
	// pSectionHeader->VirtualAddress = the relative address of where the data goes relative to the baseAddress
	for (WORD i = 0; i < nSections; ++i)
	{
		DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
		if (strncmp((char*)pSectionHeader->Name, ".text", 5) == 0)
		{

			while(SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}
		}
		else if (strncmp((char*)pSectionHeader->Name, ".rdata", 6) == 0)
		{
			while(SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}

		}
		else if (strncmp((char*)pSectionHeader->Name, ".data", 5) == 0)
		{
			while(SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}

		}
	}
	// TODO: this would be better and more correct? 
	/*
	DWORD fileOffset = sizeof(AXE_HEADER) + axeHeader.SectionCount * sizeof(AXE_SECTION)
                 + axeHeader.ImportCount * sizeof(AXE_IMPORT)
                 + axeHeader.RelocCount * sizeof(AXE_RELOC); // if any

	PAXE_SECTION axeSections = ...; // array of AXE_SECTION
	uint8_t* dstBuffer = axeFileBuffer; // entire .axe file in memory
	uint8_t* srcBase = baseAddress_;    // original PE loaded in memory

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
    	char name[9] = {0};
    	memcpy(name, pSectionHeader->Name, 8);

		if (strncmp(name, ".text", 5) == 0 ||
			strncmp(name, ".rdata", 6) == 0 ||
			strncmp(name, ".data", 5) == 0)
		{
			// Fill AXE_SECTION metadata
			axeSections[i].RVA = pSectionHeader->VirtualAddress;
			axeSections[i].Size = pSectionHeader->Misc.VirtualSize;
			axeSections[i].Offset = fileOffset;
			axeSections[i].Characteristics = pSectionHeader->Characteristics;

			// Copy section raw bytes into buffer
			memcpy(dstBuffer + fileOffset, srcBase + pSectionHeader->PointerToRawData,
				pSectionHeader->SizeOfRawData);

			// Move fileOffset to next section (aligned if desired)
			fileOffset += align(pSectionHeader->SizeOfRawData, 0x1000);
		}
	}
	*/

}


bool AdrenochromeBuilder::createAXE(
	std::string path,
	std::vector<uint8_t>& buffer)
{
	std::ofstream outfile(path, std::ios::binary | std::ios::trunc);

	if (!outfile)
	{
		return false;
	}
	outfile.write(reinterpret_cast<const char *>(buffer.data()), buffer.size());
	return outfile.good();
}

