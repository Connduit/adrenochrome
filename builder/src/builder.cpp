#include "Builder.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <fstream>
#include <iostream>
#include <string>



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

// TODO: do i even need a axe_struct? will def help with organizing and future proofing
// but what if i just did a virtualalloc using the SizeOfImage and just wrote everything 
// i want to keep into that buffer. And then kept track of how many bytes i wrote to that 
// buffer. and then just wrote all the bytes from virtualalloc_baseAddress to 
// virtualalloc_baseAddress + nBytes to some file on disk that would be my .axe file
void AdrenochromeBuilder::populateContext()
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	// TODO: need to do sizeofimage - sizeofheaders? (if we plan on removing headers)
	//ctx_->axeHeader.SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	// TODO: im pretty sure this will be wrong since im stripping a bunch of parts of the dll.
	// the entry point will have to be manually calculated 
	//ctx_->axeHeader.EntryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint; // TODO: for should i just return absolute?

	ctx_->axeHeader.Magic = 0xDEADBEEF;
	ctx_->axeHeader.NumberOfSections = 3; // TODO: should start o
	ctx_->axeHeader.NumberOfRelocations = 0;
	ctx_->axeHeader.NumberOfImports = 0;

	// TODO: pNtHeaders->FileHeader ? 
	// TODO: pNtHeaders->OptionalHeader ? 

	//AXE_SECTION axeSections[ctx_->axeHeader.NumberOfSections];
	AXE_SECTION axeSections[3];
	// TODO: need to allocate this??
	//std::vector<AXE_SECTION> axeSections;
	//axeSections.reserve(ctx_->axeHeader.NumberOfSections);

	// TODO: createContextInMemory() here? 
	// ULONG_PTR baseAddress = (ULONG_PTR)VirtualAlloc(NULL, ctx_->axeHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	//baseAddress_ = baseAddress;


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
			axeSections[i].Offset = pSectionHeader->PointerToRawData;
			axeSections[i].Size = pSectionHeader->SizeOfRawData;
			//axeSections[i].flags = pSectionHeader->Characteristics;  // optional
			axeSections[i].memoryAddress = NULL;          // your loader will set this

			/*
			while (SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}
			*/
		}
		else if (strncmp((char*)pSectionHeader->Name, ".rdata", 6) == 0)
		{
			axeSections[i].Offset = pSectionHeader->PointerToRawData;
			axeSections[i].Size = pSectionHeader->SizeOfRawData;
			//axeSections[i].flags = pSectionHeader->Characteristics;  // optional
			axeSections[i].memoryAddress = NULL;          // your loader will set this

			/*
			while (SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}
			*/

		}
		else if (strncmp((char*)pSectionHeader->Name, ".data", 5) == 0)
		{
			axeSections[i].Offset = pSectionHeader->PointerToRawData;
			axeSections[i].Size = pSectionHeader->SizeOfRawData;
			//axeSections[i].flags = pSectionHeader->Characteristics;  // optional
			axeSections[i].memoryAddress = NULL;          // your loader will set this

			/*
			while (SizeOfRawData--)
			{
				// TODO: 
				// *dstPtr++ = *srcPtr++;
			}
			*/

		}
	}

	ctx_->pAxeSections = axeSections;

	/*
	// TODO: relocs
	for (IMAGE_BASE_RELOCATION* relBlock = firstRelBlock; relBlock->VirtualAddress != 0;
	 relBlock = nextRelBlock) {

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

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(baseAddress + desc->OriginalFirstThunk);
		int funcIndex = 0;

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

	/*
	// TODO: Section Blobs
	// TODO: this would be better and more correct? 
	DWORD fileOffset = sizeof(AXE_HEADER) + axeHeader.SectionCount * sizeof(AXE_SECTION)
                 + axeHeader.ImportCount * sizeof(AXE_IMPORT)
                 + axeHeader.RelocCount * sizeof(AXE_RELOC); // if any

	PAXE_SECTION axeSections = ...; // array of AXE_SECTION
	uint8_t* srcBase = peFileBuffer;        // FILE bytes
	uint8_t* dstBuffer = axeFileBuffer;     // AXE file


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

			memcpy(dstBuffer + fileOffset,
				srcBase + pSectionHeader->PointerToRawData,
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

