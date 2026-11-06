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
	cursor_(0),
	hFile_(nullptr),
	hMap_(nullptr),
	lpView_(nullptr)
	// baseAddress_(0),
{
	// LOGGING STUFF?
}


AdrenochromeBuilder::~AdrenochromeBuilder()
{
	if (lpView_)
	{
		UnmapViewOfFile(lpView_);
	}

	if (hMap_)
	{
		CloseHandle(hMap_);
	}

	if (hFile_)
	{
		CloseHandle(hFile_);
	}

	if (outfileStream_)
	{
		outfileStream_.close();
	}

}

void AdrenochromeBuilder::build()
{
	// TODO: main function
	createAXE(); // check return type
	initializeContext();
	populateContext(); // change function type from void so i can check return type

}

bool AdrenochromeBuilder::basicBuild(std::string& path)
{
	std::filesystem::path input(path);
	outputFilename_ = input.replace_extension(".axe").string();

	// Open DLL at end to get size
	std::ifstream dll(path, std::ios::binary | std::ios::ate);
	if (!dll)
		return false;

	std::streamsize size = dll.tellg();
	if (size <= 0)
		return false;

	dll.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	if (!dll.read(buffer.data(), size))
		return false;

	std::ofstream axe(outputFilename_, std::ios::binary | std::ios::trunc);
	if (!axe)
		return false;

	axe.write(buffer.data(), size);
	return axe.good();
}

// void AdrenochromeBuilder::loadFile(std::string& path)
// void AdrenochromeBuilder::loadFile(const std::wstring& path)
//  TODO: change return type?
void AdrenochromeBuilder::loadFile(std::string& path)
{
	std::filesystem::path p(path);
	outputFilename_ = p.replace_extension("axe").string();

	hFile_ = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile_ == INVALID_HANDLE_VALUE)
	{
		// TODO: throw helpful error
		return;
	}

	hMap_ = CreateFileMappingW(hFile_, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMap_ == NULL)
	{
		// TODO: throw helpful error
		return;
	}

	// NOTE: lpView is the baseAddress... TODO: rename var?
	// TODO: store this var as a class variable?
	lpView_ = MapViewOfFile(hMap_, FILE_MAP_READ, 0, 0, 0);

	if (lpView_ != NULL)
	{
		rawImageBase_ = (ULONG_PTR)lpView_;
	}
	else
	{
		// TODO: throw helpful error
	}
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

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	ctx_.axeHeader.PreferredImageBase = pNtHeaders->OptionalHeader.ImageBase;  // Usually 0x140000000 for x64

	// TODO: delete? pointless? 
	// outfileStream_.write(reinterpret_cast<const char *>(&ctx_.axeHeader), sizeof(ctx_.axeHeader));

	//buildConfig.sectionNames = { ".text", ".rdata", ".data" };

	for (std::string& name : buildConfig.sectionNames)
	{
		/*
		if (name == ".reloc")
		{
			continue;
		}*/
		AXE_SECTION section{};
		size_t copySize = (name.size() < sizeof(section.Name)) ? name.size() : sizeof(section.Name);
		std::memcpy(section.Name, name.data(), copySize);
		section.memoryAddress = 0; // starting addr for the specific section? (this is an RVA?) (fill later?)
		section.Offset = 0;			 // raw offset (we will fill this later)
		section.Size = 0;				 // raw size (we will fill this later)
		ctx_.axeSections.push_back(section);

		//ctx_.axeHeader.NumberOfSections++;
	}
	ctx_.axeHeader.NumberOfSections = ctx_.axeSections.size(); // TODO: this is better than incrementing in a for loop?
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

	DWORD currentRVA = 0x1000;
	//uint32_t numSectionHeaders = ctx_.axeHeader.NumberOfSections; //+ 1;  // +1 for .reloc
	//uint32_t dataStart = sizeof(AXE_HEADER) + numSectionHeaders * sizeof(AXE_SECTION);
	//uint32_t dataStart = sizeof(AXE_HEADER) + numSectionHeaders * sizeof(AXE_SECTION);
	uint32_t dataStart = sizeof(AXE_HEADER) + ctx_.axeHeader.NumberOfSections * sizeof(AXE_SECTION);

	cursor_ = dataStart;

	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// Populate AXE sections
	for (USHORT i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
		auto iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
			[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

		if (iter != ctx_.axeSections.end())
		{
			DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
			iter->Offset = cursor_;
			iter->Size = SizeOfRawData;
			iter->memoryAddress = currentRVA;
			cursor_ += iter->Size;
			currentRVA += (SizeOfRawData + 0xFFF) & ~0xFFF;
		}
	}

	// Process relocations
	PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pRelocDir->Size)
	{
		PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(rawImageBase_ + Rva2Offset(pRelocDir->VirtualAddress));

		for (; relocBlock->SizeOfBlock; relocBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)relocBlock + relocBlock->SizeOfBlock))
		{
			ULONG numRelocs = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
			PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)relocBlock + sizeof(IMAGE_BASE_RELOCATION));

			for (ULONG i = 0; i < numRelocs; ++i, ++pReloc)
			{
				DWORD relocRVA = relocBlock->VirtualAddress + pReloc->offset;
				std::string sectionName = keepSection(relocRVA);

				if (sectionName.size() > 0)
				{
					PIMAGE_SECTION_HEADER pTargetSection = getPESection(relocRVA);
					if (!pTargetSection) continue;

					auto iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
						[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

					if (iter != ctx_.axeSections.end())
					{
						DWORD index = static_cast<DWORD>(std::distance(ctx_.axeSections.begin(), iter));
						AXE_RELOCATION relocAxe{};
						relocAxe.sectionIndex = index;
						relocAxe.offset = relocRVA - pTargetSection->VirtualAddress;
						relocAxe.type = pReloc->type;
						ctx_.axeRelocations.push_back(relocAxe);
					}
				}
			}
		}

		ctx_.axeHeader.NumberOfRelocations = ctx_.axeRelocations.size();
	}

	// ✅ Add .reloc section BEFORE calculating entry point
	if (ctx_.axeRelocations.size() > 0)
	{
		std::cout << "Adding .reloc section, current section count: " << ctx_.axeSections.size() << std::endl;  // ✅ ADD
		AXE_SECTION relocSection{};
		std::memcpy(relocSection.Name, ".reloc", 6);
		relocSection.Offset = cursor_;  // Right after last data section
		relocSection.Size = ctx_.axeRelocations.size() * sizeof(AXE_RELOCATION);
		relocSection.memoryAddress = 0;
		ctx_.axeSections.push_back(relocSection);
		ctx_.axeHeader.NumberOfSections = ctx_.axeSections.size();
		std::cout << "After adding .reloc, section count: " << ctx_.axeSections.size() << std::endl;  // ✅ ADD

	}

	calculateEntryPoint();

	// Write to file
	cursor_ = 0;
	updateHeader();
	cursor_ += sizeof(AXE_HEADER);
	updateSectionHeaders();
	cursor_ += ctx_.axeSections.size() * sizeof(AXE_SECTION);
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
// TODO: DELETE
/*
std::string AdrenochromeBuilder::keepSection(ULONG_PTR addr)
{	

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	DWORD dwRva = (DWORD)(addr - rawImageBase_);

	// find what section the entry point is in 
	for (WORD i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		// TODO: change all these comparisions in the if statement to virtual not raw?
		if (dwRva >= pSectionHeader->PointerToRawData && 
			dwRva < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)
			//dwRva < pSectionHeader->PointerToRawData + pSectionHeader->Misc.VirtualSize)
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
}*/

// NOTE: fixed version? 
std::string AdrenochromeBuilder::keepSection(DWORD dwRva)
{	
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (WORD i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		// Compare RVA to VirtualAddress... TODO: make this a function instead? 
		if (dwRva >= pSectionHeader->VirtualAddress &&
			dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{
			std::string sectionName(reinterpret_cast<const char*>(pSectionHeader->Name),
				strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8));

			std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
				[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

			if (iter != ctx_.axeSections.end())
			{
				return sectionName;
			}
		}
	}

	return std::string();
}

DWORD AdrenochromeBuilder::Rva2Offset(DWORD dwRva)
{
	WORD wIndex = 0; // TODO: rename to something like sIndex or sectionIndex maybe?
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
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
			dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].Misc.VirtualSize))
			//dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
		{
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
		}
	}
	return 0;
}
	
PIMAGE_SECTION_HEADER AdrenochromeBuilder::getPESection(DWORD dwRva)
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	WORD nSections = pNtHeaders->FileHeader.NumberOfSections;


	for (WORD i = 0; i < nSections; ++i, ++pSectionHeader)
	{
		if (dwRva >= pSectionHeader->VirtualAddress && 
			dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
		{
			return pSectionHeader;
			/*
			std::string sectionName(reinterpret_cast<const char*>(pSectionHeader->Name), strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8)); // TODO: don't hard code length? 
			//std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);
			// TODO: make this into its own function?
			std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
				[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

			if (iter != ctx_.axeSections.end())
			{
				return pSectionHeader;
			}
			*/
		}
	}
	return nullptr;
}

//PAXE_SECTION AdrenochromeBuilder::getAXESection(DWORD dwRva)
PAXE_SECTION AdrenochromeBuilder::getAXESection(PIMAGE_SECTION_HEADER pSectionHeader)
{
	std::string sectionName(reinterpret_cast<const char*>(pSectionHeader->Name),
		strnlen(reinterpret_cast<const char*>(pSectionHeader->Name), 8));

	std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
		[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

	if (iter != ctx_.axeSections.end())
	{
		return &(*iter);
	}

	return nullptr;  // ✅ Return nullptr instead

	////////////////////////////////////////////////
	/*
	std::string sectionName = reinterpret_cast<char*>(pSectionHeader->Name);

	std::vector<AXE_SECTION>::iterator iter = std::find_if(ctx_.axeSections.begin(), ctx_.axeSections.end(),
		[&sectionName](const AXE_SECTION& s) { return std::string(s.Name) == sectionName; });

	if (iter != ctx_.axeSections.end())
	{
		return &(*iter);
	}

	// TODO: should never get here? this is just for compiler warnings?
	AXE_SECTION nullAxeSection{};
	return &nullAxeSection; // TODO: should just return nullptr instead?
	*/
}

// TODO: not implemented
BOOL AdrenochromeBuilder::SectionNamesEqual(const IMAGE_SECTION_HEADER &peSection, const AXE_SECTION &axeSection)
{
	//return reinterpret_cast<char*>(peSection.Name) == std::string(axeSection.Name);
	//return peSection.Name == axeSection.Name;
	return false;
}

void AdrenochromeBuilder::calculateEntryPoint()
{

	DWORD axeEntryRVA = findFunctionAddress();  // Find "AxeEntry" export

	if (axeEntryRVA == 0)
	{
		std::cerr << "ERROR: AxeEntry function not found in exports!" << std::endl;
		std::cerr << "Make sure your engine.dll exports AxeEntry" << std::endl;

		// Fallback to DllMain
		std::cerr << "Falling back to DllMain entry point" << std::endl;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
		axeEntryRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	}
	else
	{
		std::cout << "✓ Found AxeEntry at RVA: 0x" << std::hex << axeEntryRVA << std::dec << std::endl;
	}

	// Find which PE section contains this RVA
	PIMAGE_SECTION_HEADER matching_section = getPESection(axeEntryRVA);

	if (!matching_section)
	{
		std::cerr << "ERROR: Could not find PE section for entry RVA 0x"
			<< std::hex << axeEntryRVA << std::dec << std::endl;

		// Debug: Print all sections
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
		PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		std::cerr << "Available PE sections:" << std::endl;
		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
		{
			std::cerr << "  " << std::string((char*)pSectionHeader->Name, strnlen((char*)pSectionHeader->Name, 8))
				<< " VA: 0x" << std::hex << pSectionHeader->VirtualAddress
				<< " - 0x" << (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)
				<< std::dec << std::endl;
		}
		return;
	}

	std::string sectionName(reinterpret_cast<const char*>(matching_section->Name),
		strnlen(reinterpret_cast<const char*>(matching_section->Name), 8));
	std::cout << "✓ Entry point is in section: " << sectionName << std::endl;

	// Find corresponding AXE section
	PAXE_SECTION axeEpSection = getAXESection(matching_section);

	if (!axeEpSection)
	{
		std::cerr << "ERROR: Section '" << sectionName << "' is not in the AXE file!" << std::endl;
		std::cerr << "Add it to buildConfig.sectionNames in initializeContext()" << std::endl;

		// Debug: Print kept sections
		std::cerr << "Sections in AXE:" << std::endl;
		for (const auto& sec : ctx_.axeSections)
		{
			std::cerr << "  " << std::string(sec.Name, strnlen(sec.Name, 8)) << std::endl;
		}
		return;
	}

	// Calculate offset within the section
	DWORD rva = axeEntryRVA - matching_section->VirtualAddress;

	// Entry point = file offset in AXE
	ULONG_PTR entryPoint = axeEpSection->Offset + rva;
	ctx_.axeHeader.AddressOfEntryPoint = (DWORD)entryPoint;

	std::cout << "✓ Entry point set to file offset: 0x" << std::hex << entryPoint << std::dec << std::endl;


	///////////////////////////////////////////////////////////////////////////////





	/*
	 * DWORD AddressOfEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	 * epSection = find_section_ep_is_in(AddressOfEntryPoint);
	 * rva = AddressOfEntryPoint - epSection->VirtualAddress;
	 * axeEpSection = find_section_in_axe_that_matches(epSection);
	 * axeEntryPoint = axeEpSection.Offset + rva;
	 *
	 * */


	// TODO: instead the address of entry point should be where the function "AxeEntry" lives
	/*
	DWORD axeEntryRVA = findFunctionAddress(); // should be relative to the image base

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);
	DWORD AddressOfEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	//DWORD AddressOfEntryPoint = axeEntryRVA;

	////////////////////////////////////////////////////////////////////////
	PIMAGE_SECTION_HEADER matching_section = getPESection(AddressOfEntryPoint);
	DWORD rva = AddressOfEntryPoint - matching_section->VirtualAddress; // rva relative to the section where the addressofentrypoint exists
	PAXE_SECTION axeEpSection = getAXESection(matching_section); // getAXESection that has the same name as Matching Section
	ULONG_PTR entryPoint = axeEpSection->Offset + rva;
	ctx_.axeHeader.AddressOfEntryPoint = (DWORD)entryPoint;
	////////////////////////////////////////////////////////////////////////
	*/

}


// buffer is just some (heap?) allocated region of memory where the pe file lives
//DWORD AdrenochromeBuilder::findFunctionAddress(VOID* buffer) // TODO: pass lpProcName here?
DWORD AdrenochromeBuilder::findFunctionAddress(void)
{

	// TODO: dllBaseAddress and rawImageAddress are not used consistently
	// in this function? 

	LPCSTR lpProcName = "AxeEntry";


	///
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)rawImageBase_ + ((PIMAGE_DOS_HEADER)rawImageBase_)->e_lfanew);

	// NOTE: this is the rva for the Export Directory (PIMAGE_EXPORT_DIRECTORY)
	DWORD dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	// uiNameArray = the address of the modules export directory entry
	UINT_PTR uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)pNTHeader)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT  ];


	// get the File Offset of the export directory
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(rawImageBase_ + Rva2Offset(dwExportDirRVA));


	
	// TODO: 
	DWORD* arrayOfNamesRVAs = (DWORD*)(rawImageBase_ + Rva2Offset(pExportDir->AddressOfNames));
	DWORD* arrayOfFunctionRVAs = (DWORD*)(rawImageBase_ + Rva2Offset(pExportDir->AddressOfFunctions));
	WORD* arrayOfNameOrdinals = (WORD*)(rawImageBase_ + Rva2Offset(pExportDir->AddressOfNameOrdinals));


	DWORD numNames = pExportDir->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader

	// TODO: remove these... not needed anymore
	//DWORD targetFunctionAddress;  // TODO: should be 0
	//DWORD targetFunctionAddressOffset; // TODO: should be 0 

	for (DWORD i = 0; i < numNames; ++i)
	{
		// ✅ Use Rva2Offset to ACCESS the name string in the file
		char* prodName = (char*)((ULONG_PTR)rawImageBase_ + Rva2Offset(arrayOfNamesRVAs[i]));

		if (strstr(prodName, "AxeEntry") != NULL)
		{
			return arrayOfFunctionRVAs[arrayOfNameOrdinals[i]];
		}
	}

	/*
	for (DWORD i = 0; i < numNames; ++i)
	{
		//char * cpExportedFunctionName = (char *)(dllBaseAddress + Rva2Offset( DEREF_32( uiNameArray  ), dllBaseAddress  ));
		//MessageBoxA(NULL, cpExportedFunctionName, "Exported Function Name: ", MB_OK);


		char* prodName = (char*)((ULONG_PTR)rawImageBase_ + Rva2Offset(arrayOfNamesRVAs[i])); // TODO: ULONG_PTR type cast isn't needed?
		if (strstr(prodName, "AxeEntry") != NULL) // TODO: do not hardcode reflective loader function name that we're using as an entry point
		{
			//targetFunctionAddress = dllBaseAddress + Rva2Offset(arrayOfFunctionRVAs[arrayOfNameOrdinals[i]], dllBaseAddress);
			//targetFunctionAddressOffset = Rva2Offset(arrayOfFunctionRVAs[arrayOfNameOrdinals[i]], dllBaseAddress);
			//return targetFunctionAddressOffset;
			return Rva2Offset(arrayOfFunctionRVAs[arrayOfNameOrdinals[i]]);
		}
	}*/
	return 0;
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

