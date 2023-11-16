#include "pch.h"
#include "helpers.h"


DWORD GetOffset(const DWORD rva, const IMAGE_DATA* const image)
{
	const IMAGE_SECTION_HEADER* SectionHeader = image->sections;

	for (UINT x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
	{
		if (rva >= SectionHeader[x].VirtualAddress && rva <= (SectionHeader[x].VirtualAddress + SectionHeader[x].Misc.VirtualSize))
		{
			return SectionHeader[x].PointerToRawData + (rva - SectionHeader[x].VirtualAddress);
		}
	}

	std::cerr << "Failed to find file offset\n";
	std::cerr << "Module: " << image->name << '\n';
	std::cerr << "RVA: " << HexOut << rva << std::endl;
	return NULL;
}


bool ImageCmp(const std::string path, const char* const name)
{
	return _stricmp((path.substr(path.find_last_of('\\') + 1)).c_str(), name) == 0;
}


LOADED_MODULE* GetLoadedModule(const char* const name)
{
	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		if (ImageCmp(LoadedModules[x].name, name)) return &LoadedModules[x];
	}

	return nullptr;
}


bool CheckModules(const char* const target)
{
	for (UINT x = 0; x < modules.size(); ++x)
	{
		if (ImageCmp(modules[x].image.name, target)) return true;
	}

	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		if (ImageCmp(LoadedModules[x].name, target)) return true;
	}

	return false;
} 