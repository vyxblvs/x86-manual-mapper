#include "pch.h"
#include "helpers.h"


DWORD GetOffset(const DWORD rva, const IMAGE_DATA* image)
{
	const IMAGE_SECTION_HEADER* SectionHeader = image->sections;

	for (ULONG x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
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


std::string PathToImage(const std::string path)
{
	const UINT pos = path.find_last_of('\\') + 1;
	return path.substr(pos);
}


LOADED_MODULE* FindLoadedModule(const char* name)
{
	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		if (_stricmp(name, PathToImage(LoadedModules[x].name).c_str()) == 0)
			return &LoadedModules[x];
	}

	return nullptr;
}


bool CheckModules(const char* target)
{
	for (UINT x = 0; x < modules.size(); ++x)
	{
		if (_stricmp(target, PathToImage(modules[x].image.name).c_str()) == 0)
			return true;
	}

	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		if (_stricmp(target, PathToImage(LoadedModules[x].name).c_str()) == 0) 
			return true;
	}

	return false;
}