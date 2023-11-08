#include "pch.h"
#include "helpers.h"


DWORD GetOffset(DWORD rva, LOADED_IMAGE* image)
{
	const auto SectionHeader = image->Sections;

	for (ULONG x = 0; x < image->NumberOfSections; ++x)
	{
		if (rva >= SectionHeader[x].VirtualAddress && rva <= (SectionHeader[x].VirtualAddress + SectionHeader[x].Misc.VirtualSize))
		{
			return SectionHeader[x].PointerToRawData + (rva - SectionHeader[x].VirtualAddress);
		}
	}

	std::cout << "Failed to find file offset\n";
	std::cout << "Module: " << image->ModuleName << '\n';
	std::cout << "RVA: " << HexOut << rva << std::endl;
	return NULL;
}


std::string PathToImage(std::string path)
{
	UINT pos = path.find_last_of('\\') + 1;
	return path.substr(pos);
}


_LoadedModule* FindLoadedModule(const char* name)
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
		if (_stricmp(target, PathToImage(modules[x].image->ModuleName).c_str()) == 0)
			return true;
	}

	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		if (_stricmp(target, PathToImage(LoadedModules[x].name).c_str()) == 0) 
			return true;
	}

	return false;
}


bool WaitForThreads(std::vector<HANDLE>& buffer)
{
#pragma warning(disable:6258)

	for (UINT x = 0; x < buffer.size(); ++x)
	{
		WaitForSingleObject(buffer[x], INFINITE);

		DWORD status;
		GetExitCodeThread(buffer[x], &status);

		if (!status)
		{
			for (UINT y = 0; y < buffer.size(); ++y)
			{
				TerminateThread(buffer[y], 0);
				CloseHandle(buffer[y]);
			}

			buffer.clear();
			return false;
		}

		CloseHandle(buffer[x]);
	}

	buffer.clear();

	return true;

#pragma warning(default:6258)
}