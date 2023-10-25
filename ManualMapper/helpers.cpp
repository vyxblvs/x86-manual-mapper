#include "pch.h"
#include "helpers.h"


bool AllocMemory(_module* target)
{
	target->BasePtr = VirtualAllocEx(process, nullptr, target->image->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!target->BasePtr)
	{
		std::cout << "Failed to allocate memory (" << GetLastError() << ")\n";
		std::cout << "Module: " << target->image->ModuleName << '\n';
		return false;
	}

	DWORD OldProtection;
	return VirtualProtect(target->image->MappedAddress, target->image->SizeOfImage, PAGE_WRITECOPY, &OldProtection);
}


DWORD GetOffset(DWORD rva, LOADED_IMAGE* image)
{
	const auto SectionHeader = image->Sections;

	for (ULONG x = 0; x < image->NumberOfSections; ++x)
	{
		if (rva >= SectionHeader[x].VirtualAddress && rva <= (SectionHeader[x].VirtualAddress + SectionHeader[x].Misc.VirtualSize))
		{
			return SectionHeader[x].PointerToRawData + (rva - SectionHeader[x].VirtualAddress);
		}
		
		if (x && rva < SectionHeader[x].VirtualAddress)
		{
			return SectionHeader[x].PointerToRawData - (SectionHeader[x].VirtualAddress - rva);
		}
	}

	std::cout << "Failed to find file offset\n";
	std::cout << "Module: " << image->ModuleName << '\n';
	std::cout << "RVA: 0x" << HexOut << rva << std::endl;
	return NULL;
}


BOOL WINAPI WriteProcessMemoryEx(HANDLE process, LPVOID address, LPCVOID buffer, SIZE_T size)
{
	if (!WriteProcessMemory(process, address, buffer, size, nullptr))
	{
		std::cout << "WPM Failed (" << GetLastError() << ")\n";
		std::cout << "Address: 0x" << HexOut << address << '\n';
		return false;
	}
	
	return true;
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
		if (_stricmp(target, PathToImage(LoadedModules[x].name.c_str()).c_str()) == 0)
			return true;
	}

	return false;
}


bool WaitForThreads(std::vector<HANDLE>* buffer)
{
	for (UINT x = 0; x < buffer->size(); ++x)
	{
		WaitForSingleObject(buffer->at(x), INFINITE);

		DWORD status;
		GetExitCodeThread(buffer->at(x), &status);

		if (!status)
		{
			for (UINT y = 0; y < buffer->size(); ++y)
			{
				TerminateThread(buffer->at(y), 0);
				CloseHandle(buffer->at(y));
			}
			return false;
		}

		CloseHandle(buffer->at(x));
	}

	buffer->clear();

	return true;
}