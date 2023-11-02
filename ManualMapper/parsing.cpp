#include "pch.h"
#include "parsing.h"
#include "helpers.h"


bool FindModuleDir(const char* target, const std::string dir)
{
	WIN32_FIND_DATAA data;
	const HANDLE search = FindFirstFileExA((dir + "\\*").c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
	if (!search)
	{
		std::cout << "FindFirstFileExA Failed (" << GetLastError() << ")\n";
		std::cout << "Path: " << dir + "\\*" << '\n';
		return false;
	}

	do
	{
		char path[MAX_PATH];
		PathCombineA(path, dir.c_str(), data.cFileName);
		
		if (CheckAttribs(data)) continue;

		if (IsDirectory(data))
		{
			if (FindModuleDir(target, path))
			{
				FindClose(search);
				return true;
			}
		}

		else if (_stricmp(target, data.cFileName) == 0)
		{
			modules.emplace_back(_module{ ImageLoad(path, nullptr) });
			if (!modules.back().image)
			{
				std::cout << "[FindModuleDir] Failed to load image (" << GetLastError() << ")\n";
				std::cout << "Path: " << path << '\n';
				FindClose(search);
				return false;
			}

			FindClose(search);
			return true;
		}

	} while (FindNextFileA(search, &data) && GetLastError() != ERROR_NO_MORE_FILES);

	SetLastError(0);
	FindClose(search);
	return false;
}


bool GetDependencies(LOADED_IMAGE* image)
{
	//Initialize directories to be searched for unloaded modules
	static std::string directories[2]{ "c:\\Windows\\SysWOW64" };
	if (directories[1].empty())
	{
		directories[1].resize(MAX_PATH);
		if (!GetModuleFileNameExA(process, nullptr, directories[1].data(), MAX_PATH))
		{
			std::cout << "[GetDependencies] Failed to get process directory (" << GetLastError() << ")\n";
			return false;
		}

		UINT pos = directories[1].find_last_of('\\');
		directories[1] = directories[1].substr(0, pos);
	}

	const IMAGE_DATA_DIRECTORY ImportTableData = ImportDirectory(image); 
	if (!ImportTableData.Size) return true;

	const auto MappedAddress   = image->MappedAddress;
	const auto ImportDirectory = ConvertRva<_ImportDescriptor*>(MappedAddress, ImportTableData.VirtualAddress, image);

	for (ULONG x = 0; x < (ImportTableData.Size / sizeof(_ImportDescriptor)) - 1; ++x)
	{
		const char* ModuleName = ConvertRva<const char*>(MappedAddress, ImportDirectory[x].Name, image);
		if (CheckModules(ModuleName)) continue;

		for (UINT y = 0; y < 2; ++y)
		{
			if (!FindModuleDir(ModuleName, directories[y]) && y == 2)
			{
				std::cout << "[GetDependencies] Failed to locate module: " << ModuleName << '\n';
				return false;
			}
		}
	}
	
	return true;
}


void WINAPI ApplyReloction(_module* TargetModule)
{
	const auto image   = TargetModule->image;
	const auto DataDir = RelocationDirectory(image);

	auto RelocBlock = ConvertRva<IMAGE_BASE_RELOCATION*>(image->MappedAddress, DataDir.VirtualAddress, image);
	const auto FinalEntry = reinterpret_cast<BYTE*>(RelocBlock) + DataDir.Size;

	while (reinterpret_cast<BYTE*>(RelocBlock) < FinalEntry)
	{
		const WORD* entry = reinterpret_cast<WORD*>(RelocBlock) + 4;

		for (UINT y = 0; entry[y] != IMAGE_REL_BASED_ABSOLUTE && y < (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++y)
		{
			DWORD* RelocAddress = ConvertRva<DWORD*>(image->MappedAddress, entry[y] % 0x1000 + RelocBlock->VirtualAddress, image);
			*RelocAddress = (*RelocAddress - image->FileHeader->OptionalHeader.ImageBase) + TargetModule->ImageBase;
		}

		RelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocBlock) + RelocBlock->SizeOfBlock);
	}

	return;
}


bool GetLoadedExport(const char* ModuleName, const char* ExportName, DWORD* buffer)
{
	_LoadedModule* ModulePtr = FindLoadedModule(ModuleName);
	if (ModulePtr == nullptr)
	{
		std::cout << "[GetLoadedExport] Failed to locate loaded module: " << ModuleName << '\n';
		return false;
	}

	//Loading the module locally so I can call GetProcAddress
	if (!ModulePtr->LocalBase)
	{
		ModulePtr->LocalHandle = LoadLibraryA(ModulePtr->name.c_str());
		if (!ModulePtr->LocalHandle)
		{
			std::cout << "[GetLoadedExport] Failed to load module (" << GetLastError() << ")\n";
			std::cout << "Path: " << ModulePtr->name << '\n';
			return false;
		}
	}

	DWORD ProcAddress = reinterpret_cast<DWORD>(GetProcAddress(ModulePtr->LocalHandle, ExportName));
	if (ProcAddress == NULL)
	{
		std::cout << "[GetLoadedExport] Failed to locate function (" << GetLastError() << ")\n";
		std::cout << "Function name: " << ExportName << '\n';
		std::cout << "Module: " << ModuleName << '\n';
		return false;
	}

	*buffer = ModulePtr->base + (ProcAddress - ModulePtr->LocalBase);
	
	return true;
}


bool GetUnloadedExport(const char* ModuleName, const char* ImportName, DWORD* buffer)
{
	//Locating the imported module
	_module* ModulePtr = nullptr;
	for (UINT x = 0; x < modules.size(); ++x)
	{
		if (_stricmp(ModuleName, PathToImage(modules[x].image->ModuleName).c_str()) == 0)
		{
			ModulePtr = &modules[x];
			break;
		}
	}
	if (!ModulePtr)
	{
		std::cout << "[GetUnloadedExport] Failed to locate module: " << ModuleName << '\n';
		std::cout << "Vector size: " << modules.size() << '\n';
		return false;
	}

	//Getting basic export data
	const auto image		 = ModulePtr->image;
	const auto ImageBase	 = image->MappedAddress;
	const auto ExportDirData = ExportDirectory(image);
	const auto ExportDir     = ConvertRva<IMAGE_EXPORT_DIRECTORY*>(ImageBase, ExportDirData.VirtualAddress, image);
	const auto ExportTable   = ConvertRva<DWORD*>(ImageBase, ExportDir->AddressOfFunctions,    image);
	const auto NamePtrTable  = ConvertRva<DWORD*>(ImageBase, ExportDir->AddressOfNames,        image);
	const auto OrdinalTable  = ConvertRva<WORD*> (ImageBase, ExportDir->AddressOfNameOrdinals, image);

	//Parsing the export directory for a function match
	for(UINT x = 0; x < ExportDir->NumberOfFunctions; ++x)
	{
		const auto ExportName = ConvertRva<const char*>(ImageBase, NamePtrTable[x], image);
		if (_stricmp(ImportName, ExportName) == 0)
		{
			//Getting the Export Address Table index for the matched function
			const WORD index = OrdinalTable[x];
			
			//Handling forwarders
			if ((ExportTable[index] >= ExportDirData.VirtualAddress) && (ExportTable[index] < ExportDirData.VirtualAddress + ExportDirData.Size))
			{
				const std::string forwarder = ConvertRva<const char*>(ImageBase, ExportTable[index], image);
				return GetLoadedExport((forwarder.substr(0, forwarder.find_last_of('.') + 1) + "dll").c_str(), ExportName, buffer);
			}
			else *buffer = ModulePtr->ImageBase + ExportTable[index];

			return true;
		}
	}

	std::cout << "[GetUnloadedExport] No export found for: " << ImportName << '\n';
	std::cout << "Module: " << ModuleName << '\n';
	return false;
}


bool WINAPI ResolveImports(_module* target)
{
	//Getting basic import data
	const auto image = target->image;
	const auto ImageBase = image->MappedAddress;
	const auto ImportDir = ConvertRva<_ImportDescriptor*>(ImageBase, ImportDirectory(image).VirtualAddress, image);
	
	//Parsing IDT (final entry is NULL)
	for (UINT x = 0; ImportDir[x].Name != NULL; ++x)
	{
		const auto ImportTable = ConvertRva<ThunkData32*>(ImageBase, ImportDir[x].FirstThunk,	   image);
		const auto LookupTable = ConvertRva<ThunkData32*>(ImageBase, ImportDir[x].Characteristics, image);
		const auto ModuleName  = ConvertRva<const char*> (ImageBase, ImportDir[x].Name,			   image);

		//Checking if the indexed module is already loaded within the target process
		const bool IsModuleLoaded = reinterpret_cast<int>(FindLoadedModule(ModuleName)) > 0; 

		//Going through each function imported from the indexed module (ILT ends with NULL entry)
		for (UINT y = 0; LookupTable[y].u1.Function != NULL; ++y)
		{
			const char* ImportName = ConvertRva<IMAGE_IMPORT_BY_NAME*>(ImageBase, LookupTable[y].u1.AddressOfData, image)->Name;

			if (IsModuleLoaded)
			{
				if (GetLoadedExport(ModuleName, ImportName, &ImportTable[y].u1.AddressOfData) == false) return false;
			}
			else
			{
				if (GetUnloadedExport(ModuleName, ImportName, &ImportTable[y].u1.AddressOfData) == false) return false;
			}
		}
	}

	return true;
}