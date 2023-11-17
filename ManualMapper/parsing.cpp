#include "pch.h"
#include "parsing.h"


bool GetDll(const char* const path, MODULE* const buffer)
{
	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
	{
		std::cerr << "Invalid file path provided: " << path << '\n';
		return false;
	}

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (file.fail())
	{
		std::cerr << "Failed to open file: " << path << '\n';
		return false;
	}

	const UINT size = static_cast<UINT>(file.tellg());
	char* const image_ptr = new char[size];

	file.seekg(0, std::ios::beg);
	file.read(image_ptr, size);
	file.close();

	IMAGE_DATA& const image = buffer->image;
	if (!image.path)
	{
		image.path = new char[MAX_PATH];
		strcpy_s(image.path, MAX_PATH, path);
	}

	image.LocalBase = image_ptr;
	image.NT_HEADERS = reinterpret_cast<IMAGE_NT_HEADERS32*>(image_ptr + *reinterpret_cast<DWORD*>(image_ptr + 0x3C));
	image.sections = IMAGE_FIRST_SECTION(image.NT_HEADERS);

	if (image.NT_HEADERS->OptionalHeader.Magic != 0x10B)
	{
		std::cerr << "Invalid DLL architecture, image must be PE32\n";
		std::cerr << "Magic number: " << HexOut << image.NT_HEADERS->OptionalHeader.Magic << '\n';
		std::cerr << "Path: " << path << '\n';
		delete[] image_ptr;
		return false;
	}

	return true;
}


bool FindModuleDir(const char* const target, std::string dir)
{
	dir += '\\';
	WIN32_FIND_DATAA data;
	const HANDLE search = FindFirstFileExA((dir + '*').c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
	if (!search)
	{
		std::cerr << "FindFirstFileExA Failed (" << GetLastError() << ")\n";
		std::cerr << "Path: " << dir + "\\*" << '\n';
		return false;
	}

	do
	{
		if (data.dwFileAttributes >= 256) continue;

		char path[MAX_PATH];
		strcpy_s(path, MAX_PATH, (dir + data.cFileName).c_str());

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
			FindClose(search);
			modules.emplace_back(MODULE{});
			return GetDll(path, &modules.back());
		}

	} while (FindNextFileA(search, &data) && GetLastError() != ERROR_NO_MORE_FILES);

	SetLastError(0);
	FindClose(search);
	return false;
}


template <typename ret> auto ConvertRva(const void* const base, const DWORD rva, const IMAGE_DATA* const image) -> ret
{
	const IMAGE_SECTION_HEADER* SectionHeader = image->sections;

	for (UINT x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
	{
		if (rva >= SectionHeader[x].VirtualAddress && rva <= (SectionHeader[x].VirtualAddress + SectionHeader[x].Misc.VirtualSize))
		{
			return reinterpret_cast<ret>(reinterpret_cast<DWORD>(base) + SectionHeader[x].PointerToRawData + (rva - SectionHeader[x].VirtualAddress));
		}
	}

	std::cerr << "Failed to find file offset\n";
	std::cerr << "Module: " << image->path << '\n';
	std::cerr << "RVA: " << HexOut << rva << '\n';
	return reinterpret_cast<ret>(NULL);
}


MODULE* FindModule(const char* const name)
{
	std::string path;

	for (UINT x = 0; x < LoadedModules.size(); ++x)
	{
		path = LoadedModules[x].image.path;
		if (_stricmp((path.substr(path.find_last_of('\\') + 1)).c_str(), name) == 0) return &LoadedModules[x];
	}

	for (UINT x = 0; x < modules.size(); ++x)
	{
		path = modules[x].image.path;
		if (_stricmp((path.substr(path.find_last_of('\\') + 1)).c_str(), name) == 0) return &modules[x];
	}

	return nullptr;
}


bool GetDependencies(const IMAGE_DATA* const image)
{
	//Initialize directories to be searched for unloaded modules
	static char directories[2][MAX_PATH]{ "c:\\Windows\\SysWOW64", '\0'};
	if (!directories[1][0])
	{
		std::string buffer(MAX_PATH, NULL);
		if (!GetModuleFileNameExA(process, nullptr, buffer.data(), MAX_PATH))
		{
			std::cerr << "Failed to get process directory (" << GetLastError() << ")\n";
			return false;
		}
		strcpy_s(directories[1], MAX_PATH, (buffer.substr(0, buffer.find_last_of('\\'))).c_str());
	}

	const IMAGE_DATA_DIRECTORY ImportTableData = DataDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT); 
	if (!ImportTableData.Size) return true;

	const char* const MappedAddress = image->LocalBase;
	const auto ImportDirectory = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(MappedAddress, ImportTableData.VirtualAddress, image);

	for (UINT x = 0; x < (ImportTableData.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1; ++x)
	{
		const char* const ModuleName = ConvertRva<const char*>(MappedAddress, ImportDirectory[x].Name, image);
		if (FindModule(ModuleName)) continue;

		for (UINT y = 0, num_of_paths = sizeof(directories) / MAX_PATH; y < num_of_paths; ++y)
		{
			if (!FindModuleDir(ModuleName, directories[y]) && y == num_of_paths)
			{
				std::cerr << "[GetDependencies] Failed to locate module: " << ModuleName << '\n';
				return false;
			}
		}
	}
	
	return true;
}


void ApplyReloction(const MODULE* TargetModule)
{
	const auto image   = &TargetModule->image;
	const auto DataDir = DataDirectory(image, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	auto RelocBlock = ConvertRva<IMAGE_BASE_RELOCATION*>(image->LocalBase, DataDir.VirtualAddress, image);
	const BYTE* const FinalEntry = reinterpret_cast<BYTE*>(RelocBlock) + DataDir.Size;

	while (reinterpret_cast<BYTE*>(RelocBlock) < FinalEntry)
	{
		const auto entry = reinterpret_cast<const WORD*>(RelocBlock) + 4;

		for (UINT y = 0; entry[y] != IMAGE_REL_BASED_ABSOLUTE && y < (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++y)
		{
			DWORD* const RelocAddress = ConvertRva<DWORD*>(image->LocalBase, entry[y] % 0x1000 + RelocBlock->VirtualAddress, image);
			*RelocAddress = (*RelocAddress - image->NT_HEADERS->OptionalHeader.ImageBase) + TargetModule->ImageBase;
		}

		RelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocBlock) + RelocBlock->SizeOfBlock);
	}
}


bool GetLoadedFunction(MODULE* ModulePtr, const char* const FunctionName, DWORD* const buffer)
{
	const DWORD address = reinterpret_cast<DWORD>(GetProcAddress(ModulePtr->image.handle, FunctionName));
	if (!address)
	{
		std::cout << "Failed to locate function: " << FunctionName << '\n';
		return false;
	}

	*buffer = ModulePtr->ImageBase + (address - reinterpret_cast<DWORD>(ModulePtr->image.handle));
	return true;
}


bool GetExport(const MODULE* const ModulePtr, const char* const ModuleName, const char* const ImportName, DWORD* const buffer)
{
	const auto image         = &ModulePtr->image;
	const auto MappedAddress = image->LocalBase;
	const auto ExportDirData = DataDirectory(image, IMAGE_DIRECTORY_ENTRY_EXPORT);
	const auto ExportDir     = ConvertRva<IMAGE_EXPORT_DIRECTORY*>(MappedAddress, ExportDirData.VirtualAddress, image);
	const auto ExportTable   = ConvertRva<DWORD*>(MappedAddress, ExportDir->AddressOfFunctions,    image);
	const auto NamePtrTable  = ConvertRva<DWORD*>(MappedAddress, ExportDir->AddressOfNames,        image);
	const auto OrdinalTable  = ConvertRva<WORD*> (MappedAddress, ExportDir->AddressOfNameOrdinals, image);

	for(UINT x = 0; x < ExportDir->NumberOfFunctions; ++x)
	{
		const auto ExportName = ConvertRva<const char*>(MappedAddress, NamePtrTable[x], image);
		if (_stricmp(ImportName, ExportName) == 0)
		{
			const WORD index = OrdinalTable[x];
			
			//Handling Forwarders (this should probably just be removed)
			if ((ExportTable[index] >= ExportDirData.VirtualAddress) && (ExportTable[index] < ExportDirData.VirtualAddress + ExportDirData.Size))
			{
				std::string forwarder = ConvertRva<const char*>(MappedAddress, ExportTable[index], image);
				forwarder = forwarder.substr(0, forwarder.find_last_of('.') + 1) + "dll";

				MODULE* const ForwardedModule = FindModule(forwarder.c_str());
				if (!ForwardedModule)
				{
					std::cout << "Failed to locate module imported via forwarding: " << ModulePtr->image.path << '\n';
					return false;
				}

				if (!ForwardedModule->image.NT_HEADERS && ForwardedModule->image.handle)
				{
					return GetLoadedFunction(ForwardedModule, ImportName, buffer);
				}

				return GetExport(ForwardedModule, forwarder.c_str(), ImportName, buffer);
			}

			const MODULE* const ImportedModule = FindModule(ModuleName);
			if (!ImportedModule) return false;
			*buffer = ImportedModule->ImageBase + ExportTable[index];

			return true;
		}
	}

	std::cerr << "No export found for: " << ImportName << '\n';
	std::cerr << "Module: " << ModulePtr->image.path << '\n';
	return false;
}


bool ResolveImports(const IMAGE_DATA* const image)
{
	const char* const MappedAddress = image->LocalBase;
	const auto ImportDir = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(MappedAddress, DataDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress, image);
	
	for (UINT x = 0; ImportDir[x].Name != NULL; ++x)
	{
		const auto ImportTable = ConvertRva<IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].FirstThunk, image);
		const auto LookupTable = ConvertRva<const IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].Characteristics, image);
		const auto ModuleName  = ConvertRva<const char*> (MappedAddress, ImportDir[x].Name, image);

		MODULE* const ModulePtr = FindModule(ModuleName);
		if (!ModulePtr->image.NT_HEADERS && !ModulePtr->image.handle && !GetDll(ModulePtr->image.path, ModulePtr)) return false;
		
		for (UINT y = 0; LookupTable[y].u1.Function; ++y)
		{
			const char* const ImportName = ConvertRva<IMAGE_IMPORT_BY_NAME*>(MappedAddress, LookupTable[y].u1.AddressOfData, image)->Name;

			if (!ModulePtr->image.NT_HEADERS && ModulePtr->image.handle)
			{
				if (!GetLoadedFunction(ModulePtr, ImportName, &ImportTable[y].u1.AddressOfData)) return false;
			}
			else
			{
				if (!GetExport(ModulePtr, ModuleName, ImportName, &ImportTable[y].u1.AddressOfData)) return false;
			}
		}
	}

	return true;
}