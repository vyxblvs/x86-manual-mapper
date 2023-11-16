#include "pch.h"
#include "parsing.h"
#include "helpers.h"


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

	image.name = new char[MAX_PATH];
	strcpy_s(image.name, MAX_PATH, path);

	image.MappedAddress = image_ptr;
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
		if (CheckAttribs(data)) continue;

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
			modules.emplace_back(MODULE{ NULL });
			return GetDll(path, &modules.back());
		}

	} while (FindNextFileA(search, &data) && GetLastError() != ERROR_NO_MORE_FILES);

	SetLastError(0);
	FindClose(search);
	return false;
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

	const char* const MappedAddress = image->MappedAddress;
	const auto ImportDirectory = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(MappedAddress, ImportTableData.VirtualAddress, image);

	for (UINT x = 0; x < (ImportTableData.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)) - 1; ++x)
	{
		const char* const ModuleName = ConvertRva<const char*>(MappedAddress, ImportDirectory[x].Name, image);
		if (CheckModules(ModuleName)) continue;

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

	auto RelocBlock = ConvertRva<IMAGE_BASE_RELOCATION*>(image->MappedAddress, DataDir.VirtualAddress, image);
	const BYTE* const FinalEntry = reinterpret_cast<BYTE*>(RelocBlock) + DataDir.Size;

	while (reinterpret_cast<BYTE*>(RelocBlock) < FinalEntry)
	{
		const auto entry = reinterpret_cast<const WORD*>(RelocBlock) + 4;

		for (UINT y = 0; entry[y] != IMAGE_REL_BASED_ABSOLUTE && y < (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++y)
		{
			DWORD* const RelocAddress = ConvertRva<DWORD*>(image->MappedAddress, entry[y] % 0x1000 + RelocBlock->VirtualAddress, image);
			*RelocAddress = (*RelocAddress - image->NT_HEADERS->OptionalHeader.ImageBase) + TargetModule->ImageBase;
		}

		RelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocBlock) + RelocBlock->SizeOfBlock);
	}
}


bool GetLoadedExport(LOADED_MODULE* const ModulePtr, const char* const ExportName, DWORD* const buffer)
{
	if (!ModulePtr->handle)
	{
		ModulePtr->handle = LoadLibraryA(ModulePtr->name);
		if (!ModulePtr->handle)
		{
			std::cerr << "[GetLoadedExport] Failed to load module (" << GetLastError() << ")\n";
			std::cerr << "Path: " << ModulePtr->name << '\n';
			return false;
		}
	}

	const DWORD ProcAddress = reinterpret_cast<DWORD>(GetProcAddress(ModulePtr->handle, ExportName));
	if (!ProcAddress)
	{
		std::cerr << "[GetLoadedExport] Failed to locate function (" << GetLastError() << ")\n";
		std::cerr << "Function name: " << ExportName << '\n';
		std::cerr << "Module: " << ModulePtr->name << '\n';
		return false;
	}

	*buffer = ModulePtr->base + (ProcAddress - reinterpret_cast<DWORD>(ModulePtr->handle));
	
	return true;
}


bool GetUnloadedExport(const char* const ModuleName, const char* const ImportName, DWORD* const buffer)
{
	//Locating the imported module
	const MODULE* ModulePtr = nullptr;
	for (UINT x = 0; x < modules.size(); ++x)
	{
		if (ImageCmp(modules[x].image.name, ModuleName))
		{
			ModulePtr = &modules[x];
			break;
		}
	}
	if (!ModulePtr)
	{
		std::cerr << "[GetUnloadedExport] Failed to locate module: " << ModuleName << '\n';
		std::cerr << "Vector size: " << modules.size() << '\n';
		return false;
	}

	//Getting basic export data
	const auto image         = &ModulePtr->image;
	const auto MappedAddress = image->MappedAddress;
	const auto ExportDirData = DataDirectory(image, IMAGE_DIRECTORY_ENTRY_EXPORT);
	const auto ExportDir     = ConvertRva<IMAGE_EXPORT_DIRECTORY*>(MappedAddress, ExportDirData.VirtualAddress, image);
	const auto ExportTable   = ConvertRva<DWORD*>(MappedAddress, ExportDir->AddressOfFunctions,    image);
	const auto NamePtrTable  = ConvertRva<DWORD*>(MappedAddress, ExportDir->AddressOfNames,        image);
	const auto OrdinalTable  = ConvertRva<WORD*> (MappedAddress, ExportDir->AddressOfNameOrdinals, image);

	//Parsing the export directory for a function match
	for(UINT x = 0; x < ExportDir->NumberOfFunctions; ++x)
	{
		const auto ExportName = ConvertRva<const char*>(MappedAddress, NamePtrTable[x], image);
		if (_stricmp(ImportName, ExportName) == 0)
		{
			//Getting the Export Address Table index for the matched function
			const WORD index = OrdinalTable[x];
			
			//Handling forwarders
			if ((ExportTable[index] >= ExportDirData.VirtualAddress) && (ExportTable[index] < ExportDirData.VirtualAddress + ExportDirData.Size))
			{
				const std::string forwarder = ConvertRva<const char*>(MappedAddress, ExportTable[index], image);
				LOADED_MODULE* const ModulePtr = GetLoadedModule((forwarder.substr(0, forwarder.find_last_of('.') + 1) + "dll").c_str());
				if (!ModulePtr)
				{
					std::cout << "Failed to locate module imported via forwarding: " << ModuleName << '\n';
					return false;
				}
				return GetLoadedExport(ModulePtr, ExportName, buffer);
			}
			else *buffer = ModulePtr->ImageBase + ExportTable[index];

			return true;
		}
	}

	std::cerr << "No export found for: " << ImportName << '\n';
	std::cerr << "Module: " << ModuleName << '\n';
	return false;
}


bool ResolveImports(const IMAGE_DATA* const image)
{
	//Getting basic import data
	const char* const MappedAddress = image->MappedAddress;
	const auto ImportDir = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(MappedAddress, DataDirectory(image, IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress, image);
	
	//Parsing IDT (final entry is NULL)
	for (UINT x = 0; ImportDir[x].Name != NULL; ++x)
	{
		const auto ImportTable = ConvertRva<IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].FirstThunk, image);
		const auto LookupTable = ConvertRva<const IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].Characteristics, image);
		const auto ModuleName  = ConvertRva<const char*> (MappedAddress, ImportDir[x].Name, image);

		//Checking if the indexed module is already loaded within the target process
		LOADED_MODULE* const ModuleIndex = GetLoadedModule(ModuleName); 

		//Going through each function imported from the indexed module (ILT ends with NULL entry)
		for (UINT y = 0; LookupTable[y].u1.Function != NULL; ++y)
		{
			const char* const ImportName = ConvertRva<IMAGE_IMPORT_BY_NAME*>(MappedAddress, LookupTable[y].u1.AddressOfData, image)->Name;

			if (ModuleIndex)
			{
				if (!GetLoadedExport(ModuleIndex, ImportName, &ImportTable[y].u1.AddressOfData)) return false;
			}
			else
			{
				if (!GetUnloadedExport(ModuleName, ImportName, &ImportTable[y].u1.AddressOfData)) return false;
			}
		}
	}

	return true;
}