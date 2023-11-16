#pragma once
#include "parsing.h"

//Forward Declarations

DWORD GetOffset(const DWORD rva, const IMAGE_DATA* const image);

bool ImageCmp(std::string path, const char* const name);

LOADED_MODULE* GetLoadedModule(const char* const name);

bool CheckModules(const char* target);


//Macros

template <typename ret> auto ConvertRva(const void* const base, const DWORD rva, const IMAGE_DATA* const image) -> ret
{
	const DWORD offset = GetOffset(rva, image);
	return offset ? reinterpret_cast<ret>(reinterpret_cast<DWORD>(base) + offset) : nullptr;
}

#define HexOut "0x" << std::uppercase << std::hex

#define CheckAttribs(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE || data.dwFileAttributes >= 256)

#define IsDirectory(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(data.cFileName, ".") && strcmp(data.cFileName, ".."))

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, nullptr)