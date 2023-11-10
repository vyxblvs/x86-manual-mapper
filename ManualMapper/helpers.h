#pragma once
#include "parsing.h"

//Forward Declarations

DWORD GetOffset(const DWORD rva, const IMAGE_DATA* image);

std::string PathToImage(const std::string path);

LOADED_MODULE* FindLoadedModule(const char* name);

bool CheckModules(const char* target);


//Macros

template <typename ReturnType, typename ParamType> auto ConvertRva(ParamType base, const DWORD rva, const IMAGE_DATA* image) -> ReturnType
{
	return reinterpret_cast<ReturnType>(reinterpret_cast<BYTE*>(base) + GetOffset(rva, image));
}

#define CheckAttribs(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE || data.dwFileAttributes >= 256)

#define IsDirectory(data) (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(data.cFileName, ".") && strcmp(data.cFileName, ".."))

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), buffer, size, nullptr)

#define HexOut "0x" << std::uppercase << std::hex

#define STATUS_FAILURE 0